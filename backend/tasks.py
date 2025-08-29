import os
import time
import logging
from datetime import datetime
from ipaddress import ip_network, ip_address
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from ping3 import ping
import nmap

from .database import SessionLocal, commit_with_retry
from . import models

scheduler = AsyncIOScheduler()
_sweep_running = Event()
logger = logging.getLogger("ipam.tasks")
# Ensure INFO-level logs are visible even under default Uvicorn config
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper()))


def ping_host(ip: str):
    try:
        delay = ping(ip, timeout=1, unit="ms")
        return delay
    except Exception:
        return None


def icmp_scan():
    # If a full sweep is in progress, yield quickly to avoid overlap
    if _sweep_running.is_set():
        logger.info("icmp_scan: skip (sweep in progress)")
        return
    # Ping known hosts concurrently, then write results in batches
    t0 = time.perf_counter()
    db = SessionLocal()
    try:
        hosts = db.query(models.Host).all()
        ips = [(h.id, h.ip) for h in hosts]
    finally:
        db.close()

    workers = int(os.environ.get("PING_WORKERS", "64"))
    results = []
    if ips:
        logger.info(f"icmp_scan: start hosts={len(ips)} workers={workers}")
        with ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(ping_host, ip): host_id for host_id, ip in ips}
            for fut in as_completed(futs):
                host_id = futs[fut]
                try:
                    delay = fut.result()
                except Exception:
                    delay = None
                results.append((host_id, delay))

    db = SessionLocal()
    try:
        id_to_host = {h.id: h for h in db.query(models.Host).all()}
        batch = 0
        for host_id, delay in results:
            host = id_to_host.get(host_id)
            if not host:
                continue
            status = models.HostStatus(host_id=host.id, is_up=delay is not None, latency_ms=delay)
            if delay is not None:
                if host.first_seen_at is None:
                    host.first_seen_at = datetime.utcnow()
                host.last_seen_at = datetime.utcnow()
            db.add(status)
            batch += 1
            if batch % 100 == 0:
                commit_with_retry(db)
        commit_with_retry(db)
        # After pings, try ARP cache to fill missing MACs quickly
        try:
            mac_map = _read_arp_cache()
            updated = 0
            for h in id_to_host.values():
                if not h.mac:
                    mac = mac_map.get(h.ip)
                    if mac:
                        h.mac = mac
                        updated += 1
            if updated:
                commit_with_retry(db)
                logger.info(f"icmp_scan: macs_filled_from_arp={updated}")
        except Exception:
            pass
    finally:
        db.close()
    up = sum(1 for _, d in results if d is not None)
    dt_ms = int((time.perf_counter() - t0) * 1000)
    logger.info(f"icmp_scan: finish hosts={len(results)} up={up} duration_ms={dt_ms}")


def nmap_scan():
    t0 = time.perf_counter()
    logger.info("nmap_scan: start")
    db = SessionLocal()
    try:
        nm = nmap.PortScanner()
        hosts = db.query(models.Host).all()
        args = os.environ.get("NMAP_ARGS", "-Pn -T3 --top-ports 1000 -sS -sV")
        # Backward-compat: fix older invalid flag if present
        if "--top-1000-ports" in args:
            args = args.replace("--top-1000-ports", "--top-ports 1000")
        # If not running as root, prefer TCP connect scan over SYN
        try:
            if hasattr(os, "geteuid") and os.geteuid() != 0 and "-sS" in args and "-sT" not in args:
                args = args.replace("-sS", "-sT")
                logger.info("nmap_scan: not root; using -sT instead of -sS")
        except Exception:
            pass
        alive = 0
        ports_written = 0
        batch = 0
        for host in hosts:
            last = host.statuses[0] if host.statuses else None
            if last and last.is_up:
                alive += 1
                try:
                    nm.scan(host.ip, arguments=args)
                    if host.ip in nm.all_hosts():
                        # Capture MAC address from Nmap if available
                        try:
                            mac_addr = nm[host.ip].get('addresses', {}).get('mac')
                            if mac_addr and (not host.mac):
                                host.mac = mac_addr.lower()
                        except Exception:
                            pass
                        for proto in nm[host.ip].all_protocols():
                            for port, data in nm[host.ip][proto].items():
                                hop = models.HostOpenPort(
                                    host_id=host.id,
                                    port=int(port),
                                    proto=str(proto),
                                    service=(data.get("name") if isinstance(data, dict) else None),
                                    state=(data.get("state") if isinstance(data, dict) else None),
                                )
                                db.add(hop)
                                batch += 1
                                ports_written += 1
                                if batch % 50 == 0:
                                    commit_with_retry(db)
                except Exception:
                    # Ignore Nmap errors per host
                    pass
        commit_with_retry(db)
    finally:
        db.close()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    logger.info(f"nmap_scan: finish alive_hosts={alive} ports_written={ports_written} duration_ms={dt_ms}")


def sweep_subnets(db: SessionLocal):
    """Enumerate configured subnets and ping hosts up to a size limit.
    Creates Host rows for alive IPs if missing and associates with subnet.
    """
    if os.environ.get("DISABLE_SCANNING") == "1":
        return
    max_hosts = int(os.environ.get("MAX_SUBNET_SIZE", "4096"))
    subnets = db.query(models.Subnet).all()
    for subnet in subnets:
        try:
            net = ip_network(subnet.cidr, strict=False)
        except Exception:
            continue
        # Skip very large networks
        total = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
        if total > max_hosts:
            logger.info(f"sweep_subnets: skip {subnet.cidr} size={total} max={max_hosts}")
            continue
        # Fast concurrent enumerate-and-ping
        t0 = time.perf_counter()
        logger.info(f"sweep_subnets: start {subnet.cidr}")
        ips = [str(ip) for ip in (net.hosts() if net.version == 4 else net)]
        results = _ping_many(ips, workers=int(os.environ.get("SWEEP_PING_WORKERS", "128")), timeout_ms=int(os.environ.get("SWEEP_PING_TIMEOUT_MS", "500")))
        created, alive = _apply_ping_results(db, subnet.id, results)
        dt_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(f"sweep_subnets: finish {subnet.cidr} alive={alive} created_hosts={created} duration_ms={dt_ms}")


def sweep_subnet_id(db: SessionLocal, subnet_id: int):
    if os.environ.get("DISABLE_SCANNING") == "1":
        return
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        return
    try:
        net = ip_network(subnet.cidr, strict=False)
    except Exception:
        return
    total = net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0)
    max_hosts = int(os.environ.get("MAX_SUBNET_SIZE", "4096"))
    if total > max_hosts:
        logger.info(f"sweep_subnet_id: skip {subnet.cidr} size={total} max={max_hosts}")
        return
    t0 = time.perf_counter()
    logger.info(f"sweep_subnet_id: start {subnet.cidr}")
    ips = [str(ip) for ip in (net.hosts() if net.version == 4 else net)]
    results = _ping_many(ips, workers=int(os.environ.get("SWEEP_PING_WORKERS", "128")), timeout_ms=int(os.environ.get("SWEEP_PING_TIMEOUT_MS", "500")))
    created, alive = _apply_ping_results(db, subnet.id, results)
    dt_ms = int((time.perf_counter() - t0) * 1000)
    logger.info(f"sweep_subnet_id: finish {subnet.cidr} alive={alive} created_hosts={created} duration_ms={dt_ms}")


def scan_single_subnet(cidr: str):
    """Trigger immediate sweep for one subnet CIDR string."""
    db = SessionLocal()
    try:
        subnet = db.query(models.Subnet).filter(models.Subnet.cidr == cidr).first()
        if not subnet:
            return
        sweep_subnet_id(db, subnet.id)
    finally:
        db.close()


def scan_single_subnet_id(subnet_id: int):
    db = SessionLocal()
    try:
        _sweep_running.set()
        sweep_subnet_id(db, subnet_id)
    finally:
        db.close()
        _sweep_running.clear()


def start_scheduler():
    scheduler.add_job(
        icmp_scan,
        "interval",
        seconds=int(os.environ.get("SCAN_ICMP_INTERVAL_SECONDS", "60")),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=30,
        id="icmp_scan",
        replace_existing=True,
    )
    # Schedule Nmap by default unless explicitly disabled
    if os.environ.get("ENABLE_NMAP_SCHEDULER", "1") == "1":
        scheduler.add_job(
            nmap_scan,
            "interval",
            minutes=int(os.environ.get("SCAN_NMAP_INTERVAL_MINUTES", "10")),
            max_instances=1,
            coalesce=True,
            misfire_grace_time=60,
            id="nmap_scan",
            replace_existing=True,
        )
    # Sweep subnets less frequently to avoid long ICMP runs
    def _sweep_job():
        db = SessionLocal()
        try:
            logger.info("sweep_subnets_job: start")
            _sweep_running.set()
            sweep_subnets(db)
            logger.info("sweep_subnets_job: finish")
        finally:
            db.close()
            _sweep_running.clear()

    scheduler.add_job(
        _sweep_job,
        "interval",
        minutes=int(os.environ.get("SCAN_SWEEP_INTERVAL_MINUTES", "5")),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=120,
        id="sweep_subnets",
        replace_existing=True,
    )
    scheduler.start()


def scan_host_ports_id(host_id: int):
    """Run Nmap for a single host and persist open ports."""
    t0 = time.perf_counter()
    db = SessionLocal()
    try:
        host = db.query(models.Host).filter(models.Host.id == host_id).first()
        if not host:
            return
        logger.info(f"nmap_host: start host_id={host_id} ip={host.ip}")
        nm = nmap.PortScanner()
        args = os.environ.get("NMAP_ARGS", "-Pn -T3 --top-ports 1000 -sS -sV")
        if "--top-1000-ports" in args:
            args = args.replace("--top-1000-ports", "--top-ports 1000")
        try:
            if hasattr(os, "geteuid") and os.geteuid() != 0 and "-sS" in args and "-sT" not in args:
                args = args.replace("-sS", "-sT")
                logger.info(f"nmap_host: not root; using -sT for host_id={host_id}")
        except Exception:
            pass
        try:
            nm.scan(host.ip, arguments=args)
            ports_written = 0
            if host.ip in nm.all_hosts():
                # capture MAC if available
                try:
                    mac_addr = nm[host.ip].get('addresses', {}).get('mac')
                    if mac_addr and (not host.mac):
                        host.mac = mac_addr.lower()
                except Exception:
                    pass
                for proto in nm[host.ip].all_protocols():
                    for port, data in nm[host.ip][proto].items():
                        hop = models.HostOpenPort(
                            host_id=host.id,
                            port=int(port),
                            proto=str(proto),
                            service=(data.get("name") if isinstance(data, dict) else None),
                            state=(data.get("state") if isinstance(data, dict) else None),
                        )
                        db.add(hop)
                        ports_written += 1
            if ports_written:
                commit_with_retry(db)
            dt = int((time.perf_counter() - t0) * 1000)
            logger.info(f"nmap_host: finish host_id={host_id} ip={host.ip} ports={ports_written} duration_ms={dt}")
        except Exception as e:
            dt = int((time.perf_counter() - t0) * 1000)
            logger.info(f"nmap_host: error host_id={host_id} ip={host.ip} duration_ms={dt} err={type(e).__name__}")
    finally:
        db.close()


def _ping_many(ips, workers: int = 128, timeout_ms: int = 500):
    # Run many pings concurrently with a bounded timeout per host.
    # Returns list of tuples (ip, delay_ms_or_None)
    results = []
    if not ips:
        return results
    def _one(ip):
        try:
            return ip, ping(ip, timeout=timeout_ms / 1000.0, unit="ms")
        except Exception:
            return ip, None
    with ThreadPoolExecutor(max_workers=workers) as exe:
        futs = {exe.submit(_one, ip): ip for ip in ips}
        for fut in as_completed(futs):
            results.append(fut.result())
    return results


def _apply_ping_results(db: SessionLocal, subnet_id: int, results):
    # Apply ping results in a single transaction, creating hosts for alive IPs.
    created = 0
    alive = 0
    # Preload existing hosts in subnet for quick lookup
    existing = {h.ip: h for h in db.query(models.Host).all()}
    batch = 0
    for ip_str, delay in results:
        if delay is None:
            continue
        h = existing.get(ip_str)
        if not h:
            h = models.Host(ip=ip_str, subnet_id=subnet_id)
            db.add(h)
            db.flush()
            existing[ip_str] = h
            created += 1
        if h.subnet_id != subnet_id:
            h.subnet_id = subnet_id
        status = models.HostStatus(host_id=h.id, is_up=True, latency_ms=delay)
        if h.first_seen_at is None:
            h.first_seen_at = datetime.utcnow()
        h.last_seen_at = datetime.utcnow()
        db.add(status)
        alive += 1
        batch += 1
        if batch % 200 == 0:
            commit_with_retry(db)
    commit_with_retry(db)
    return created, alive


def _read_arp_cache():
    """Parse system ARP/ND cache using multiple tools into {ip: mac}.
    Tries `ip neigh show` and falls back to `arp -n` (net-tools).
    """
    import subprocess, shlex
    macs = {}
    # Method 1: iproute2
    try:
        out = subprocess.check_output(shlex.split("ip neigh show"), stderr=subprocess.DEVNULL, timeout=2).decode()
        for line in out.splitlines():
            parts = line.split()
            # expected: "IP dev IF lladdr MAC STATE" or IPv6 equivalents
            if len(parts) >= 5 and parts[2] == 'lladdr':
                ip = parts[0]
                mac = parts[3].lower()
                macs[ip] = mac
    except Exception:
        pass
    # Method 2: net-tools arp
    try:
        out = subprocess.check_output(shlex.split("arp -n"), stderr=subprocess.DEVNULL, timeout=2).decode()
        # Skip header, parse lines like: "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(('address', 'arp', 'gateway')):
                continue
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                # Find a token that looks like a MAC address
                for token in parts[1:]:
                    if len(token) == 17 and token.count(':') == 5:
                        macs.setdefault(ip, token.lower())
                        break
    except Exception:
        pass
    return macs

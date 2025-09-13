import os
import time
import logging
from datetime import datetime
from ipaddress import ip_network
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from ping3 import ping
import nmap
import socket
from datetime import timedelta
import json as _json
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import base64

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

# Simple in-memory job status tracking for UI tooltips
JOB_STATUS = {}


def record_job_run(job_id: str, success: bool, meta: str | None = None):
    try:
        JOB_STATUS[job_id] = {
            "last_run": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "success": bool(success),
            "meta": meta,
        }
    except Exception:
        logger.exception("record_job_run: failed for job_id=%s", job_id)


def job_status_snapshot():
    order = [
        ("icmp_scan", "ICMP"),
        ("nmap_scan", "Nmap"),
        ("sweep_subnets", "Sweep"),
        ("rdns_refresh", "Reverse DNS"),
        ("dnslog_refresh", "DNS Logs"),
    ]
    out = []
    for jid, name in order:
        st = JOB_STATUS.get(jid, {})
        out.append({
            "id": jid,
            "name": name,
            "last_run": st.get("last_run"),
            "success": st.get("success"),
            "meta": st.get("meta"),
        })
    return out


def _normalize_delay(value):
    try:
        # ping3 returns float (ms) on success, None/False on failure
        if value is None or value is False:
            return None
        if isinstance(value, (int, float)):
            return float(value)
    except Exception:
        logger.exception("_normalize_delay: failed for value=%s", value)
    return None


def ping_host(ip: str):
    try:
        delay = ping(ip, timeout=1, unit="ms")
        return _normalize_delay(delay)
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
            logger.exception("icmp_scan: ARP cache processing failed")
    finally:
        db.close()
    up = sum(1 for _, d in results if d is not None)
    dt_ms = int((time.perf_counter() - t0) * 1000)
    logger.info(f"icmp_scan: finish hosts={len(results)} up={up} duration_ms={dt_ms}")
    record_job_run("icmp_scan", True, f"up={up} hosts={len(results)}")


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
            logger.exception("nmap_scan: privilege check replace -sS with -sT failed")
        require_up = os.environ.get("NMAP_REQUIRE_UP", "0") == "1"
        alive = 0
        ports_written = 0
        batch = 0
        for host in hosts:
            last = host.statuses[0] if host.statuses else None
            if last and last.is_up:
                alive += 1
            if require_up and not (last and last.is_up):
                continue
            try:
                nm.scan(host.ip, arguments=args)
                if host.ip in nm.all_hosts():
                    # Single timestamp per host scan to group all ports from this run
                    scan_ts = datetime.utcnow()
                    # Capture MAC address from Nmap if available
                    try:
                        mac_addr = nm[host.ip].get('addresses', {}).get('mac')
                        if mac_addr and (not host.mac):
                            host.mac = mac_addr.lower()
                    except Exception:
                        pass
                    for proto in nm[host.ip].all_protocols():
                        # Safely iterate numeric port entries only
                        try:
                            proto_map = nm[host.ip][proto]
                        except Exception:
                            continue
                        for port, data in list(proto_map.items()):
                            try:
                                port_num = int(port)
                            except Exception:
                                continue
                            # Only persist open ports
                            st = data.get("state") if isinstance(data, dict) else None
                            if st != "open":
                                continue
                            hop = models.HostOpenPort(
                                host_id=host.id,
                                port=port_num,
                                proto=str(proto),
                                service=(data.get("name") if isinstance(data, dict) else None),
                                state=st,
                                ts=scan_ts,
                            )
                            db.add(hop)
                            batch += 1
                            ports_written += 1
                            if batch % 50 == 0:
                                commit_with_retry(db)
            except Exception:
                # Log Nmap errors per host, continue scanning others
                logger.exception("nmap_scan: scanning host_id=%s ip=%s failed", getattr(host, 'id', None), getattr(host, 'ip', None))
        commit_with_retry(db)
    finally:
        db.close()
    dt_ms = int((time.perf_counter() - t0) * 1000)
    logger.info(f"nmap_scan: finish alive_hosts={alive} ports_written={ports_written} duration_ms={dt_ms}")
    record_job_run("nmap_scan", True, f"alive={alive} ports={ports_written}")


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
    # Track job executions and errors
    try:
        from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR

        def _listener(event):
            try:
                ok = not getattr(event, "exception", None)
                record_job_run(getattr(event, "job_id", "unknown"), bool(ok))
            except Exception:
                logger.exception("scheduler listener: failed to record job status")

        scheduler.add_listener(_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
    except Exception:
        pass
    scheduler.start()
    # RDNS refresher
    try:
        interval = int(os.environ.get("RDNS_REFRESH_MINUTES", "10"))
    except Exception:
        interval = 10
    scheduler.add_job(
        rdns_refresh,
        "interval",
        minutes=max(1, interval),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
        id="rdns_refresh",
        replace_existing=True,
    )

    # DNS log ingestion (e.g., AdGuard Home /control/querylog)
    try:
        if os.environ.get("DNSLOG_ENABLE", "1") == "1" and os.environ.get("DNSLOG_URL"):
            minutes = int(os.environ.get("DNSLOG_INTERVAL_MINUTES", "5"))
            scheduler.add_job(
                dnslog_refresh,
                "interval",
                minutes=max(1, minutes),
                max_instances=1,
                coalesce=True,
                misfire_grace_time=60,
                id="dnslog_refresh",
                replace_existing=True,
            )
    except Exception:
        logger.debug("dnslog_refresh scheduling failed", exc_info=True)


def rdns_refresh():
    """Background job: resolve reverse DNS for recently-seen external peers.

    - Creates rdns_cache table if missing.
    - Looks back a time window (default 24h) over netflow_flows.
    - Resolves up to a capped number of unique IPs, skipping fresh cache rows.
    """
    from sqlalchemy import text as sql_text
    lookback_minutes = int(os.environ.get("RDNS_LOOKBACK_MINUTES", "1440"))
    cap = int(os.environ.get("RDNS_MAX_PER_RUN", "300"))
    ttl_minutes = int(os.environ.get("RDNS_TTL_MINUTES", "1440"))  # re-resolve daily by default
    cutoff = datetime.utcnow() - timedelta(minutes=max(1, lookback_minutes))
    upserted_count = 0
    try:
        with SessionLocal().bind.connect() as conn:
            # Ensure cache table exists (Postgres types if available)
            if str(conn.dialect.name).startswith("postgres"):
                conn.exec_driver_sql(
                    """
                    CREATE TABLE IF NOT EXISTS rdns_cache (
                      ip INET PRIMARY KEY,
                      hostname TEXT,
                      last_resolved TIMESTAMPTZ
                    );
                    """
                )
            else:
                conn.exec_driver_sql(
                    """
                    CREATE TABLE IF NOT EXISTS rdns_cache (
                      ip TEXT PRIMARY KEY,
                      hostname TEXT,
                      last_resolved TEXT
                    );
                    """
                )

            # Collect recent external IPs (either src or dst not in any subnet)
            recent_ips = set()
            try:
                rows = conn.execute(
                    sql_text(
                        """
                        WITH internal AS (
                          SELECT cidr FROM subnet
                        )
                        SELECT DISTINCT host(ipv) AS ip
                        FROM (
                          SELECT nf.src_addr AS ipv FROM netflow_flows nf WHERE nf.ts >= :cut
                          UNION ALL
                          SELECT nf.dst_addr AS ipv FROM netflow_flows nf WHERE nf.ts >= :cut
                        ) t
                        WHERE NOT EXISTS (
                          SELECT 1 FROM internal i WHERE t.ipv << cidr(i.cidr)
                        )
                        LIMIT :cap
                        """
                    ),
                    {"cut": cutoff, "cap": cap},
                ).fetchall()
                for r in rows:
                    if r.ip:
                        recent_ips.add(str(r.ip))
            except Exception:
                recent_ips = set()

            if not recent_ips:
                return

            # Load existing cache entries to apply TTL
            cache = {}
            try:
                cres = conn.execute(sql_text("SELECT ip, hostname, last_resolved FROM rdns_cache")).fetchall()
                for ip, host, ts in cres:
                    cache[str(ip)] = (host, ts)
            except Exception:
                cache = {}

            # Resolve with short timeout
            prev_to = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(float(os.environ.get("RDNS_TIMEOUT_SECONDS", "0.5")))
                to_upsert = []
                for ip in recent_ips:
                    # Skip fresh cache entries
                    ts = None
                    if ip in cache:
                        try:
                            ts = cache[ip][1]
                            if isinstance(ts, str):
                                # sqlite path: parse-ish; treat any string as fresh to avoid churn
                                ts = datetime.utcnow()
                        except Exception:
                            ts = None
                    if ts is not None:
                        try:
                            if (datetime.utcnow() - ts) < timedelta(minutes=ttl_minutes):
                                continue
                        except Exception:
                            pass
                    try:
                        host, _, _ = socket.gethostbyaddr(ip)
                        if host and host != ip:
                            host = host.rstrip('.')
                            logger.info(f"rdns_refresh: match ip={ip} host={host}")
                            to_upsert.append((ip, host))
                        else:
                            # still upsert empty hostname to mark as attempted
                            to_upsert.append((ip, None))
                    except Exception:
                        to_upsert.append((ip, None))
                # Upsert into cache
                if to_upsert:
                    if str(conn.dialect.name).startswith("postgres"):
                        conn.exec_driver_sql(
                            "INSERT INTO rdns_cache (ip, hostname, last_resolved) VALUES (%(ip)s, %(host)s, NOW()) "
                            "ON CONFLICT (ip) DO UPDATE SET hostname = EXCLUDED.hostname, last_resolved = EXCLUDED.last_resolved",
                            [{"ip": ip, "host": host} for ip, host in to_upsert],
                        )
                    else:
                        conn.execute(
                            sql_text("INSERT OR REPLACE INTO rdns_cache (ip, hostname, last_resolved) VALUES (:ip, :host, :ts)"),
                            [{"ip": ip, "host": host, "ts": datetime.utcnow().isoformat()} for ip, host in to_upsert],
                        )
                    upserted_count = len(to_upsert)
                    logger.info(f"rdns_refresh: upserted={upserted_count}")
            finally:
                socket.setdefaulttimeout(prev_to)
    except Exception:
        # Background; swallow errors
        logger.debug("rdns_refresh encountered an error", exc_info=True)
        record_job_run("rdns_refresh", False)
        return
    record_job_run("rdns_refresh", True, f"upserted={upserted_count}")


def dnslog_refresh():
    """For recent external IPs seen in NetFlow, query the DNS log API per IP
    to find domains that resolved to the IP, then upsert IP→domain in rdns_cache.

    Env:
      - DNSLOG_URL, DNSLOG_BASIC_AUTH, DNSLOG_LIMIT, DNSLOG_MAX_PER_RUN
    """
    url = os.environ.get("DNSLOG_URL")
    if not url:
        return
    limit = int(os.environ.get("DNSLOG_LIMIT", "10000"))
    max_upserts = int(os.environ.get("DNSLOG_MAX_PER_RUN", "300"))
    # Collect recent external IPs from flows (reuse rdns_refresh logic)
    from sqlalchemy import text as sql_text
    recent_ips = []
    try:
        with SessionLocal().bind.connect() as conn:
            rows = conn.execute(
                sql_text(
                    """
                    WITH internal AS (
                      SELECT cidr FROM subnet
                    )
                    SELECT DISTINCT host(ipv) AS ip
                    FROM (
                      SELECT nf.src_addr AS ipv FROM netflow_flows nf WHERE nf.ts >= NOW() - INTERVAL '24 hours'
                      UNION ALL
                      SELECT nf.dst_addr AS ipv FROM netflow_flows nf WHERE nf.ts >= NOW() - INTERVAL '24 hours'
                    ) t
                    WHERE NOT EXISTS (
                      SELECT 1 FROM internal i WHERE t.ipv << cidr(i.cidr)
                    )
                    LIMIT :cap
                    """
                ),
                {"cap": max_upserts},
            ).fetchall()
            for r in rows:
                if r.ip:
                    recent_ips.append(str(r.ip))
    except Exception:
        logger.error("dnslog_refresh: failed to list recent external IPs", exc_info=True)
        return

    if not recent_ips:
        record_job_run("dnslog_refresh", True, "no-ips")
        return

    def _query_domains_for_ip(ip: str):
        params = urlencode({"older_than": "", "limit": str(limit)})
        full_url = f"{url}?{params}" if "?" not in url else f"{url}&{params}"
        req = Request(full_url)
        auth = os.environ.get("DNSLOG_BASIC_AUTH")
        if auth and ":" in auth:
            token = base64.b64encode(auth.encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        req.add_header("Accept", "application/json")
        try:
            with urlopen(req, timeout=6) as resp:
                payload = _json.loads(resp.read().decode("utf-8", errors="ignore") or "{}")
        except Exception:
            return None
        data = payload.get("data") or []
        domains = []
        for entry in data:
            try:
                q = (entry.get("question") or {}).get("name")
                if not q:
                    continue
                answers = entry.get("answer") or []
                hit = False
                for ans in answers:
                    t = (ans.get("type") or "").upper()
                    if t in ("A", "AAAA") and str(ans.get("value")) == ip:
                        hit = True
                        break
                if hit:
                    domains.append(q.rstrip('.'))
            except Exception:
                continue
        if not domains:
            return None
        # Return the first unique domain
        seen = set()
        for d in domains:
            if d not in seen:
                seen.add(d)
                return d
        return None

    t0 = time.perf_counter()
    upserts = []
    logger.info(f"dnslog_refresh: scanning_ips={len(recent_ips)} limit_per_run={max_upserts}")
    for ip in recent_ips:
        dom = _query_domains_for_ip(ip)
        if dom:
            logger.info(f"dnslog_refresh: match ip={ip} domain={dom}")
            upserts.append({"ip": ip, "host": dom})
        if len(upserts) >= max_upserts:
            break

    if not upserts:
        record_job_run("dnslog_refresh", True, "no-mappings")
        return

    try:
        with SessionLocal().bind.begin() as conn:
            # Ensure table exists
            if str(conn.dialect.name).startswith("postgres"):
                conn.exec_driver_sql(
                    """
                    CREATE TABLE IF NOT EXISTS rdns_cache (
                      ip INET PRIMARY KEY,
                      hostname TEXT,
                      last_resolved TIMESTAMPTZ
                    );
                    """
                )
            else:
                conn.execute(
                    sql_text(
                        """
                        CREATE TABLE IF NOT EXISTS rdns_cache (
                          ip TEXT PRIMARY KEY,
                          hostname TEXT,
                          last_resolved TEXT
                        );
                        """
                    )
                )
            if str(conn.dialect.name).startswith("postgres"):
                conn.exec_driver_sql(
                    "INSERT INTO rdns_cache (ip, hostname, last_resolved) VALUES (%(ip)s, %(host)s, NOW()) "
                    "ON CONFLICT (ip) DO UPDATE SET hostname = EXCLUDED.hostname, last_resolved = EXCLUDED.last_resolved",
                    upserts,
                )
            else:
                conn.execute(
                    sql_text("INSERT OR REPLACE INTO rdns_cache (ip, hostname, last_resolved) VALUES (:ip, :host, :ts)"),
                    [{"ip": r["ip"], "host": r["host"], "ts": datetime.utcnow().isoformat()} for r in upserts],
                )
        dt = int((time.perf_counter() - t0) * 1000)
        logger.info(f"dnslog_refresh: matches={len(upserts)} duration_ms={dt}")
        record_job_run("dnslog_refresh", True, f"upserted={len(upserts)} in {dt}ms")
    except Exception:
        logger.error("dnslog_refresh: upsert failed", exc_info=True)
        record_job_run("dnslog_refresh", False, "upsert-failed")


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
                # Single timestamp for all ports from this scan
                scan_ts = datetime.utcnow()
                # capture MAC if available
                try:
                    mac_addr = nm[host.ip].get('addresses', {}).get('mac')
                    if mac_addr and (not host.mac):
                        host.mac = mac_addr.lower()
                except Exception:
                    pass
                for proto in nm[host.ip].all_protocols():
                    try:
                        proto_map = nm[host.ip][proto]
                    except Exception:
                        continue
                    for port, data in list(proto_map.items()):
                        try:
                            port_num = int(port)
                        except Exception:
                            continue
                        st = data.get("state") if isinstance(data, dict) else None
                        if st != "open":
                            continue
                        hop = models.HostOpenPort(
                            host_id=host.id,
                            port=port_num,
                            proto=str(proto),
                            service=(data.get("name") if isinstance(data, dict) else None),
                            state=st,
                            ts=scan_ts,
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
            val = ping(ip, timeout=timeout_ms / 1000.0, unit="ms")
            return ip, _normalize_delay(val)
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


def refresh_mac_for_host_id(host_id: int):
    """Attempt to populate MAC for a single host via ARP cache.
    Tries a quick ping to populate the ARP table, then reads it.
    """
    db = SessionLocal()
    try:
        host = db.query(models.Host).filter(models.Host.id == host_id).first()
        if not host:
            return
        # Trigger ARP resolution
        try:
            ping_host(host.ip)
        except Exception:
            pass
        macs = _read_arp_cache()
        mac = macs.get(host.ip)
        if mac and (not host.mac):
            host.mac = mac
            commit_with_retry(db)
    finally:
        db.close()

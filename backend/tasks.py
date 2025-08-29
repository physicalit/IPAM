import os
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from ping3 import ping
import nmap

from .database import SessionLocal
from . import models

scheduler = AsyncIOScheduler()


def ping_host(ip: str):
    try:
        delay = ping(ip, timeout=1, unit="ms")
        return delay
    except Exception:
        return None


def icmp_scan():
    db = SessionLocal()
    hosts = db.query(models.Host).all()
    for host in hosts:
        delay = ping_host(host.ip)
        status = models.HostStatus(host_id=host.id, is_up=delay is not None, latency_ms=delay)
        if delay is not None:
            if host.first_seen_at is None:
                host.first_seen_at = datetime.utcnow()
            host.last_seen_at = datetime.utcnow()
        db.add(status)
    db.commit()
    db.close()


def nmap_scan():
    db = SessionLocal()
    nm = nmap.PortScanner()
    hosts = db.query(models.Host).all()
    args = os.environ.get("NMAP_ARGS", "-Pn -T3 --top-1000-ports -sS -sV")
    for host in hosts:
        last = host.statuses[0] if host.statuses else None
        if last and last.is_up:
            try:
                nm.scan(host.ip, arguments=args)
                for proto in nm[host.ip].all_protocols():
                    for port, data in nm[host.ip][proto].items():
                        hop = models.HostOpenPort(
                            host_id=host.id,
                            port=port,
                            proto=proto,
                            service=data.get("name"),
                            state=data.get("state"),
                        )
                        db.add(hop)
            except Exception:
                pass
    db.commit()
    db.close()


def start_scheduler():
    scheduler.add_job(icmp_scan, "interval", seconds=int(os.environ.get("SCAN_ICMP_INTERVAL_SECONDS", "60")))
    scheduler.add_job(nmap_scan, "interval", minutes=int(os.environ.get("SCAN_NMAP_INTERVAL_MINUTES", "60")))
    scheduler.start()

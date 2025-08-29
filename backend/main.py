import os
from fastapi import FastAPI, Request, Depends, Form, Path
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text as sql_text, inspect
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from ipaddress import ip_network, ip_address
import json

from .database import engine, Base, get_db, commit_with_retry
from . import models
from .auth import router as auth_router
from .tasks import start_scheduler, icmp_scan, nmap_scan, scan_single_subnet, scan_single_subnet_id, scan_host_ports_id
import logging
logger = logging.getLogger("ipam.web")
import threading

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "changeme"))
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(auth_router)

templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    # Add missing columns (simple migration): mac on host
    try:
        inspector = inspect(engine)
        cols = [c['name'] for c in inspector.get_columns('host')]
        if 'mac' not in cols:
            with engine.begin() as conn:
                conn.execute(sql_text("ALTER TABLE host ADD COLUMN mac VARCHAR(64)"))
    except Exception:
        pass
    # ensure default user
    db = next(get_db())
    if not db.query(models.User).filter_by(username="admin").first():
        import bcrypt

        hashed = bcrypt.hashpw(os.environ.get("ADMIN_PASSWORD", "admin").encode(), bcrypt.gensalt()).decode()
        user = models.User(username="admin", hashed_password=hashed)
        db.add(user)
        db.commit()
    db.close()
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        start_scheduler()
        # Kick off initial scans in background so startup isn't blocked
        def _kickoff():
            try:
                icmp_scan()
                nmap_scan()
            except Exception:
                pass

        threading.Thread(target=_kickoff, daemon=True).start()


@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    hosts = db.query(models.Host).all()
    # Sort hosts by IP address (numeric), IPv4 before IPv6
    def _ip_key(h):
        try:
            ip = ip_address(h.ip)
            return (ip.version, int(ip))
        except Exception:
            return (9, h.ip)
    hosts = sorted(hosts, key=_ip_key)
    # Build latest open ports summary per host for tooltip display
    port_summaries = {}
    for h in hosts:
        try:
            if not h.open_ports:
                continue
            latest_ts = h.open_ports[0].ts
            current = [p for p in h.open_ports if p.ts == latest_ts]
            items = []
            for p in current:
                label = f"{p.port}/{p.proto}"
                if p.service:
                    label += f" {p.service}"
                items.append(label)
            if items:
                port_summaries[h.id] = ", ".join(sorted(items, key=lambda s: (s.split('/')[0].isdigit() and int(s.split('/')[0]) or 0)))
        except Exception:
            continue
    subnets = db.query(models.Subnet).all()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "hosts": hosts, "subnets": subnets, "port_summaries": port_summaries},
    )


@app.post("/hosts")
def add_host(request: Request, ip: str = Form(...), subnet_id: int = Form(None), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Auto-attach to the most specific matching subnet, treat as reservation
    try:
        from ipaddress import ip_address, ip_network

        ip_obj = ip_address(ip)
        best = None
        for sn in db.query(models.Subnet).all():
            try:
                net = ip_network(sn.cidr, strict=False)
            except Exception:
                continue
            if ip_obj in net:
                if best is None or net.prefixlen > best[0].prefixlen:
                    best = (net, sn)
        if best:
            subnet_id = best[1].id
    except Exception:
        pass

    # Upsert-like behavior for reservations on duplicate IPs
    existing = db.query(models.Host).filter(models.Host.ip == ip).first()
    if existing:
        try:
            # Merge reserved flag into tags
            tags = {}
            try:
                if existing.tags_json:
                    tags = json.loads(existing.tags_json)
            except Exception:
                tags = {}
            tags["reserved"] = True
            existing.tags_json = json.dumps(tags)
            # Update subnet link if we found a more specific subnet
            if subnet_id and existing.subnet_id != subnet_id:
                existing.subnet_id = subnet_id
            if not commit_with_retry(db):
                raise RuntimeError("commit failed")
        except Exception:
            hosts = db.query(models.Host).all()
            subnets = db.query(models.Subnet).all()
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
                status_code=503,
            )
        return RedirectResponse("/", status_code=302)
    else:
        # Create new reserved host
        tags = {"reserved": True}
        host = models.Host(ip=ip, subnet_id=subnet_id, tags_json=json.dumps(tags))
        db.add(host)
        if not commit_with_retry(db):
            # Return a friendly error page if DB stayed locked
            hosts = db.query(models.Host).all()
            subnets = db.query(models.Subnet).all()
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
                status_code=503,
            )
    return RedirectResponse("/", status_code=302)


@app.post("/subnets")
def add_subnet(request: Request, cidr: str = Form(...), name: str = Form(...), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Validate and normalize CIDR
    try:
        normalized = str(ip_network(cidr, strict=False))
    except Exception:
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": f"Invalid CIDR: {cidr}"},
            status_code=400,
        )

    subnet = models.Subnet(cidr=normalized, name=name)
    db.add(subnet)
    try:
        if not commit_with_retry(db):
            raise IntegrityError("locked", params=None, orig=None)
    except IntegrityError:
        db.rollback()
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "hosts": hosts,
                "subnets": subnets,
                "error": f"Subnet already exists: {normalized}",
            },
            status_code=400,
        )
    # Immediately sweep the new subnet so results appear fast
    if os.environ.get("DISABLE_SCHEDULER") != "1":
        # Run the scan asynchronously to keep UX snappy (only this subnet)
        def _scan_once(subnet_id: int):
            try:
                scan_single_subnet_id(subnet_id)
            except Exception:
                pass

        threading.Thread(target=_scan_once, args=(subnet.id,), daemon=True).start()
    return RedirectResponse("/", status_code=302)


@app.post("/subnets/{subnet_id}/scan")
def scan_subnet_now(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Fire-and-forget background scan for this subnet
    def _scan_once():
        try:
            scan_single_subnet_id(subnet_id)
        except Exception:
            pass

    threading.Thread(target=_scan_once, daemon=True).start()
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/scan_ports")
def scan_host_ports(request: Request, host_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    def _scan():
        try:
            logger.info(f"scan_ports_request: host_id={host_id}")
            scan_host_ports_id(host_id)
        except Exception:
            pass
    threading.Thread(target=_scan, daemon=True).start()
    return RedirectResponse("/", status_code=302)


@app.post("/subnets/{subnet_id}/rename")
def rename_subnet(request: Request, subnet_id: int, name: str = Form(...), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        return RedirectResponse("/", status_code=302)
    subnet.name = name.strip()
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)


@app.post("/subnets/{subnet_id}/delete")
def delete_subnet(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    subnet = db.query(models.Subnet).filter(models.Subnet.id == subnet_id).first()
    if not subnet:
        return RedirectResponse("/", status_code=302)
    # For hosts in this subnet: delete unreserved; keep reserved (detach)
    hosts_in_subnet = db.query(models.Host).filter(models.Host.subnet_id == subnet_id).all()
    for h in hosts_in_subnet:
        is_reserved = False
        try:
            if h.tags_json and 'reserved' in (json.loads(h.tags_json) or {}):
                is_reserved = True
        except Exception:
            is_reserved = False
        if is_reserved:
            # keep but detach from subnet
            h.subnet_id = None
        else:
            # remove host and related data
            db.query(models.HostOpenPort).filter(models.HostOpenPort.host_id == h.id).delete()
            db.query(models.HostStatus).filter(models.HostStatus.host_id == h.id).delete()
            db.delete(h)
    db.delete(subnet)
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/hostname")
def set_hostname(
    request: Request,
    host_id: int = Path(...),
    hostname: str = Form(...),
    db: Session = Depends(get_db),
):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)
    # Only allow setting hostname if currently empty (editable when scans have not identified one)
    if not host.hostname:
        host.hostname = hostname.strip()
        # Mark as reserved when hostname is set manually
        try:
            tags = {}
            if host.tags_json:
                try:
                    tags = json.loads(host.tags_json)
                except Exception:
                    tags = {}
            tags["reserved"] = True
            host.tags_json = json.dumps(tags)
        except Exception:
            pass
        if not commit_with_retry(db):
            hosts = db.query(models.Host).all()
            subnets = db.query(models.Subnet).all()
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
                status_code=503,
            )
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/hostname/clear")
def clear_hostname(
    request: Request,
    host_id: int = Path(...),
    db: Session = Depends(get_db),
):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if host:
        host.hostname = None
        if not commit_with_retry(db):
            hosts = db.query(models.Host).all()
            subnets = db.query(models.Subnet).all()
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
                status_code=503,
            )
    return RedirectResponse("/", status_code=302)


# Note: MAC address is not user-editable; it is populated by scanners (Nmap/ARP).


@app.post("/hosts/{host_id}/unreserve")
def unreserve_host(
    request: Request,
    host_id: int = Path(...),
    db: Session = Depends(get_db),
):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)

    # Determine last known status
    last = host.statuses[0] if host.statuses else None
    is_up = bool(last and last.is_up)

    # If up: keep host, just remove reserved flag
    # If down: remove host entirely (and related rows)
    try:
        if is_up:
            tags = {}
            try:
                if host.tags_json:
                    tags = json.loads(host.tags_json)
            except Exception:
                tags = {}
            if "reserved" in tags:
                del tags["reserved"]
            host.tags_json = json.dumps(tags) if tags else None
            # Clear hostname when unreserving
            host.hostname = None
        else:
            # clean related rows then delete
            db.query(models.HostOpenPort).filter(models.HostOpenPort.host_id == host.id).delete()
            db.query(models.HostStatus).filter(models.HostStatus.host_id == host.id).delete()
            db.delete(host)
        if not commit_with_retry(db):
            raise RuntimeError("commit failed")
    except Exception:
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)

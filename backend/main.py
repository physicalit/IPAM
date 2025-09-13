import os
from fastapi import FastAPI, Request, Depends, Form, Path, UploadFile, File
from fastapi.responses import RedirectResponse, StreamingResponse, PlainTextResponse, JSONResponse
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
from .tasks import (
    start_scheduler,
    icmp_scan,
    nmap_scan,
    scan_single_subnet_id,
    scan_host_ports_id,
    refresh_mac_for_host_id,
    rdns_refresh,
    dnslog_refresh,
    job_status_snapshot,
)
import logging
logger = logging.getLogger("ipam.web")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper()))
import threading
import csv
from io import StringIO
from datetime import timedelta

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "changeme"))
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(auth_router)

templates = Jinja2Templates(directory="templates")
# Template globals: expose flags
templates.env.globals["scheduler_enabled"] = (os.environ.get("DISABLE_SCHEDULER") != "1")
templates.env.globals["netflow_enabled"] = str(engine.dialect.name).startswith("postgres")
templates.env.globals["job_status"] = job_status_snapshot


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
        logger.exception("startup: failed to ensure host.mac column")
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
                # Seed RDNS cache once on startup
                rdns_refresh()
                # Seed DNS forward cache (from external logs) once on startup
                try:
                    dnslog_refresh()
                except Exception:
                    logger.exception("startup: dnslog_refresh failed")
            except Exception:
                logger.exception("startup: initial background scans failed")

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
            logger.exception("dashboard: failed to parse IP: %s", getattr(h, 'ip', None))
            return (9, h.ip)
    hosts = sorted(hosts, key=_ip_key)
    # Build latest open ports summary per host for tooltip display
    # Ports are grouped by protocol and sorted numerically. The tooltip uses
    # line breaks for easier scanning (rendered via CSS white-space: pre-line).
    port_summaries = {}
    for h in hosts:
        try:
            if not h.open_ports:
                continue
            latest_ts = h.open_ports[0].ts
            # Take ports from the most recent scan timestamp
            current = []
            for p in h.open_ports:
                if p.ts != latest_ts:
                    continue
                # Only show open ports; legacy entries might lack state
                if p.state and str(p.state).lower() != "open":
                    continue
                current.append(p)
            if not current:
                continue
            by_proto = {}
            for p in current:
                proto = (p.proto or "").lower() or "tcp"
                by_proto.setdefault(proto, []).append((int(p.port), (p.service or "").strip()))
            lines = []
            for proto in sorted(by_proto.keys()):
                ports = sorted(by_proto[proto], key=lambda t: t[0])
                parts = []
                for port_num, svc in ports:
                    if svc:
                        parts.append(f"{port_num} {svc}")
                    else:
                        parts.append(f"{port_num}")
                label_proto = proto.upper()
                lines.append(f"{label_proto}: {', '.join(parts)}")
            port_summaries[h.id] = "\n".join(lines)
        except Exception:
            logger.exception("dashboard: failed building ports summary for host_id=%s", getattr(h, 'id', None))
            continue
    subnets = db.query(models.Subnet).all()
    # Compute count of UP hosts per subnet (latest ping status)
    subnet_up_counts = {}
    for h in hosts:
        try:
            if h.subnet_id is None:
                continue
            last = h.statuses[0] if h.statuses else None
            if last and last.is_up:
                subnet_up_counts[h.subnet_id] = subnet_up_counts.get(h.subnet_id, 0) + 1
        except Exception:
            logger.exception("dashboard: failed to compute UP count for subnet_id=%s", getattr(h, 'subnet_id', None))
            continue
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "hosts": hosts, "subnets": subnets, "port_summaries": port_summaries, "subnet_up_counts": subnet_up_counts},
    )


@app.get("/health")
def health(request: Request, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return JSONResponse({"error": "auth required"}, status_code=401)
    try:
        hosts = db.query(models.Host).count()
        subnets = db.query(models.Subnet).count()
        statuses = db.query(models.HostStatus).count()
        ports = db.query(models.HostOpenPort).count()
    except Exception:
        logger.exception("health: failed counting ORM tables")
        hosts = subnets = statuses = ports = None
    netflow_rows = None
    try:
        with engine.connect() as conn:
            netflow_rows = conn.execute(sql_text("SELECT COUNT(*) FROM netflow_flows")).scalar()
    except Exception:
        logger.exception("health: failed to count netflow_flows")
    data = {
        "scheduler_enabled": os.environ.get("DISABLE_SCHEDULER") != "1",
        "db": {
            "hosts": hosts,
            "subnets": subnets,
            "host_status": statuses,
            "host_open_port": ports,
            "netflow_flows": netflow_rows,
        },
        "dialect": str(engine.dialect.name),
    }
    return JSONResponse(data)


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
        logger.exception("netflow_clear: clearing table failed")

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


def _csv_response(filename: str, content: str) -> StreamingResponse:
    resp = StreamingResponse(iter([content]), media_type="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _ensure_rdns_cache_table_conn(conn):
    """Ensure rdns_cache exists on the provided connection (Postgres only)."""
    try:
        if str(engine.dialect.name).startswith("postgres"):
            conn.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS rdns_cache (
                  ip INET PRIMARY KEY,
                  hostname TEXT,
                  last_resolved TIMESTAMPTZ
                );
                """
            )
            # Migrate legacy schemas where ip was created as TEXT
            try:
                rows = conn.exec_driver_sql(
                    "SELECT data_type FROM information_schema.columns WHERE table_name='rdns_cache' AND column_name='ip'"
                ).fetchall()
                if rows:
                    dt = str(rows[0][0] or "").lower()
                    if dt != "inet":
                        conn.exec_driver_sql("ALTER TABLE rdns_cache ALTER COLUMN ip TYPE INET USING ip::inet")
            except Exception:
                logger.exception("_ensure_rdns_cache_table_conn: migration check failed")
    except Exception:
        logger.exception("_ensure_rdns_cache_table_conn: ensure table failed")


@app.get("/export/subnets")
def export_subnets(request: Request, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "cidr", "name", "notes"])
    for sn in db.query(models.Subnet).all():
        writer.writerow([sn.id, sn.cidr, sn.name or "", sn.notes or ""])
    return _csv_response("subnets.csv", output.getvalue())


@app.get("/export/hosts")
def export_hosts(request: Request, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id",
        "ip",
        "subnet_id",
        "hostname",
        "description",
        "tags_json",
        "first_seen_at",
        "last_seen_at",
        "mac",
    ])
    for h in db.query(models.Host).all():
        writer.writerow([
            h.id,
            h.ip,
            h.subnet_id if h.subnet_id is not None else "",
            h.hostname or "",
            h.description or "",
            h.tags_json or "",
            h.first_seen_at.isoformat() if h.first_seen_at else "",
            h.last_seen_at.isoformat() if h.last_seen_at else "",
            h.mac or "",
        ])
    return _csv_response("hosts.csv", output.getvalue())


@app.post("/import/subnets")
def import_subnets(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    try:
        content = file.file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(StringIO(content))
        count = 0
        for row in reader:
            cidr = (row.get("cidr") or row.get("CIDR") or "").strip()
            name = (row.get("name") or row.get("NAME") or "").strip() or cidr
            notes = (row.get("notes") or row.get("NOTES") or "").strip() or None
            if not cidr:
                continue
            # normalize
            try:
                norm = str(ip_network(cidr, strict=False))
            except Exception:
                continue
            sn = db.query(models.Subnet).filter(models.Subnet.cidr == norm).first()
            if not sn:
                sn = models.Subnet(cidr=norm, name=name, notes=notes)
                db.add(sn)
            else:
                sn.name = name or sn.name
                sn.notes = notes if notes is not None else sn.notes
            count += 1
        if not commit_with_retry(db):
            return PlainTextResponse("Database busy, please retry.", status_code=503)
        return RedirectResponse("/", status_code=302)
    finally:
        try:
            file.file.close()
        except Exception:
            pass


@app.post("/import/hosts")
def import_hosts(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    try:
        content = file.file.read().decode("utf-8", errors="ignore")
        reader = csv.DictReader(StringIO(content))
        count = 0
        for row in reader:
            ip = (row.get("ip") or row.get("IP") or "").strip()
            if not ip:
                continue
            subnet_id = row.get("subnet_id") or row.get("SUBNET_ID")
            subnet_id = int(subnet_id) if (subnet_id and str(subnet_id).isdigit()) else None
            hostname = (row.get("hostname") or "").strip() or None
            description = (row.get("description") or "").strip() or None
            tags_json = (row.get("tags_json") or "").strip() or None
            mac = (row.get("mac") or "").strip() or None
            # upsert by IP
            h = db.query(models.Host).filter(models.Host.ip == ip).first()
            if not h:
                h = models.Host(ip=ip)
                db.add(h)
            if subnet_id is not None:
                h.subnet_id = subnet_id
            if hostname:
                h.hostname = hostname
            if description:
                h.description = description
            if tags_json:
                h.tags_json = tags_json
            if mac:
                h.mac = mac.lower()
            count += 1
        if not commit_with_retry(db):
            return PlainTextResponse("Database busy, please retry.", status_code=503)
        return RedirectResponse("/", status_code=302)
    finally:
        try:
            file.file.close()
        except Exception:
            pass


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


@app.get("/netflow")
def netflow_analysis(request: Request, minutes: int = 60, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Guard: requires PostgreSQL (netflow_flows is Postgres-specific inet/timestamptz)
    if not str(engine.dialect.name).startswith("postgres"):
        return templates.TemplateResponse(
            "netflow.html",
            {
                "request": request,
                "error": "NetFlow analysis requires PostgreSQL. Configure DATABASE_URL to Postgres.",
                "minutes": minutes,
                "subnets": [],
                "edges": [],
            },
        )

    ts_from = datetime.utcnow() - timedelta(minutes=max(1, min(minutes, 24 * 60)))
    # Load subnets once
    subnets = db.query(models.Subnet).all()
    subnet_results = []
    edges = []
    scanners = []
    scan_pairs = {"initiators": {}, "responders": {}}  # maps local_ip -> list of remote peers (display, count)
    try:
        # Use AUTOCOMMIT to avoid a failed statement poisoning subsequent queries
        with engine.connect() as _raw:
            conn = _raw.execution_options(isolation_level="AUTOCOMMIT")
            # Build latest ping status per host (map by IP)
            status_map = {}
            try:
                stat_rows = conn.execute(
                    sql_text(
                        """
                        SELECT h.ip AS ip,
                               (
                                  SELECT hs.is_up FROM host_status hs
                                  WHERE hs.host_id = h.id
                                  ORDER BY hs.ts DESC
                                  LIMIT 1
                               ) AS is_up
                        FROM host h
                        """
                    )
                ).fetchall()
                for r in stat_rows:
                    status_map[str(r.ip)] = bool(r.is_up) if r.is_up is not None else None
            except Exception:
                logger.exception("netflow: building status_map failed")
                status_map = {}
            # Cross-subnet edges (map), including External peers
            try:
                edge_rows = conn.execute(
                    sql_text(
                        """
                        SELECT * FROM (
                          -- internal -> internal
                          SELECT 
                            s1.id AS src_id, s1.name AS src_name, s1.cidr AS src_cidr,
                            s2.id AS dst_id, s2.name AS dst_name, s2.cidr AS dst_cidr,
                            SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                            SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                            COUNT(*) AS flows
                          FROM netflow_flows nf
                          JOIN subnet s1 ON nf.src_addr << cidr(s1.cidr)
                          JOIN subnet s2 ON nf.dst_addr << cidr(s2.cidr)
                          WHERE nf.ts >= :ts_from
                          GROUP BY s1.id, s1.name, s1.cidr, s2.id, s2.name, s2.cidr
                          
                          UNION ALL
                          -- internal -> external
                          SELECT 
                            s1.id AS src_id, s1.name AS src_name, s1.cidr AS src_cidr,
                            NULL::int AS dst_id, 'External' AS dst_name, NULL::text AS dst_cidr,
                            SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                            SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                            COUNT(*) AS flows
                          FROM netflow_flows nf
                          JOIN subnet s1 ON nf.src_addr << cidr(s1.cidr)
                          WHERE nf.ts >= :ts_from
                            AND NOT EXISTS (
                              SELECT 1 FROM subnet s2 WHERE nf.dst_addr << cidr(s2.cidr)
                            )
                          GROUP BY s1.id, s1.name, s1.cidr
                          
                          UNION ALL
                          -- external -> internal
                          SELECT 
                            NULL::int AS src_id, 'External' AS src_name, NULL::text AS src_cidr,
                            s2.id AS dst_id, s2.name AS dst_name, s2.cidr AS dst_cidr,
                            SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                            SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                            COUNT(*) AS flows
                          FROM netflow_flows nf
                          JOIN subnet s2 ON nf.dst_addr << cidr(s2.cidr)
                          WHERE nf.ts >= :ts_from
                            AND NOT EXISTS (
                              SELECT 1 FROM subnet s1 WHERE nf.src_addr << cidr(s1.cidr)
                            )
                          GROUP BY s2.id, s2.name, s2.cidr
                        ) t
                        ORDER BY bytes DESC
                        LIMIT 100
                        """
                    ),
                    {"ts_from": ts_from},
                ).fetchall()
                for r in edge_rows:
                    edges.append(
                        {
                            "src_id": r.src_id,
                            "src_name": r.src_name,
                            "src_cidr": r.src_cidr,
                            "dst_id": r.dst_id,
                            "dst_name": r.dst_name,
                            "dst_cidr": r.dst_cidr,
                            "bytes": int(r.bytes or 0),
                            "pkts": int(r.pkts or 0),
                            "flows": int(r.flows or 0),
                        }
                    )
            except Exception:
                logger.exception("netflow: edge_rows query failed")
                edges = []

            # Per-subnet peers (outgoing and incoming top talkers), grouped by local host within the subnet
            for sn in subnets:
                try:
                    out_rows = conn.execute(
                        sql_text(
                            """
                            SELECT 
                              host(nf.src_addr) AS local_ip,
                              lh.hostname AS local_hostname,
                              host(nf.dst_addr) AS remote_ip,
                              rh.hostname AS remote_hostname,
                              SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                              SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                              COUNT(*) AS flows,
                              array_remove(array_agg(DISTINCT nf.protocol), NULL) AS protos,
                              MIN(nf.input_snmp) AS in_if,
                              MIN(nf.output_snmp) AS out_if,
                              sn2.id AS remote_subnet_id,
                              sn2.name AS remote_subnet_name,
                              sn2.cidr AS remote_subnet_cidr
                            FROM netflow_flows nf
                            LEFT JOIN host lh ON lh.ip = host(nf.src_addr)
                            LEFT JOIN host rh ON rh.ip = host(nf.dst_addr)
                            LEFT JOIN subnet sn2 ON nf.dst_addr << cidr(sn2.cidr)
                            WHERE nf.ts >= :ts_from AND nf.src_addr << cidr(:cidr)
                            GROUP BY host(nf.src_addr), lh.hostname, host(nf.dst_addr), rh.hostname, sn2.id, sn2.name, sn2.cidr
                            ORDER BY bytes DESC
                            LIMIT 25
                            """
                        ),
                        {"ts_from": ts_from, "cidr": sn.cidr},
                    ).fetchall()
                except Exception:
                    logger.exception("netflow: out_rows query failed for subnet_id=%s", getattr(sn, 'id', None))
                    out_rows = []
                try:
                    in_rows = conn.execute(
                        sql_text(
                            """
                            SELECT 
                              host(nf.dst_addr) AS local_ip,
                              lh.hostname AS local_hostname,
                              host(nf.src_addr) AS remote_ip,
                              rh.hostname AS remote_hostname,
                              SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                              SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                              COUNT(*) AS flows,
                              array_remove(array_agg(DISTINCT nf.protocol), NULL) AS protos,
                              MIN(nf.input_snmp) AS in_if,
                              MIN(nf.output_snmp) AS out_if,
                              sn2.id AS remote_subnet_id,
                              sn2.name AS remote_subnet_name,
                              sn2.cidr AS remote_subnet_cidr
                            FROM netflow_flows nf
                            LEFT JOIN host lh ON lh.ip = host(nf.dst_addr)
                            LEFT JOIN host rh ON rh.ip = host(nf.src_addr)
                            LEFT JOIN subnet sn2 ON nf.src_addr << cidr(sn2.cidr)
                            WHERE nf.ts >= :ts_from AND nf.dst_addr << cidr(:cidr)
                            GROUP BY host(nf.dst_addr), lh.hostname, host(nf.src_addr), rh.hostname, sn2.id, sn2.name, sn2.cidr
                            ORDER BY bytes DESC
                            LIMIT 25
                            """
                        ),
                        {"ts_from": ts_from, "cidr": sn.cidr},
                    ).fetchall()
                except Exception:
                    logger.exception("netflow: in_rows query failed for subnet_id=%s", getattr(sn, 'id', None))
                    in_rows = []

                # Parse optional ifIndex->label mapping, default to OPNsense-like 1:WAN, 2:LAN
                iflabel_env = os.environ.get("NETFLOW_IFINDEX_LABELS", "1:WAN,2:LAN")
                _map = {}
                try:
                    for part in iflabel_env.split(','):
                        if not part.strip():
                            continue
                        k, v = part.split(':', 1)
                        _map[int(k.strip())] = v.strip()
                except Exception:
                    logger.exception("netflow: failed parsing NETFLOW_IFINDEX_LABELS; using defaults")
                    _map = {1: 'WAN', 2: 'LAN'}

                def _iface(idx: int):
                    if idx is None:
                        return None, None
                    name = _map.get(int(idx), f"if{int(idx)}")
                    role = 'wan' if name.upper() == 'WAN' else ('lan' if name.upper() == 'LAN' else 'other')
                    return name, role

                def _pack(rows, direction: str):
                    items = []
                    for r in rows:
                        # Choose the interface closest to the local host:
                        # - Outgoing (local → remote): packets arrive on LAN (input_snmp)
                        # - Incoming (remote → local): packets leave to LAN (output_snmp)
                        sel_idx = r.in_if if direction == 'out' else r.out_if
                        if sel_idx is None:
                            sel_idx = r.out_if if direction == 'out' else r.in_if
                        ifname, ifrole = _iface(sel_idx) if sel_idx is not None else (None, None)
                        items.append(
                            {
                                "local_ip": r.local_ip,
                                "local_hostname": r.local_hostname,
                                "local_is_up": status_map.get(str(r.local_ip)),
                                "remote_ip": r.remote_ip,
                                "remote_hostname": r.remote_hostname,
                                "remote_is_up": status_map.get(str(r.remote_ip)),
                                "bytes": int(r.bytes or 0),
                                "pkts": int(r.pkts or 0),
                                "flows": int(r.flows or 0),
                                "protos": [p for p in (r.protos or []) if p is not None],
                                "remote_subnet_id": r.remote_subnet_id,
                                "remote_subnet_name": r.remote_subnet_name,
                                "remote_subnet_cidr": r.remote_subnet_cidr,
                                "direction": direction,
                                "ifindex": int(sel_idx) if sel_idx is not None else None,
                                "ifname": ifname,
                                "ifrole": ifrole,
                            }
                        )
                    return items

                subnet_results.append(
                    {
                        "subnet": sn,
                        "out_peers": _pack(out_rows, "out"),
                        "in_peers": _pack(in_rows, "in"),
                    }
                )
            # Top ICMP/ICMPv6 scanners (internal sources generating ping traffic)
            try:
                scanners_rows = conn.execute(
                    sql_text(
                        """
                        SELECT 
                          host(nf.src_addr) AS ip,
                          lh.hostname AS hostname,
                          sn.id AS subnet_id,
                          sn.name AS subnet_name,
                          sn.cidr AS subnet_cidr,
                          SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                          SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                          COUNT(*) AS flows,
                          COUNT(DISTINCT host(nf.dst_addr)) AS peers
                        FROM netflow_flows nf
                        JOIN subnet sn ON nf.src_addr << cidr(sn.cidr)
                        LEFT JOIN host lh ON lh.ip = host(nf.src_addr)
                        WHERE nf.ts >= :ts_from
                          AND (
                               LOWER(COALESCE(nf.protocol, '')) IN ('icmp','icmpv6')
                               OR nf.protocol IN ('1','58')
                          )
                        GROUP BY host(nf.src_addr), lh.hostname, sn.id, sn.name, sn.cidr
                        ORDER BY bytes DESC
                        LIMIT 10
                        """
                    ),
                    {"ts_from": ts_from},
                ).fetchall()
                for r in scanners_rows:
                    scanners.append(
                        {
                            "ip": r.ip,
                            "hostname": r.hostname,
                            "subnet_id": r.subnet_id,
                            "subnet_name": r.subnet_name,
                            "subnet_cidr": r.subnet_cidr,
                            "bytes": int(r.bytes or 0),
                            "pkts": int(r.pkts or 0),
                            "flows": int(r.flows or 0),
                            "peers": int(r.peers or 0),
                            "is_up": status_map.get(str(r.ip)),
                        }
                    )
            except Exception:
                logger.exception("netflow: scanners query failed")
                scanners = []

            # Pair details for initiators (internal src) -> remote (dst)
            try:
                pair_rows = conn.execute(
                    sql_text(
                        """
                        SELECT host(nf.src_addr) AS local_ip,
                               host(nf.dst_addr) AS remote_ip,
                               sn2.id AS remote_subnet_id,
                               sn2.name AS remote_subnet_name,
                               rh.hostname AS remote_hostname,
                               SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                               COUNT(*) AS flows
                        FROM netflow_flows nf
                        JOIN subnet s ON nf.src_addr << cidr(s.cidr)
                        LEFT JOIN subnet sn2 ON nf.dst_addr << cidr(sn2.cidr)
                        LEFT JOIN host rh ON rh.ip = host(nf.dst_addr)
                        WHERE nf.ts >= :ts_from AND (LOWER(COALESCE(nf.protocol,'')) IN ('icmp','icmpv6') OR nf.protocol IN ('1','58'))
                        GROUP BY host(nf.src_addr), host(nf.dst_addr), sn2.id, sn2.name, rh.hostname
                        ORDER BY bytes DESC
                        LIMIT 300
                        """
                    ),
                    {"ts_from": ts_from},
                ).fetchall()
                for r in pair_rows:
                    key = str(r.local_ip)
                    scan_pairs["initiators"].setdefault(key, [])
                    scan_pairs["initiators"][key].append(
                        {
                            "remote_ip": r.remote_ip,
                            "remote_hostname": r.remote_hostname,
                            "remote_subnet_id": r.remote_subnet_id,
                            "remote_subnet_name": r.remote_subnet_name,
                            "bytes": int(r.bytes or 0),
                            "flows": int(r.flows or 0),
                        }
                    )
            except Exception:
                logger.exception("netflow: initiators pair query failed")

            # Pair details for responders (internal dst) <- remote (src)
            try:
                pair_rows = conn.execute(
                    sql_text(
                        """
                        SELECT host(nf.dst_addr) AS local_ip,
                               host(nf.src_addr) AS remote_ip,
                               sn2.id AS remote_subnet_id,
                               sn2.name AS remote_subnet_name,
                               rh.hostname AS remote_hostname,
                               SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                               COUNT(*) AS flows
                        FROM netflow_flows nf
                        JOIN subnet s ON nf.dst_addr << cidr(s.cidr)
                        LEFT JOIN subnet sn2 ON nf.src_addr << cidr(sn2.cidr)
                        LEFT JOIN host rh ON rh.ip = host(nf.src_addr)
                        WHERE nf.ts >= :ts_from AND (LOWER(COALESCE(nf.protocol,'')) IN ('icmp','icmpv6') OR nf.protocol IN ('1','58'))
                        GROUP BY host(nf.dst_addr), host(nf.src_addr), sn2.id, sn2.name, rh.hostname
                        ORDER BY bytes DESC
                        LIMIT 300
                        """
                    ),
                    {"ts_from": ts_from},
                ).fetchall()
                for r in pair_rows:
                    key = str(r.local_ip)
                    scan_pairs["responders"].setdefault(key, [])
                    scan_pairs["responders"][key].append(
                        {
                            "remote_ip": r.remote_ip,
                            "remote_hostname": r.remote_hostname,
                            "remote_subnet_id": r.remote_subnet_id,
                            "remote_subnet_name": r.remote_subnet_name,
                            "bytes": int(r.bytes or 0),
                            "flows": int(r.flows or 0),
                        }
                    )
            except Exception:
                logger.exception("netflow: responders pair query failed")
    except Exception:
        logger.exception("netflow: main aggregation failed")
        subnet_results = []
        scanners = []

    # Derive WAN/LAN roles per ifIndex using app-defined subnets
    # Heuristic: if an interface carries more bytes to/from External peers,
    # mark it WAN; if it carries more bytes to/from internal subnets, mark it LAN.
    try:
        iface_bytes = {}
        for entry in subnet_results:
            for k in ("out_peers", "in_peers"):
                for p in entry.get(k, []) or []:
                    idx = p.get("ifindex")
                    if idx is None:
                        continue
                    is_external = p.get("remote_subnet_id") is None
                    st = iface_bytes.setdefault(int(idx), {"ext": 0, "int": 0})
                    st["ext" if is_external else "int"] += int(p.get("bytes", 0) or 0)
        # Build role map
        iface_role = {}
        for idx, st in iface_bytes.items():
            if st["ext"] > st["int"]:
                iface_role[idx] = "wan"
            elif st["int"] > st["ext"]:
                iface_role[idx] = "lan"
            # else leave undefined
        # Apply derived roles to items and set human names accordingly
        for entry in subnet_results:
            for k in ("out_peers", "in_peers"):
                for p in entry.get(k, []) or []:
                    idx = p.get("ifindex")
                    if idx is None:
                        continue
                    role = iface_role.get(int(idx))
                    if role:
                        p["ifrole"] = role
                        # Prefer explicit WAN/LAN labels derived from data
                        p["ifname"] = "WAN" if role == "wan" else "LAN"
    except Exception:
        logger.exception("netflow: interface role derivation failed")

    # Reverse DNS from cache
    try:
        # Ensure rdns_cache exists to avoid errors on first load
        with engine.connect() as _c:
            try:
                if str(engine.dialect.name).startswith("postgres"):
                    _c.exec_driver_sql(
                        """
                        CREATE TABLE IF NOT EXISTS rdns_cache (
                          ip INET PRIMARY KEY,
                          hostname TEXT,
                          last_resolved TIMESTAMPTZ
                        );
                        """
                    )
            except Exception:
                logger.exception("netflow: ensure rdns_cache table failed")
        unique_ips = []
        seen = set()
        cap = 200
        for entry in subnet_results:
            for k in ("out_peers", "in_peers"):
                for p in entry.get(k, []) or []:
                    if p.get("remote_subnet_id") is None:
                        ip = p.get("remote_ip")
                        if ip and ip not in seen:
                            seen.add(ip)
                            unique_ips.append(ip)
                            if len(unique_ips) >= cap:
                                break
                if len(unique_ips) >= cap:
                    break
            if len(unique_ips) >= cap:
                break
        if unique_ips:
            placeholders = ",".join(f":ip{i}" for i in range(len(unique_ips)))
            params = {f"ip{i}": ip for i, ip in enumerate(unique_ips)}
            with engine.begin() as conn:
                try:
                    _ensure_rdns_cache_table_conn(conn)
                    rows = conn.execute(
                        sql_text(f"SELECT host(ip::inet) AS ip, hostname FROM rdns_cache WHERE host(ip::inet) IN ({placeholders})"),
                        params,
                    ).fetchall()
                except Exception as e:
                    logger.warning("netflow: rdns_cache lookup failed (phase1): %s", e, exc_info=True)
                    rows = []
            rdns_map = {str(r.ip): r.hostname for r in rows if r.hostname}
            if rdns_map:
                for entry in subnet_results:
                    for k in ("out_peers", "in_peers"):
                        for p in entry.get(k, []) or []:
                            if p.get("remote_subnet_id") is None:
                                ip = p.get("remote_ip")
                                val = rdns_map.get(ip)
                                if val:
                                    p["remote_rdns"] = val
        # Also enrich scanner pairs
        extra_ips = []
        seen2 = set()
        for kind in ("initiators", "responders"):
            for lst in (scan_pairs.get(kind) or {}).values():
                for item in lst:
                    if item.get("remote_subnet_id") is None:
                        ip = item.get("remote_ip")
                        if ip and ip not in seen2:
                            seen2.add(ip)
                            extra_ips.append(ip)
        if extra_ips:
            placeholders2 = ",".join(f":e{i}" for i in range(len(extra_ips)))
            params2 = {f"e{i}": ip for i, ip in enumerate(extra_ips)}
            with engine.begin() as conn:
                try:
                    _ensure_rdns_cache_table_conn(conn)
                    rows2 = conn.execute(
                        sql_text(f"SELECT host(ip::inet) AS ip, hostname FROM rdns_cache WHERE host(ip::inet) IN ({placeholders2})"),
                        params2,
                    ).fetchall()
                except Exception as e:
                    logger.warning("netflow: rdns_cache lookup failed (phase2): %s", e, exc_info=True)
                    rows2 = []
            rdns_map2 = {str(r.ip): r.hostname for r in rows2 if r.hostname}
            if rdns_map2:
                for kind in ("initiators", "responders"):
                    for lst in (scan_pairs.get(kind) or {}).values():
                        for item in lst:
                            if item.get("remote_subnet_id") is None:
                                ip = item.get("remote_ip")
                                val = rdns_map2.get(ip)
                                if val:
                                    item["remote_rdns"] = val
    except Exception:
        logger.exception("netflow: RDNS enrichment failed")

    # Now build merged conversations per subnet (combine Outgoing/Incoming by pair)
    try:
        for entry in subnet_results:
            pairs = {}
            # index by (local_ip, remote_ip)
            for p in (entry.get("out_peers") or []):
                key = (p.get("local_ip"), p.get("remote_ip"))
                it = pairs.setdefault(
                    key,
                    {
                        "local_ip": p.get("local_ip"),
                        "local_hostname": p.get("local_hostname"),
                        "remote_ip": p.get("remote_ip"),
                        "remote_hostname": p.get("remote_hostname"),
                        "remote_rdns": p.get("remote_rdns"),  # <-- ADD THIS LINE
                        "remote_subnet_id": p.get("remote_subnet_id"),
                        "remote_subnet_name": p.get("remote_subnet_name"),
                        "remote_subnet_cidr": p.get("remote_subnet_cidr"),
                        "protos": set(),
                        "out_bytes": 0,
                        "out_pkts": 0,
                        "out_flows": 0,
                        "in_bytes": 0,
                        "in_pkts": 0,
                        "in_flows": 0,
                        "ifindex": p.get("ifindex"),
                        "ifname": p.get("ifname"),
                        "ifrole": p.get("ifrole"),
                        "local_is_up": p.get("local_is_up"),
                        "remote_is_up": p.get("remote_is_up"),
                    },
                )
                it["protos"].update(p.get("protos") or [])
                it["out_bytes"] += int(p.get("bytes", 0) or 0)
                it["out_pkts"] += int(p.get("pkts", 0) or 0)
                it["out_flows"] += int(p.get("flows", 0) or 0)
                # prefer defined ifname/role
                if p.get("ifname") and not it.get("ifname"):
                    it["ifname"] = p.get("ifname")
                if p.get("ifrole") and not it.get("ifrole"):
                    it["ifrole"] = p.get("ifrole")
            for p in (entry.get("in_peers") or []):
                key = (p.get("local_ip"), p.get("remote_ip"))
                it = pairs.setdefault(
                    key,
                    {
                        "local_ip": p.get("local_ip"),
                        "local_hostname": p.get("local_hostname"),
                        "remote_ip": p.get("remote_ip"),
                        "remote_hostname": p.get("remote_hostname"),
                        "remote_rdns": p.get("remote_rdns"),  # <-- ADD THIS LINE
                        "remote_subnet_id": p.get("remote_subnet_id"),
                        "remote_subnet_name": p.get("remote_subnet_name"),
                        "remote_subnet_cidr": p.get("remote_subnet_cidr"),
                        "protos": set(),
                        "out_bytes": 0,
                        "out_pkts": 0,
                        "out_flows": 0,
                        "in_bytes": 0,
                        "in_pkts": 0,
                        "in_flows": 0,
                        "ifindex": p.get("ifindex"),
                        "ifname": p.get("ifname"),
                        "ifrole": p.get("ifrole"),
                        "local_is_up": p.get("local_is_up"),
                        "remote_is_up": p.get("remote_is_up"),
                    },
                )
                it["protos"].update(p.get("protos") or [])
                it["in_bytes"] += int(p.get("bytes", 0) or 0)
                it["in_pkts"] += int(p.get("pkts", 0) or 0)
                it["in_flows"] += int(p.get("flows", 0) or 0)
                if p.get("ifname") and not it.get("ifname"):
                    it["ifname"] = p.get("ifname")
                if p.get("ifrole") and not it.get("ifrole"):
                    it["ifrole"] = p.get("ifrole")

            conv = []
            for it in pairs.values():
                it["total_bytes"] = int(it.get("out_bytes", 0)) + int(it.get("in_bytes", 0))
                it["has_out"] = it.get("out_flows", 0) > 0
                it["has_in"] = it.get("in_flows", 0) > 0
                it["bidirectional"] = bool(it["has_out"] and it["has_in"])
                it["protos"] = sorted({str(x).lower() for x in (it.get("protos") or [])})
                conv.append(it)
            conv.sort(key=lambda x: x.get("total_bytes", 0), reverse=True)
            entry["conv_peers"] = conv
    except Exception:
        # If anything fails, leave conv_peers unset
        logger.exception("netflow: failed building merged conversations")

    # Build a friendly list of internal responders (local hosts scanned by remote scanners)
    responded_hosts = []
    try:
        # Optional map ip->hostname for local hosts
        local_name_map = {}
        with engine.connect() as conn:
            try:
                # host.ip is stored as text/varchar; avoid calling host() which expects inet
                rows = conn.execute(sql_text("SELECT ip AS ip, hostname FROM host"))
                for r in rows:
                    if getattr(r, "hostname", None):
                        local_name_map[str(r.ip)] = r.hostname
            except Exception:
                logger.exception("netflow: failed mapping local hostnames for responders")
        # Flatten scan_pairs.responders to per-local host summaries
        for local_ip, lst in (scan_pairs.get("responders") or {}).items():
            total_bytes = 0
            total_flows = 0
            peers = []
            for item in lst or []:
                b = int(item.get("bytes", 0) or 0)
                f = int(item.get("flows", 0) or 0)
                total_bytes += b
                total_flows += f
                name = (
                    item.get("remote_hostname")
                    or item.get("remote_subnet_name")
                    or item.get("remote_rdns")
                    or item.get("remote_ip")
                )
                peers.append({
                    "name": name,
                    "bytes": b,
                    "flows": f,
                })
            peers.sort(key=lambda x: x.get("bytes", 0), reverse=True)
            responded_hosts.append({
                "local_ip": local_ip,
                "local_hostname": local_name_map.get(str(local_ip)),
                "total_bytes": total_bytes,
                "total_flows": total_flows,
                "peers": peers,
            })
        # Order hosts by total bytes desc and keep top 10 for display
        responded_hosts.sort(key=lambda x: x.get("total_bytes", 0), reverse=True)
    except Exception:
        logger.exception("netflow: building responded_hosts failed")
        responded_hosts = []

    # Byte pretty-printer
    def human_bytes(n: int) -> str:
        try:
            n = int(n or 0)
        except Exception:
            n = 0
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        f = float(n)
        i = 0
        while f >= 1024.0 and i < len(units) - 1:
            f /= 1024.0
            i += 1
        if i == 0:
            return f"{int(f)} {units[i]}"
        return f"{f:.1f} {units[i]}"

    return templates.TemplateResponse(
        "netflow.html",
        {
            "request": request,
            "minutes": minutes,
            "subnets": subnet_results,
            "edges": edges,
            "title": "NetFlow",
            "human_bytes": human_bytes,
            "scanners": scanners,
            "scan_pairs": scan_pairs,
            "responded_hosts": responded_hosts,
            "rdns_map": rdns_map if 'rdns_map' in locals() else {},
            "rdns_map2": rdns_map2 if 'rdns_map2' in locals() else {},
        },
    )


@app.get("/netflow/flows/download")
def netflow_download(
    request: Request,
    minutes: int = 60,
    local: str = None,
    remote: str = None,
    dir: str = "out",
    fmt: str = "csv",
):
    # if "user" not in request.session:
    #     return RedirectResponse("/login")
    if not str(engine.dialect.name).startswith("postgres"):
        return PlainTextResponse("NetFlow export requires PostgreSQL.", status_code=400)
    if not local or not remote or dir not in ("out", "in", "both"):
        return PlainTextResponse("Missing or invalid parameters.", status_code=400)

    ts_from = datetime.utcnow() - timedelta(minutes=max(1, min(minutes, 24 * 60)))
    # Build and run query
    rows = []
    try:
        with engine.connect() as _raw:
            conn = _raw.execution_options(isolation_level="AUTOCOMMIT")
            if dir == "out":
                where = "host(nf.src_addr) = :local AND host(nf.dst_addr) = :remote"
                params = {"ts_from": ts_from, "local": local, "remote": remote}
            elif dir == "in":
                where = "host(nf.dst_addr) = :local AND host(nf.src_addr) = :remote"
                params = {"ts_from": ts_from, "local": local, "remote": remote}
            else:  # both
                where = "( (host(nf.src_addr) = :local AND host(nf.dst_addr) = :remote) OR (host(nf.dst_addr) = :local AND host(nf.src_addr) = :remote) )"
                params = {"ts_from": ts_from, "local": local, "remote": remote}
            q = sql_text(
                f"""
                SELECT 
                  nf.ts,
                  host(nf.src_addr) AS src_addr,
                  host(nf.dst_addr) AS dst_addr,
                  nf.src_port,
                  nf.dst_port,
                  nf.protocol,
                  nf.input_snmp,
                  nf.output_snmp,
                  nf.in_bytes,
                  nf.out_bytes,
                  nf.in_pkts,
                  nf.out_pkts,
                  nf.exporter,
                  nf.sequence,
                  nf.template_id
                FROM netflow_flows nf
                WHERE nf.ts >= :ts_from AND {where}
                ORDER BY nf.ts DESC
                """
            )
            rows = conn.execute(q, params).fetchall()
    except Exception:
        logger.exception("netflow_download: failed to fetch flows (local=%s remote=%s dir=%s)", local, remote, dir)
        rows = []

    # Serialize
    filename_base = f"flows_{dir}_{local.replace(':','-')}_to_{remote.replace(':','-')}_{minutes}m"
    if (fmt or '').lower() == 'json':
        data = []
        for r in rows:
            data.append({
                "ts": (r.ts.isoformat() if getattr(r, "ts", None) else None),
                "src_addr": getattr(r, "src_addr", None),
                "dst_addr": getattr(r, "dst_addr", None),
                "src_port": getattr(r, "src_port", None),
                "dst_port": getattr(r, "dst_port", None),
                "protocol": getattr(r, "protocol", None),
                "input_snmp": getattr(r, "input_snmp", None),
                "output_snmp": getattr(r, "output_snmp", None),
                "in_bytes": getattr(r, "in_bytes", 0) or 0,
                "out_bytes": getattr(r, "out_bytes", 0) or 0,
                "in_pkts": getattr(r, "in_pkts", 0) or 0,
                "out_pkts": getattr(r, "out_pkts", 0) or 0,
                "exporter": getattr(r, "exporter", None),
                "sequence": getattr(r, "sequence", None),
                "template_id": getattr(r, "template_id", None),
            })
        import json as _json
        payload = _json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        resp = StreamingResponse(iter([payload]), media_type="application/json")
        resp.headers["Content-Disposition"] = f"attachment; filename={filename_base}.json"
        return resp
    else:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ts",
            "src_addr",
            "dst_addr",
            "src_port",
            "dst_port",
            "protocol",
            "input_snmp",
            "output_snmp",
            "in_bytes",
            "out_bytes",
            "in_pkts",
            "out_pkts",
            "exporter",
            "sequence",
            "template_id",
        ])
        for r in rows:
            writer.writerow([
                r.ts.isoformat() if getattr(r, "ts", None) else "",
                getattr(r, "src_addr", ""),
                getattr(r, "dst_addr", ""),
                getattr(r, "src_port", ""),
                getattr(r, "dst_port", ""),
                getattr(r, "protocol", ""),
                getattr(r, "input_snmp", ""),
                getattr(r, "output_snmp", ""),
                getattr(r, "in_bytes", 0) or 0,
                getattr(r, "out_bytes", 0) or 0,
                getattr(r, "in_pkts", 0) or 0,
                getattr(r, "out_pkts", 0) or 0,
                getattr(r, "exporter", ""),
                getattr(r, "sequence", ""),
                getattr(r, "template_id", ""),
            ])
        return _csv_response(f"{filename_base}.csv", output.getvalue())



@app.post("/netflow/clear")
def netflow_clear(request: Request):
    if "user" not in request.session:
        return RedirectResponse("/login")
    try:
        with engine.begin() as conn:
            if str(engine.dialect.name).startswith("postgres"):
                conn.exec_driver_sql("TRUNCATE TABLE netflow_flows")
            else:
                from sqlalchemy import text as sql_text
                conn.execute(sql_text("DELETE FROM netflow_flows"))
    except Exception:
        logger.exception("add_host: failed to auto-attach to subnet for ip=%s", ip)
    return RedirectResponse("/netflow", status_code=302)


@app.post("/subnets/{subnet_id}/scan")
def scan_subnet_now(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Fire-and-forget background scan for this subnet
    def _scan_once():
        try:
            scan_single_subnet_id(subnet_id)
        except Exception:
            logger.exception("scan_subnet_now: scan_single_subnet_id failed (subnet_id=%s)", subnet_id)

    threading.Thread(target=_scan_once, daemon=True).start()
    return RedirectResponse("/", status_code=302)


@app.post("/subnets/{subnet_id}/scan_ports")
def scan_subnet_ports_now(request: Request, subnet_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    # Fire-and-forget: scan ports for all hosts in a subnet
    def _scan_all():
        session = next(get_db())
        try:
            q = session.query(models.Host)
            if subnet_id != 0:
                q = q.filter(models.Host.subnet_id == subnet_id)
            else:
                q = q.filter(models.Host.subnet_id.is_(None))
            ids = [h.id for h in q.all()]
        finally:
            session.close()
        for hid in ids:
            try:
                scan_host_ports_id(hid)
            except Exception:
                logger.exception("scan_subnet_ports_now: scan_host_ports_id failed (host_id=%s)", hid)
    threading.Thread(target=_scan_all, daemon=True).start()
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
            logger.exception("scan_host_ports: scan_host_ports_id failed (host_id=%s)", host_id)
    threading.Thread(target=_scan, daemon=True).start()
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/refresh_mac")
def refresh_mac(request: Request, host_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    def _refresh():
        try:
            refresh_mac_for_host_id(host_id)
        except Exception:
            logger.exception("refresh_mac: refresh_mac_for_host_id failed (host_id=%s)", host_id)
    threading.Thread(target=_refresh, daemon=True).start()
    return RedirectResponse("/", status_code=302)


def _set_tag(host: models.Host, key: str, value: bool):
    try:
        tags = {}
        if host.tags_json:
            tags = json.loads(host.tags_json) or {}
    except Exception:
        tags = {}
    if value:
        tags[key] = True
    else:
        if key in tags:
            del tags[key]
    host.tags_json = json.dumps(tags) if tags else None


@app.post("/hosts/{host_id}/deprecate")
def deprecate_host(request: Request, host_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)
    _set_tag(host, "deprecated", True)
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/undeprecate")
def undeprecate_host(request: Request, host_id: int, db: Session = Depends(get_db)):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)
    _set_tag(host, "deprecated", False)
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
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
# Re-enabled below via explicit edit endpoint when user toggles editing in UI.


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

    # If host has no subnet (appears under 'Other'): always remove host
    # Else: If up -> keep and just remove reserved flag; If down -> remove host
    try:
        if host.subnet_id is None:
            db.query(models.HostOpenPort).filter(models.HostOpenPort.host_id == host.id).delete()
            db.query(models.HostStatus).filter(models.HostStatus.host_id == host.id).delete()
            db.delete(host)
        elif is_up:
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


@app.post("/hosts/{host_id}/mac")
def set_mac(
    request: Request,
    host_id: int = Path(...),
    mac: str = Form(...),
    db: Session = Depends(get_db),
):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)
    import re
    mac = mac.strip()
    if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", mac):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Invalid MAC format (AA:BB:CC:DD:EE:FF)"},
            status_code=400,
        )
    host.mac = mac.lower()
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)


@app.post("/hosts/{host_id}/mac/clear")
def clear_mac(
    request: Request,
    host_id: int = Path(...),
    db: Session = Depends(get_db),
):
    if "user" not in request.session:
        return RedirectResponse("/login")
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        return RedirectResponse("/", status_code=302)
    host.mac = None
    if not commit_with_retry(db):
        hosts = db.query(models.Host).all()
        subnets = db.query(models.Subnet).all()
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "hosts": hosts, "subnets": subnets, "error": "Database busy, please retry."},
            status_code=503,
        )
    return RedirectResponse("/", status_code=302)



from fastapi import Query, Request
from datetime import datetime

@app.get("/api/netflow/conversations")
def api_netflow_conversations(
    request: Request,
    minutes: int = Query(60, ge=1, le=1440),
    db: Session = Depends(get_db)
):
    """
    Returns aggregated NetFlow conversations for the last `minutes` minutes.
    No authentication required.
    Adds first_ts, last_ts, download_url, remote_rdns, and remote_dns per conversation.
    """
    if not str(engine.dialect.name).startswith("postgres"):
        return JSONResponse({"error": "NetFlow analysis requires PostgreSQL."}, status_code=400)

    ts_from = datetime.utcnow() - timedelta(minutes=max(1, min(minutes, 24 * 60)))
    subnets = db.query(models.Subnet).all()
    results = []
    requested_at = datetime.utcnow().isoformat() + "Z"

    try:
        with engine.connect() as _raw:
            conn = _raw.execution_options(isolation_level="AUTOCOMMIT")
            # Build latest ping status per host (map by IP)
            status_map = {}
            try:
                stat_rows = conn.execute(
                    sql_text(
                        """
                        SELECT h.ip AS ip,
                               (
                                  SELECT hs.is_up FROM host_status hs
                                  WHERE hs.host_id = h.id
                                  ORDER BY hs.ts DESC
                                  LIMIT 1
                               ) AS is_up
                        FROM host h
                        """
                    )
                ).fetchall()
                for r in stat_rows:
                    status_map[str(r.ip)] = bool(r.is_up) if r.is_up is not None else None
            except Exception:
                status_map = {}

            subnet_results = []
            for sn in subnets:
                try:
                    out_rows = conn.execute(
                        sql_text(
                            """
                            SELECT 
                              host(nf.src_addr) AS local_ip,
                              lh.hostname AS local_hostname,
                              host(nf.dst_addr) AS remote_ip,
                              rh.hostname AS remote_hostname,
                              SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                              SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                              COUNT(*) AS flows,
                              array_remove(array_agg(DISTINCT nf.protocol), NULL) AS protos,
                              MIN(nf.input_snmp) AS in_if,
                              MIN(nf.output_snmp) AS out_if,
                              sn2.id AS remote_subnet_id,
                              sn2.name AS remote_subnet_name,
                              sn2.cidr AS remote_subnet_cidr,
                              MIN(nf.ts) AS first_ts,
                              MAX(nf.ts) AS last_ts
                            FROM netflow_flows nf
                            LEFT JOIN host lh ON lh.ip = host(nf.src_addr)
                            LEFT JOIN host rh ON rh.ip = host(nf.dst_addr)
                            LEFT JOIN subnet sn2 ON nf.dst_addr << cidr(sn2.cidr)
                            WHERE nf.ts >= :ts_from AND nf.src_addr << cidr(:cidr)
                            GROUP BY host(nf.src_addr), lh.hostname, host(nf.dst_addr), rh.hostname, sn2.id, sn2.name, sn2.cidr
                            ORDER BY bytes DESC
                            LIMIT 25
                            """
                        ),
                        {"ts_from": ts_from, "cidr": sn.cidr},
                    ).fetchall()
                except Exception:
                    out_rows = []
                try:
                    in_rows = conn.execute(
                        sql_text(
                            """
                            SELECT 
                              host(nf.dst_addr) AS local_ip,
                              lh.hostname AS local_hostname,
                              host(nf.src_addr) AS remote_ip,
                              rh.hostname AS remote_hostname,
                              SUM(COALESCE(nf.in_bytes,0) + COALESCE(nf.out_bytes,0)) AS bytes,
                              SUM(COALESCE(nf.in_pkts,0) + COALESCE(nf.out_pkts,0)) AS pkts,
                              COUNT(*) AS flows,
                              array_remove(array_agg(DISTINCT nf.protocol), NULL) AS protos,
                              MIN(nf.input_snmp) AS in_if,
                              MIN(nf.output_snmp) AS out_if,
                              sn2.id AS remote_subnet_id,
                              sn2.name AS remote_subnet_name,
                              sn2.cidr AS remote_subnet_cidr,
                              MIN(nf.ts) AS first_ts,
                              MAX(nf.ts) AS last_ts
                            FROM netflow_flows nf
                            LEFT JOIN host lh ON lh.ip = host(nf.dst_addr)
                            LEFT JOIN host rh ON rh.ip = host(nf.src_addr)
                            LEFT JOIN subnet sn2 ON nf.src_addr << cidr(sn2.cidr)
                            WHERE nf.ts >= :ts_from AND nf.dst_addr << cidr(:cidr)
                            GROUP BY host(nf.dst_addr), lh.hostname, host(nf.src_addr), rh.hostname, sn2.id, sn2.name, sn2.cidr
                            ORDER BY bytes DESC
                            LIMIT 25
                            """
                        ),
                        {"ts_from": ts_from, "cidr": sn.cidr},
                    ).fetchall()
                except Exception:
                    in_rows = []

                def _pack(rows, direction: str):
                    items = []
                    for r in rows:
                        items.append(
                            {
                                "local_ip": r.local_ip,
                                "local_hostname": r.local_hostname,
                                "local_is_up": status_map.get(str(r.local_ip)),
                                "remote_ip": r.remote_ip,
                                "remote_hostname": r.remote_hostname,
                                "remote_is_up": status_map.get(str(r.remote_ip)),
                                "bytes": int(r.bytes or 0),
                                "pkts": int(r.pkts or 0),
                                "flows": int(r.flows or 0),
                                "protos": [p for p in (r.protos or []) if p is not None],
                                "remote_subnet_id": r.remote_subnet_id,
                                "remote_subnet_name": r.remote_subnet_name,
                                "remote_subnet_cidr": r.remote_subnet_cidr,
                                "direction": direction,
                                "in_if": r.in_if,
                                "out_if": r.out_if,
                                "first_ts": r.first_ts.isoformat() + "Z" if r.first_ts else None,
                                "last_ts": r.last_ts.isoformat() + "Z" if r.last_ts else None,
                            }
                        )
                    return items

                subnet_results.append(
                    {
                        "subnet": {
                            "id": sn.id,
                            "name": sn.name,
                            "cidr": sn.cidr,
                        },
                        "out_peers": _pack(out_rows, "out"),
                        "in_peers": _pack(in_rows, "in"),
                    }
                )

            # Merge conversations per subnet (combine Outgoing/Incoming by pair)
            for entry in subnet_results:
                pairs = {}
                for p in (entry.get("out_peers") or []):
                    key = (p.get("local_ip"), p.get("remote_ip"))
                    it = pairs.setdefault(
                        key,
                        {
                            "subnet_id": entry["subnet"]["id"],
                            "subnet_name": entry["subnet"]["name"],
                            "subnet_cidr": entry["subnet"]["cidr"],
                            "local_ip": p.get("local_ip"),
                            "local_hostname": p.get("local_hostname"),
                            "remote_ip": p.get("remote_ip"),
                            "remote_hostname": p.get("remote_hostname"),
                            "remote_subnet_id": p.get("remote_subnet_id"),
                            "remote_subnet_name": p.get("remote_subnet_name"),
                            "remote_subnet_cidr": p.get("remote_subnet_cidr"),
                            "protos": set(),
                            "out_bytes": 0,
                            "out_pkts": 0,
                            "out_flows": 0,
                            "in_bytes": 0,
                            "in_pkts": 0,
                            "in_flows": 0,
                            "local_is_up": p.get("local_is_up"),
                            "remote_is_up": p.get("remote_is_up"),
                            "first_ts": p.get("first_ts"),
                            "last_ts": p.get("last_ts"),
                        },
                    )
                    it["protos"].update(p.get("protos") or [])
                    it["out_bytes"] += int(p.get("bytes", 0) or 0)
                    it["out_pkts"] += int(p.get("pkts", 0) or 0)
                    it["out_flows"] += int(p.get("flows", 0) or 0)
                    # Set/merge timestamps
                    if p.get("first_ts"):
                        if not it.get("first_ts") or p["first_ts"] < it["first_ts"]:
                            it["first_ts"] = p["first_ts"]
                    if p.get("last_ts"):
                        if not it.get("last_ts") or p["last_ts"] > it["last_ts"]:
                            it["last_ts"] = p["last_ts"]
                for p in (entry.get("in_peers") or []):
                    key = (p.get("local_ip"), p.get("remote_ip"))
                    it = pairs.setdefault(
                        key,
                        {
                            "subnet_id": entry["subnet"]["id"],
                            "subnet_name": entry["subnet"]["name"],
                            "subnet_cidr": entry["subnet"]["cidr"],
                            "local_ip": p.get("local_ip"),
                            "local_hostname": p.get("local_hostname"),
                            "remote_ip": p.get("remote_ip"),
                            "remote_hostname": p.get("remote_hostname"),
                            "remote_subnet_id": p.get("remote_subnet_id"),
                            "remote_subnet_name": p.get("remote_subnet_name"),
                            "remote_subnet_cidr": p.get("remote_subnet_cidr"),
                            "protos": set(),
                            "out_bytes": 0,
                            "out_pkts": 0,
                            "out_flows": 0,
                            "in_bytes": 0,
                            "in_pkts": 0,
                            "in_flows": 0,
                            "local_is_up": p.get("local_is_up"),
                            "remote_is_up": p.get("remote_is_up"),
                            "first_ts": p.get("first_ts"),
                            "last_ts": p.get("last_ts"),
                        },
                    )
                    it["protos"].update(p.get("protos") or [])
                    it["in_bytes"] += int(p.get("bytes", 0) or 0)
                    it["in_pkts"] += int(p.get("pkts", 0) or 0)
                    it["in_flows"] += int(p.get("flows", 0) or 0)
                    # Set/merge timestamps
                    if p.get("first_ts"):
                        if not it.get("first_ts") or p["first_ts"] < it["first_ts"]:
                            it["first_ts"] = p["first_ts"]
                    if p.get("last_ts"):
                        if not it.get("last_ts") or p["last_ts"] > it["last_ts"]:
                            it["last_ts"] = p["last_ts"]
                for it in pairs.values():
                    it["total_bytes"] = int(it.get("out_bytes", 0)) + int(it.get("in_bytes", 0))
                    it["has_out"] = it.get("out_flows", 0) > 0
                    it["has_in"] = it.get("in_flows", 0) > 0
                    it["bidirectional"] = bool(it["has_out"] and it["has_in"])
                    it["protos"] = sorted({str(x).lower() for x in (it.get("protos") or [])})
                    # Add download_url for this conversation (now using dir=both)
                    base_url = str(request.base_url).rstrip("/")
                    local_ip = it.get("local_ip")
                    remote_ip = it.get("remote_ip")
                    it["download_url"] = (
                        f"{base_url}/netflow/flows/download?minutes={minutes}&local={local_ip}&remote={remote_ip}&dir=both&fmt=json"
                    )       
                    results.    append(it)
    except Exception as e:  
        return JSONResponse(    {"error": f"Failed to aggregate netflow: {str(e)}"}, status_code=500)
    q
    # --- ENRICH WITH REVERSE DNS AND DNS QUERY DATA ---
    # Collect all unique remote IPs
    remote_ips = set()
    for conv in results:
        ip = conv.get("remote_ip")
        if ip:
            remote_ips.add(ip)

    # Query rdns_cache for reverse DNS
    rdns_map = {}
    if remote_ips:
        placeholders = ",".join([f":ip{i}" for i in range(len(remote_ips))])
        params = {f"ip{i}": ip for i, ip in enumerate(remote_ips)}
        with engine.connect() as conn:
            try:
                rows = conn.execute(
                    sql_text(f"SELECT host(ip::inet) AS ip, hostname FROM rdns_cache WHERE host(ip::inet) IN ({placeholders})"),
                    params,
                ).fetchall()
                rdns_map = {str(r.ip): r.hostname for r in rows if r.hostname}
            except Exception:
                rdns_map = {}

    # Query dnslog for last DNS query for each remote IP (if you have this table)
    dns_map = {}
    if remote_ips:
        placeholders = ",".join([f":ip{i}" for i in range(len(remote_ips))])
        params = {f"ip{i}": ip for i, ip in enumerate(remote_ips)}
        with engine.connect() as conn:
            try:
                rows = conn.execute(
                    sql_text(f"""
                        SELECT DISTINCT ON (answer) answer AS ip, qname
                        FROM dnslog
                        WHERE answer IN ({placeholders})
                        ORDER BY answer, ts DESC
                    """),
                    params,
                ).fetchall()
                dns_map = {str(r.ip): r.qname for r in rows if r.qname}
            except Exception:
                dns_map = {}

    # Attach to each conversation
    for conv in results:
        ip = conv.get("remote_ip")
        conv["remote_rdns"] = rdns_map.get(ip)
        conv["remote_dns"] = dns_map.get(ip)

    return JSONResponse({
        "requested_at": requested_at,
        "interval_minutes": minutes,
        "conversations": results
    })
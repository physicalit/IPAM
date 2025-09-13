# Simple IPAM + Live Pinger (Minimal Stack)

## Goal

A lightweight IP Address Management tool with live ICMP status and hourly **Nmap** port checks, a clean responsive UI, and **local SQLite** storage. Prioritize clarity: quickly see which hosts are alive and what services are open. Hide unused IPs by default (collapsed/stacked like phpIPAM, but cleaner).

## Stack (minimal)

* **Backend:** Python **FastAPI** (REST + server-rendered pages via Jinja2)
* **DB:** **SQLite** (via SQLAlchemy)
* **Jobs/Scheduling:** **APScheduler** in-process (no Redis/Celery)
* **Scanning:** `ping3` for ICMP; **Nmap** via `python-nmap` (or subprocess)
* **UI:** **Bootstrap 5** (or Foundation) + small vanilla JS; optional inline SVG for tiny charts
* **Auth:** Simple session (Starlette sessions) + password hash (bcrypt)

> No React, no Redis, no TimescaleDB, no Docker required.

## Core Features

1. **Subnet management**

   * CRUD subnets (IPv4/IPv6), CIDR validation, CSV import.
   * Auto-enumerate hosts only when needed (don’t store every IP row).
2. **Host tracking**

   * For a subnet, show **only used/alive/annotated** IPs; collapse contiguous unused ranges (“+ 238 unused…” with expand-on-click).
   * Fields: IP, hostname, description, tags, last seen, latency, notes.
3. **Discovery**

   * **ICMP sweep** per subnet (configurable list); mark `is_up`, `latency_ms`, `last_seen_at`.
   * **Hourly Nmap** per alive host (default every 60 min, jittered). Store open ports & service names.
   * Optional **PTR lookup** (cache result, editable override).
4. **Status model & history**

   * Tables:

     * `subnet(id, cidr, name, notes)`
     * `host(id, ip, subnet_id, hostname, desc, tags_json, first_seen_at, last_seen_at)`
     * `host_status(id, host_id, ts, is_up, latency_ms)`  *(append-only)*
     * `host_open_port(id, host_id, ts, port, proto, service, state)` *(current snapshot flagged)*
   * Maintain `host_current` view (latest status per host) for fast UI.
   * Simple roll-up task (daily) to prune old pings (e.g., keep 7 days raw, then 1 sample/hour).
5. **UI (Bootstrap/Foundation)**

   * **Global Dashboard:** “Alive now”, filters (subnet, tag, service), quick search.
   * **Subnet View:** Table of hosts (alive first), status pill (Up/Down/Unknown), hostname, last seen, latency. **Collapse unused IP ranges** with expand chips.
   * **Host Drawer:** Open from row; shows open ports (from last Nmap), change events, uptime % (24h/7d), small inline SVG sparkline. Inline edit for hostname/desc/tags.
   * Mobile-friendly, keyboard nav, sticky filters.
6. **API**

   * REST endpoints for subnets, hosts, status history, ports, CSV import/export.
   * Auto OpenAPI docs at `/docs`.
7. **Security**

   * Login page and sessions.
   * Note: CSRF protection and rate limiting are planned but not implemented yet.

## Scanning Behavior

* **ICMP sweep schedule:** every 60s (per subnet) *or* configurable (e.g., 1–5 min). Concurrency cap.
* **Nmap ports:** hourly per **alive** host; default args: `-Pn -T3 --top-1000-ports -sS -sV` (tunable).
* Add **random jitter** to avoid synchronized storms.
* Manual “Scan now” buttons (debounced / rate limited).
* Local network ARP scan optional (`scapy`) when enabled.

## UX Details (important)

* **Don’t render all IPs.** Show alive/used first; compress gaps with a single row like “10.0.0.15–10.0.0.200 (186 unused)”.
* **Color, not clutter:** small status pills; port chips (e.g., `80/http`, `443/https`, `22/ssh`).
* **Quick cues:** latency badge, last change tooltip (“down 12m ago”).
* **Accessibility:** high-contrast mode toggle; semantic HTML.

## Config

* `.env`:

  * `DATABASE_URL=postgresql+psycopg2://user:password@db-host:5432/ipam` (or `sqlite:///./ipam.db`)
  * `SCAN_ICMP_INTERVAL_SECONDS=60`
  * `SCAN_NMAP_INTERVAL_MINUTES=10`
  * `SCAN_SWEEP_INTERVAL_MINUTES=5`
  * `PING_WORKERS=64`
  * `ENABLE_NMAP_SCHEDULER=1` (default on; set to 0 to disable)
  * `NMAP_ARGS="-Pn -T3 --top-ports 1000 -sT -sV"` (use `-sS` only if running as root)
  * `PTR_LOOKUP_ENABLED=true`
* APScheduler jobs registered at startup; persisted next-run times optional via SQLite.

## Deliverables

* `backend/` (FastAPI app, models, routers, schedulers, scanners)
* `templates/` (Jinja2 pages, Bootstrap or Foundation)
* `static/` (CSS overrides, minimal JS)
* `tests/` (e2e: add /24 → sweep → simulate host flip → confirm history & open ports render)
* **Sample data** + CSV import example
* **README** with setup, permissions needed for raw sockets/Nmap, and config notes

## Nice-to-haves (still minimal)

* CSV/phpIPAM import
* SNMP `sysName` fallback for hostname (per-host toggle)
* Simple webhooks on down/up (POST only)

## Quickstart

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Or with Docker (Postgres):

```bash
docker-compose up --build
```

Default credentials: `admin` / `admin` (override with `ADMIN_PASSWORD`).

If you create a `.env`, the app will auto-load it locally. Docker Compose defaults to the bundled Postgres service if `DATABASE_URL` is not set. To point at a remote DB, set `DATABASE_URL` in `.env` or your environment before `docker-compose up`.

Notes:

- Docker compose grants `NET_RAW` capability to allow ICMP (ping3) without running as privileged. If you remove this, live pings will always show Unknown/Down.
- The image installs the `nmap` binary so hourly port scans can run. Disable scheduler with `DISABLE_SCHEDULER=1` for local dev.
- Added a Subnets table to the dashboard so adding a CIDR is immediately visible, with server-side CIDR validation and deduplication.
- Database now runs on Postgres in Docker. The app will auto-create tables at startup. For local dev without Docker, set `DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/dbname`.

## CI/CD (Gitea Actions)

This repo includes a Gitea Actions pipeline at `.gitea/workflows/ci.yml` that:

- Runs Python tests on every push/PR
- Builds a Docker image on runners labeled `infra` (no push by default)

Runner requirements:

- Runner labeled: `infra`
- Docker engine (with Buildx) available to the runner

To push to a registry, you can extend the workflow with a login/push step or create a release workflow tailored to your public registry (Docker Hub, GHCR, or Gitea registry).

Environment defaults (can be overridden in Actions or deployment):

- `ENABLE_NMAP_SCHEDULER=1` (automatic port scans enabled)
- `SCAN_NMAP_INTERVAL_MINUTES=10`
- `NMAP_ARGS="-Pn -T3 --top-ports 1000 -sT -sV"`

## NetFlow Collector

The stack includes a NetFlow v9 collector that listens on UDP/2055, parses exporter templates, and persists flows into Postgres (`netflow_flows`). The `/netflow` page uses these rows to render subnet-to-subnet maps and top talkers. You can enable short hex dumps for debugging template/data sets.

Run with Docker Compose:

```bash
docker-compose up --build collector
```

This starts a UDP listener on `0.0.0.0:2055/udp` that logs lines like:

```
pkt exporter=192.168.88.1 v=9 len=1392 count=24 seq=247 srcid=0 sets=256,256,...
```

Tuning via environment variables (service `collector` in `docker-compose.yml`):

- `NETFLOW_BIND_HOST` default `0.0.0.0`
- `NETFLOW_BIND_PORT` default `2055`
- `LOG_LEVEL=DEBUG` to see all lines
- `DUMP_HEX=1` to include a short hex dump, `DUMP_HEX_LEN` to adjust bytes
- `NETFLOW_LOG_FILE=/path/to/collector.log` to also write a full, untruncated log to a file. When set, hex dumps are written twice: a short one to the console and a full one to the file.
- `NETFLOW_INSERT_BATCH` batch size for inserts (default 200)
- `NETFLOW_FLUSH_INTERVAL_MS` time-based flush for low volume (default 1000)

Notes:

- The collector creates `netflow_flows` on first run. On Postgres, the schema uses `inet` and `timestamptz`; SQLite fallback is available for dev only (the `/netflow` page requires Postgres).
- Timestamps are derived from `LAST_SWITCHED` (ms since boot) + exporter header. If missing, export time is used.
- The `/netflow` page aggregates internal↔internal and also internal↔External edges so you can see per-subnet Internet traffic.

Quick sanity checks:

```bash
docker compose exec db psql -U ipam -d ipam -c "select count(*) as rows, min(ts) as oldest, max(ts) as newest from netflow_flows;"
docker compose logs -f collector | rg "inserted|pkt exporter"
```

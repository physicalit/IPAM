# Simple IPAM + Live Pinger (Minimal Stack)

## Goal

A lightweight IP Address Management tool with live ICMP status and hourly **Nmap** port checks, a clean responsive UI, and **local SQLite** storage. Prioritize clarity: quickly see which hosts are alive and what services are open. Hide unused IPs by default (collapsed/stacked like phpIPAM, but cleaner).

## Stack (minimal)

* **Backend:** Python **FastAPI** (REST + server-rendered pages via Jinja2)
* **DB:** **SQLite** (via SQLAlchemy)
* **Jobs/Scheduling:** **APScheduler** in-process (no Redis/Celery)
* **Scanning:** `icmplib` (or `ping3`) for ICMP; **Nmap** via `python-nmap` (or subprocess)
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

   * Login page, sessions, CSRF, rate limit on manual scan triggers.

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

  * `DATABASE_URL=sqlite:///./ipam.db`
  * `SCAN_ICMP_INTERVAL_SECONDS=60`
  * `SCAN_NMAP_INTERVAL_MINUTES=60`
  * `NMAP_ARGS="-Pn -T3 --top-1000-ports -sS -sV"`
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

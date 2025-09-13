import os
import socket
import struct
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Tuple, Optional

from .database import engine


log = logging.getLogger("ipam.netflow.collector")
if not log.handlers:
    # Console handler (concise)
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    class _DropHeavyFilter(logging.Filter):
        # Drop records flagged as heavy from console to reduce noise
        def filter(self, record: logging.LogRecord) -> bool:
            return not getattr(record, "heavy", False)

    _h.addFilter(_DropHeavyFilter())
    log.addHandler(_h)

    # Optional file handler (full, untruncated)
    _log_file = os.environ.get("NETFLOW_LOG_FILE")
    if _log_file:
        _fh = logging.FileHandler(_log_file, encoding="utf-8")
        _fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        _fh.setLevel(logging.DEBUG)
        log.addHandler(_fh)

log.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper()))


# --- DB bootstrap -----------------------------------------------------------


def _ensure_tables():
    """Create the netflow_flows table if it doesn't exist.

    - Uses Postgres types (inet, timestamptz) when available.
    - Falls back to generic types on other engines (SQLite dev only).
    """
    dialect = str(engine.dialect.name)
    with engine.begin() as conn:
        if dialect.startswith("postgres"):
            conn.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS netflow_flows (
                  id BIGSERIAL PRIMARY KEY,
                  ts TIMESTAMPTZ NOT NULL,
                  src_addr INET NOT NULL,
                  dst_addr INET NOT NULL,
                  src_port INTEGER,
                  dst_port INTEGER,
                  protocol TEXT,
                  input_snmp INTEGER,
                  output_snmp INTEGER,
                  in_bytes BIGINT,
                  out_bytes BIGINT,
                  in_pkts BIGINT,
                  out_pkts BIGINT,
                  exporter TEXT,
                  sequence BIGINT,
                  template_id INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_netflow_ts ON netflow_flows (ts DESC);
                CREATE INDEX IF NOT EXISTS idx_netflow_src ON netflow_flows (src_addr);
                CREATE INDEX IF NOT EXISTS idx_netflow_dst ON netflow_flows (dst_addr);
                """
            )
            # Backfill missing columns and fix incompatible types on existing deployments
            try:
                rows = conn.exec_driver_sql(
                    "SELECT column_name, data_type, udt_name FROM information_schema.columns WHERE table_name='netflow_flows'"
                ).fetchall()
                existing = {r[0] for r in rows}
                types = {r[0]: (str(r[1] or "").lower(), str(r[2] or "").lower()) for r in rows}
                needed = {
                    "ts": "TIMESTAMPTZ",
                    "src_addr": "INET",
                    "dst_addr": "INET",
                    "src_port": "INTEGER",
                    "dst_port": "INTEGER",
                    "protocol": "TEXT",
                    "input_snmp": "INTEGER",
                    "output_snmp": "INTEGER",
                    "in_bytes": "BIGINT",
                    "out_bytes": "BIGINT",
                    "in_pkts": "BIGINT",
                    "out_pkts": "BIGINT",
                    "exporter": "TEXT",
                    "sequence": "BIGINT",
                    "template_id": "INTEGER",
                }
                # Add any missing columns
                for col, typ in needed.items():
                    if col not in existing:
                        conn.exec_driver_sql(f"ALTER TABLE netflow_flows ADD COLUMN {col} {typ}")
                # Migrate protocol to TEXT if it was created as a number type
                if "protocol" in existing:
                    dt, udt = types.get("protocol", ("", ""))
                    # information_schema.data_type is 'text' for TEXT; smallint/integer show as their names
                    if dt not in ("text", "character varying", "character"):
                        try:
                            conn.exec_driver_sql(
                                "ALTER TABLE netflow_flows ALTER COLUMN protocol TYPE TEXT USING protocol::text"
                            )
                            # Normalize common numeric protocol values to names for readability
                            conn.exec_driver_sql(
                                "UPDATE netflow_flows SET protocol = CASE protocol "
                                "WHEN '6' THEN 'tcp' "
                                "WHEN '17' THEN 'udp' "
                                "WHEN '1' THEN 'icmp' "
                                "WHEN '58' THEN 'icmpv6' "
                                "WHEN '47' THEN 'gre' "
                                "ELSE protocol END "
                                "WHERE protocol ~ '^[0-9]+$'"
                            )
                            log.info("migrated netflow_flows.protocol to TEXT and normalized values")
                        except Exception as mig_e:
                            log.warning("protocol type migration skipped: %s", mig_e)
            except Exception as e:
                log.warning("schema check failed: %s", e)
            log.debug("ensured netflow_flows table (postgres)")
        else:
            # Dev fallback for SQLite – not used by /netflow page
            conn.exec_driver_sql(
                """
                CREATE TABLE IF NOT EXISTS netflow_flows (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ts TEXT NOT NULL,
                  src_addr TEXT NOT NULL,
                  dst_addr TEXT NOT NULL,
                  src_port INTEGER,
                  dst_port INTEGER,
                  protocol TEXT,
                  input_snmp INTEGER,
                  output_snmp INTEGER,
                  in_bytes INTEGER,
                  out_bytes INTEGER,
                  in_pkts INTEGER,
                  out_pkts INTEGER,
                  exporter TEXT,
                  sequence INTEGER,
                  template_id INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_netflow_ts ON netflow_flows (ts DESC);
                CREATE INDEX IF NOT EXISTS idx_netflow_src ON netflow_flows (src_addr);
                CREATE INDEX IF NOT EXISTS idx_netflow_dst ON netflow_flows (dst_addr);
                """
            )
            log.debug("ensured netflow_flows table (sqlite)")


# --- NetFlow v9 parser ------------------------------------------------------


"""NetFlow v9 parser and collector.

Internal note: We keep field IDs inline in the parser for speed and to avoid
indirection. If you need a reference, see RFC 3954 or your exporter docs.
"""


def _proto_to_name(p: int) -> str:
    if p == 6:
        return "tcp"
    if p == 17:
        return "udp"
    if p == 1:
        return "icmp"
    # A few extras
    if p == 58:
        return "icmpv6"
    if p == 47:
        return "gre"
    return str(p)


class TemplateSpec:
    __slots__ = ("template_id", "fields", "rec_len")

    def __init__(self, template_id: int, fields: List[Tuple[int, int]]):
        self.template_id = template_id
        self.fields = fields  # list of (type_id, length)
        self.rec_len = sum(l for _, l in fields)


class TemplateCache:
    """Caches v9 templates per exporter (ip, source_id)."""

    def __init__(self):
        self._cache: Dict[Tuple[str, int, int], TemplateSpec] = {}

    def put(self, exporter_ip: str, source_id: int, spec: TemplateSpec):
        self._cache[(exporter_ip, source_id, spec.template_id)] = spec
        log.debug(
            "template cached exporter=%s srcid=%s tid=%s fields=%s len=%s",
            exporter_ip,
            source_id,
            spec.template_id,
            [t for t, _ in spec.fields],
            spec.rec_len,
        )

    def get(self, exporter_ip: str, source_id: int, template_id: int) -> Optional[TemplateSpec]:
        return self._cache.get((exporter_ip, source_id, template_id))


def _read_u(data: bytes) -> int:
    # Interpret big-endian unsigned integer from 1,2,4,8 bytes
    l = len(data)
    if l == 1:
        return data[0]
    if l == 2:
        return struct.unpack("!H", data)[0]
    if l == 4:
        return struct.unpack("!I", data)[0]
    if l == 8:
        return struct.unpack("!Q", data)[0]
    # Fallback: pad to 8
    val = 0
    for b in data:
        val = (val << 8) | b
    return val


def _read_ipv4(data: bytes) -> str:
    return ".".join(str(b) for b in data[:4])


def _read_ipv6(data: bytes) -> str:
    # Text form; inet in Postgres accepts this
    parts = struct.unpack("!8H", data[:16])
    return ":".join(f"{p:x}" for p in parts)


def _parse_v9_packet(data: bytes, exporter_ip: str, tcache: TemplateCache) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Parse a NetFlow v9 packet into flow dicts.

    Returns (flows, meta) where meta contains header fields.
    """
    flows: List[Dict[str, Any]] = []
    if len(data) < 20:
        return flows, {}
    v, count, sys_uptime_ms, export_sec, seq, source_id = struct.unpack("!HHIIII", data[:20])
    if v != 9:
        return flows, {"version": v}
    export_time = datetime.fromtimestamp(export_sec, tz=timezone.utc)
    off = 20
    end = len(data)
    while off + 4 <= end:
        set_id, set_len = struct.unpack("!HH", data[off:off + 4])
        if set_len <= 4 or off + set_len > end:
            break
        body = data[off + 4: off + set_len]
        if set_id == 0:  # Template FlowSet
            pos = 0
            while pos + 4 <= len(body):
                template_id, field_count = struct.unpack("!HH", body[pos:pos + 4])
                pos += 4
                fields: List[Tuple[int, int]] = []
                for _ in range(field_count):
                    if pos + 4 > len(body):
                        break
                    ftype, flen = struct.unpack("!HH", body[pos:pos + 4])
                    pos += 4
                    fields.append((ftype, flen))
                if fields:
                    tcache.put(exporter_ip, source_id, TemplateSpec(template_id, fields))
        elif set_id == 1:
            # Options template – ignore for now
            pass
        elif set_id >= 256:
            spec = tcache.get(exporter_ip, source_id, set_id)
            if not spec or spec.rec_len <= 0:
                log.debug(
                    "data set skipped: missing template exporter=%s srcid=%s tid=%s",
                    exporter_ip,
                    source_id,
                    set_id,
                )
                off += set_len
                continue
            pos = 0
            # Each record has fixed length = sum(field lengths)
            rec_len = spec.rec_len
            while pos + rec_len <= len(body):
                rec = body[pos:pos + rec_len]
                pos += rec_len
                out: Dict[str, Any] = {
                    "exporter": exporter_ip,
                    "sequence": seq,
                    "template_id": set_id,
                    # Defaults
                    "src_port": None,
                    "dst_port": None,
                    "protocol": None,
                    "input_snmp": None,
                    "output_snmp": None,
                    "in_bytes": None,
                    "out_bytes": None,
                    "in_pkts": None,
                    "out_pkts": None,
                }
                # Walk fields
                rpos = 0
                first_switched = None
                last_switched = None
                proto_num = None
                for ftype, flen in spec.fields:
                    fdata = rec[rpos:rpos + flen]
                    rpos += flen
                    if ftype == 8 and flen >= 4:  # IPV4_SRC_ADDR
                        out["src_addr"] = _read_ipv4(fdata)
                    elif ftype == 12 and flen >= 4:  # IPV4_DST_ADDR
                        out["dst_addr"] = _read_ipv4(fdata)
                    elif ftype == 27 and flen >= 16:  # IPV6_SRC_ADDR
                        out["src_addr"] = _read_ipv6(fdata)
                    elif ftype == 28 and flen >= 16:  # IPV6_DST_ADDR
                        out["dst_addr"] = _read_ipv6(fdata)
                    elif ftype == 7:  # L4_SRC_PORT
                        out["src_port"] = _read_u(fdata)
                    elif ftype == 11:  # L4_DST_PORT
                        out["dst_port"] = _read_u(fdata)
                    elif ftype == 10:  # INPUT_SNMP
                        out["input_snmp"] = _read_u(fdata)
                    elif ftype == 14:  # OUTPUT_SNMP
                        out["output_snmp"] = _read_u(fdata)
                    elif ftype == 1:  # IN_BYTES
                        out["in_bytes"] = _read_u(fdata)
                    elif ftype == 2:  # IN_PKTS
                        out["in_pkts"] = _read_u(fdata)
                    elif ftype == 4:  # PROTOCOL
                        proto_num = _read_u(fdata)
                    elif ftype == 21:  # LAST_SWITCHED (ms since boot)
                        last_switched = _read_u(fdata)
                    elif ftype == 22:  # FIRST_SWITCHED (ms since boot)
                        first_switched = _read_u(fdata)
                    elif ftype == 61:  # direction
                        out["direction"] = _read_u(fdata)
                    else:
                        # Ignore unneeded fields
                        pass
                # Timestamp: use LAST_SWITCHED if present, else export_time
                ts = export_time
                try:
                    if last_switched is not None:
                        delta_ms = int(sys_uptime_ms) - int(last_switched)
                        # exporter uptime is ahead of flow timestamp
                        ts = export_time - timedelta(milliseconds=max(0, delta_ms))
                except Exception:
                    ts = export_time
                out["ts"] = ts
                if proto_num is not None:
                    out["protocol"] = _proto_to_name(proto_num)
                # Store only records with both addresses
                if out.get("src_addr") and out.get("dst_addr"):
                    flows.append(out)
        else:
            # Unknown set id – skip
            pass
        off += set_len
    meta = {
        "version": v,
        "count": int(count),
        "export_time": export_time,
        "sequence": int(seq),
        "source_id": int(source_id),
    }
    return flows, meta


# --- Hex dump (optional for debugging) --------------------------------------


def _hexdump(data: bytes, max_len: int = 128, width: int = 16) -> str:
    # If max_len <= 0, do not truncate
    if max_len and max_len > 0:
        data = data[:max_len]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)


# --- Collector loop ---------------------------------------------------------


def run():
    _ensure_tables()
    bind_host = os.environ.get("NETFLOW_BIND_HOST", "0.0.0.0")
    bind_port = int(os.environ.get("NETFLOW_BIND_PORT", "2055"))
    dump_hex = os.environ.get("DUMP_HEX", "0") == "1"
    dump_len = int(os.environ.get("DUMP_HEX_LEN", "128"))
    batch_size = int(os.environ.get("NETFLOW_INSERT_BATCH", "200"))
    flush_interval_ms = int(os.environ.get("NETFLOW_FLUSH_INTERVAL_MS", "1000"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    dialect = str(engine.dialect.name)
    log.info(
        "NetFlow v9 collector listening on %s:%s/udp (dialect=%s, batch=%d, flush_ms=%d)",
        bind_host,
        bind_port,
        dialect,
        batch_size,
        flush_interval_ms,
    )

    tcache = TemplateCache()

    def _insert_rows(rows: List[Dict[str, Any]]) -> int:
        if not rows:
            return 0
        # Build SQL tailored for driver paramstyle to avoid placeholder issues
        if dialect.startswith("postgres"):
            # psycopg2 uses pyformat (e.g. %(name)s)
            sql = (
                "INSERT INTO netflow_flows (ts, src_addr, dst_addr, src_port, dst_port, protocol, input_snmp, output_snmp, in_bytes, out_bytes, in_pkts, out_pkts, exporter, sequence, template_id) "
                "VALUES (%(ts)s, %(src_addr)s, %(dst_addr)s, %(src_port)s, %(dst_port)s, %(protocol)s, %(input_snmp)s, %(output_snmp)s, %(in_bytes)s, %(out_bytes)s, %(in_pkts)s, %(out_pkts)s, %(exporter)s, %(sequence)s, %(template_id)s)"
            )
        else:
            # Use SQLAlchemy text with named binds for other dialects
            sql = (
                "INSERT INTO netflow_flows (ts, src_addr, dst_addr, src_port, dst_port, protocol, input_snmp, output_snmp, in_bytes, out_bytes, in_pkts, out_pkts, exporter, sequence, template_id) "
                "VALUES (:ts, :src_addr, :dst_addr, :src_port, :dst_port, :protocol, :input_snmp, :output_snmp, :in_bytes, :out_bytes, :in_pkts, :out_pkts, :exporter, :sequence, :template_id)"
            )
        # Normalize rows: ensure required keys and simple types
        to_ins: List[Dict[str, Any]] = []
        for r in rows:
            to_ins.append(
                {
                    "ts": r.get("ts", datetime.utcnow()),
                    "src_addr": r.get("src_addr"),
                    "dst_addr": r.get("dst_addr"),
                    "src_port": r.get("src_port"),
                    "dst_port": r.get("dst_port"),
                    "protocol": r.get("protocol"),
                    "input_snmp": r.get("input_snmp"),
                    "output_snmp": r.get("output_snmp"),
                    "in_bytes": r.get("in_bytes"),
                    "out_bytes": r.get("out_bytes"),
                    "in_pkts": r.get("in_pkts"),
                    "out_pkts": r.get("out_pkts"),
                    "exporter": r.get("exporter"),
                    "sequence": r.get("sequence"),
                    "template_id": r.get("template_id"),
                }
            )
        try:
            from sqlalchemy import text as sql_text
            with engine.begin() as conn:
                if dialect.startswith("postgres"):
                    # Use driver-level executemany with pyformat params
                    conn.exec_driver_sql(sql, to_ins)
                else:
                    conn.execute(sql_text(sql), to_ins)
            return len(to_ins)
        except Exception as e:
            # Log a compact sample row for troubleshooting
            sample = {k: to_ins[0].get(k) for k in ("ts","src_addr","dst_addr","src_port","dst_port","protocol","in_bytes","in_pkts")} if to_ins else {}
            log.error("insert failed (%d rows): %s; sample=%s", len(to_ins), e, sample)
            return 0

    pending: List[Dict[str, Any]] = []
    last_flush = datetime.now(tz=timezone.utc)

    while True:
        data, addr = sock.recvfrom(65535)
        exporter_ip, exporter_port = addr
        if not data:
            continue
        try:
            # Header peek
            if len(data) >= 20:
                v = struct.unpack("!H", data[:2])[0]
            else:
                v = 0
            if v == 9:
                flows, meta = _parse_v9_packet(data, exporter_ip, tcache)
                if flows:
                    pending.extend(flows)
                # Always log a concise per-packet summary
                sets_preview = []
                off = 20
                while off + 4 <= len(data) and len(sets_preview) < 10:
                    sid, slen = struct.unpack("!HH", data[off:off + 4])
                    sets_preview.append(str(int(sid)))
                    if slen <= 0:
                        break
                    off += slen
                log.info(
                    "pkt exporter=%s v=9 len=%d count=%s seq=%s srcid=%s sets=%s parsed_flows=%d pending=%d",
                    exporter_ip,
                    len(data),
                    meta.get("count"),
                    meta.get("sequence"),
                    meta.get("source_id"),
                    ",".join(sets_preview) if sets_preview else None,
                    len(flows),
                    len(pending),
                )
                if dump_hex:
                    # Short hex goes only to file (mark as heavy to drop from console)
                    log.info("hex:\n%s", _hexdump(data, max_len=dump_len), extra={"heavy": True})
                    # Full hex only into file handler (flagged as heavy)
                    if any(isinstance(h, logging.FileHandler) for h in log.handlers):
                        log.info("hex_full:\n%s", _hexdump(data, max_len=len(data)), extra={"heavy": True})
            else:
                # Unknown/unsupported – log briefly
                log.debug("drop packet from %s: unsupported version=%s", exporter_ip, v)
        except Exception as e:
            log.warning("parse failed from %s: %s", exporter_ip, e)

        # Flush in batches for efficiency
        if len(pending) >= batch_size:
            inserted = _insert_rows(pending)
            pending.clear()
            last_flush = datetime.now(tz=timezone.utc)
            log.info("flush(batch): inserted=%d", inserted)

        # Time-based flush to keep UI fresh under low volume
        now = datetime.now(tz=timezone.utc)
        if pending and (now - last_flush).total_seconds() * 1000.0 >= flush_interval_ms:
            inserted = _insert_rows(pending)
            pending.clear()
            last_flush = now
            log.info("flush(time): inserted=%d", inserted)


if __name__ == "__main__":
    run()

import os
import socket
import struct
import logging
from typing import Dict, Any, Tuple


log = logging.getLogger("ipam.netflow.dump")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(_h)
log.setLevel(logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO").upper()))


def _peek_header(data: bytes) -> Tuple[int, Dict[str, Any]]:
    meta: Dict[str, Any] = {}
    try:
        if len(data) < 4:
            return 0, meta
        ver = struct.unpack('!H', data[:2])[0]
        if ver == 9:
            if len(data) >= 20:
                v, count, uptime, ts, seq, srcid = struct.unpack('!HHIIII', data[:20])
                meta.update({
                    'count': int(count), 'uptime': int(uptime), 'export_ts': int(ts),
                    'sequence': int(seq), 'source_id': int(srcid)
                })
                off = 20
                sets = []
                while off + 4 <= len(data) and len(sets) < 20:
                    sid, slen = struct.unpack('!HH', data[off:off+4])
                    sets.append(int(sid))
                    if slen <= 0:
                        break
                    off += slen
                meta['set_ids'] = sets
            return 9, meta
        elif ver == 10:  # IPFIX
            if len(data) >= 16:
                v, length, uptime, seq, dom = struct.unpack('!HHIII', data[:16])
                meta.update({'length': int(length), 'uptime': int(uptime), 'sequence': int(seq), 'source_id': int(dom)})
                off = 16
                sets = []
                while off + 4 <= len(data) and len(sets) < 20:
                    sid, slen = struct.unpack('!HH', data[off:off+4])
                    sets.append(int(sid))
                    if slen <= 0:
                        break
                    off += slen
                meta['set_ids'] = sets
            return 10, meta
        elif ver == 5:
            if len(data) >= 24:
                v, count, uptime, ts, tsnano, seq, etype, eid, samp = struct.unpack('!HHIIIIBBH', data[:24])
                meta.update({'count': int(count), 'uptime': int(uptime), 'export_ts': int(ts), 'sequence': int(seq)})
            return 5, meta
        else:
            return ver, meta
    except Exception:
        return 0, meta


def _hexdump(data: bytes, max_len: int = 128, width: int = 16) -> str:
    data = data[:max_len]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexpart = ' '.join(f"{b:02x}" for b in chunk)
        asciipart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<{width*3}}  {asciipart}")
    return '\n'.join(lines)


def run():
    bind_host = os.environ.get("NETFLOW_BIND_HOST", "0.0.0.0")
    bind_port = int(os.environ.get("NETFLOW_BIND_PORT", "2055"))
    dump_hex = os.environ.get("DUMP_HEX", "0") == "1"
    dump_len = int(os.environ.get("DUMP_HEX_LEN", "128"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    log.info("NetFlow dumper listening on %s:%s/udp", bind_host, bind_port)
    while True:
        data, addr = sock.recvfrom(65535)
        exporter_ip, exporter_port = addr
        version, meta = _peek_header(data)
        set_ids = meta.get('set_ids')
        log.info(
            "pkt exporter=%s v=%s len=%d count=%s seq=%s srcid=%s sets=%s",
            exporter_ip,
            version,
            len(data),
            meta.get('count'),
            meta.get('sequence'),
            meta.get('source_id'),
            ','.join(str(s) for s in set_ids[:10]) if set_ids else None,
        )
        if dump_hex:
            log.info("hex:\n%s", _hexdump(data, max_len=dump_len))


if __name__ == "__main__":
    run()


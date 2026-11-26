"""Minimal DNS wire-format helpers (stdlib only)."""
import os
import struct

TYPE_A = 1
TYPE_AAAA = 28


def encode_query(name, qtype=TYPE_A):
    name = name.rstrip(".").encode("idna") if any(ord(c) > 127 for c in name) else name.encode("ascii")
    labels = b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\x00"
    header = struct.pack(">HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
    return header + labels + struct.pack(">HH", qtype, 1)


def _read_name(data, off):
    parts = []
    seen = set()
    end = None            # position just after the name in the original stream
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            if end is None:
                end = off + 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if end is None:
                end = off + 2     # caller resumes after the 2-byte pointer
            if ptr in seen:
                raise ValueError("pointer loop")
            seen.add(ptr)
            off = ptr
        else:
            parts.append(data[off + 1: off + 1 + length].decode("ascii", "replace"))
            off += 1 + length
    return ".".join(p for p in parts if p), end


def parse_response(data):
    """Return (rcode, answers) where answers = [(name, type, ttl, value_str)]."""
    if len(data) < 12:
        raise ValueError("short DNS message")
    qd, an, _ns, _ar = struct.unpack(">HHHH", data[4:12])
    rcode = data[3] & 0x0F
    off = 12
    for _ in range(qd):
        _name, off = _read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = _read_name(data, off)
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == TYPE_A and rdlen == 4:
            answers.append((name, rtype, ttl, ".".join(str(b) for b in rdata)))
        elif rtype == TYPE_AAAA and rdlen == 16:
            groups = [rdata[i:i + 2].hex() for i in range(0, 16, 2)]
            answers.append((name, rtype, ttl, _compact_v6(groups)))
        elif rtype == 5:  # CNAME — parse so callers can follow if needed
            cname, _ = _read_name(data, off - rdlen)
            answers.append((name, rtype, ttl, cname))
    return rcode, answers


def _compact_v6(groups):
    # naive compression of the longest zero run
    out = []
    i = 0
    while i < len(groups):
        if groups[i] == "00":
            j = i
            while j < len(groups) and groups[j] == "00":
                j += 1
            if j - i > 1:
                out.append("")
                i = j
                continue
        out.append(groups[i].lstrip("0") or "0")
        i += 1
    text = ":".join(out)
    return text.replace("::", "::", 1) if "::" in text else text


def extract_ips(answers, qtype):
    return [v for (_n, t, _ttl, v) in answers if t == qtype]

"""Minimal DNS wire-format helpers (stdlib only)."""
import os
import struct

TYPE_A = 1
TYPE_AAAA = 28


def encode_query(name, qtype=TYPE_A):
    # a trailing dot is a legal FQDN form (CONNECT 'Host: example.com.')
    # and must be stripped BEFORE encoding — the ASCII path would else
    # emit an empty label before the terminator and every resolver
    # would answer FormErr/ignore
    name = name.rstrip(".")
    name = name.encode("idna") if any(ord(c) > 127 for c in name) else name.encode("ascii")
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
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
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


def parse_response(data, qname=None):
    """Return (rcode, answers) where answers = [(name, type, ttl, value_str)].

    qname (optional): the question name. When given, only answer records
    that belong to the question are returned — the record's own name must
    equal qname (case-insensitive, trailing dot ignored, IDN-normalized)
    or the current CNAME-chain target. Over DoH this is belt-and-braces;
    over UDP the transaction ID and the connected socket are the only
    other checks, so an answer stuffed with unrelated A records is
    otherwise accepted.
    Malformed/truncated input raises ValueError — never IndexError/
    struct.error (a hostile or corrupt answer must not crash a resolver
    thread)."""
    try:
        return _parse_response_inner(data, qname)
    except ValueError:
        raise
    except (IndexError, struct.error):
        raise ValueError("malformed DNS message")


def _norm_name(name):
    """Comparable form of a DNS name: no trailing dot, lowercased,
    IDN names converted to their punycode form."""
    n = (name or "").rstrip(".")
    if any(ord(c) > 127 for c in n):
        try:
            n = n.encode("idna").decode("ascii")
        except (UnicodeError, OSError):
            pass
    return n.lower()


def _parse_response_inner(data, qname=None):
    if len(data) < 12:
        raise ValueError("short DNS message")
    qd, an, _ns, _ar = struct.unpack(">HHHH", data[4:12])
    rcode = data[3] & 0x0F
    off = 12
    for _ in range(qd):
        _name, off = _read_name(data, off)
        if off + 4 > len(data):
            raise ValueError("truncated question")
        off += 4
    expect = _norm_name(qname) if qname else None
    alias = None            # current CNAME-chain target (normalized)

    def _owned(rec_name):
        """Record belongs to the question (or the alias chain so far)?"""
        if expect is None:
            return True
        n = _norm_name(rec_name)
        return n == expect or (alias is not None and n == alias)

    answers = []
    for _ in range(an):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            raise ValueError("truncated record header")
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if len(rdata) < rdlen:
            raise ValueError("truncated record data")
        off += rdlen
        if rtype == TYPE_A and rdlen == 4:
            if _owned(name):
                answers.append((name, rtype, ttl, ".".join(str(b) for b in rdata)))
        elif rtype == TYPE_AAAA and rdlen == 16:
            if _owned(name):
                groups = [rdata[i:i + 2].hex() for i in range(0, 16, 2)]
                answers.append((name, rtype, ttl, _compact_v6(groups)))
        elif rtype == 5:  # CNAME — parse so callers can follow if needed
            cname, _ = _read_name(data, off - rdlen)
            if _owned(name):
                answers.append((name, rtype, ttl, cname))
                alias = _norm_name(cname)   # next records belong to this
    return rcode, answers


def _compact_v6(groups):
    # RFC 5952: compress the longest run of zero groups (>= 2) with "::"
    nums = [int(g, 16) for g in groups]
    best_i, best_len = -1, 1
    i = 0
    while i < 8:
        if nums[i] == 0:
            j = i
            while j < 8 and nums[j] == 0:
                j += 1
            if j - i > best_len:
                best_i, best_len = i, j - i
            i = j
        else:
            i += 1
    if best_i < 0:
        return ":".join(format(n, "x") for n in nums)
    head = ":".join(format(n, "x") for n in nums[:best_i])
    tail = ":".join(format(n, "x") for n in nums[best_i + best_len:])
    return f"{head}::{tail}"


def extract_ips(answers, qtype):
    return [v for (_n, t, _ttl, v) in answers if t == qtype]

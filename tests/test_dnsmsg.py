"""Tests for hookip.dnsmsg — wire format, no network.
Run: python tests/test_dnsmsg.py"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hookip.dnsmsg as dm  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


def enc_name(name):
    """Encode a name uncompressed (labels + terminator)."""
    out = b""
    for p in name.rstrip(".").split("."):
        b = p.encode("idna") if any(ord(c) > 127 for c in p) else p.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_resp(qname, records):
    """Minimal DNS response: header + question + uncompressed answers.
    records: (owner-name, rtype, ttl, rdata bytes)."""
    q = enc_name(qname) + struct.pack(">HH", dm.TYPE_A, 1)
    body = b""
    for (owner, rtype, ttl, rdata) in records:
        body += enc_name(owner) + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, len(records), 0, 0)
    return header + q + body


# ---- 1. trailing dot --------------------------------------------------
def test_trailing_dot():
    q1 = dm.encode_query("example.com", dm.TYPE_A)
    q2 = dm.encode_query("example.com.", dm.TYPE_A)
    check("trailing dot: identical question section", q1[12:] == q2[12:],
          f"{q1[12:]!r} vs {q2[12:]!r}")
    check("trailing dot: no empty label",
          q1[12:12 + 13] == b"\x07example\x03com\x00", q1[12:26])
    # IDN path keeps working
    q3 = dm.encode_query("exämple.com.", dm.TYPE_A)
    check("trailing dot: IDN path unaffected", b"xn--exmple-cua" in q3, q3[12:40])


# ---- 2. question-name filtering ---------------------------------------
def test_qname_filter():
    # unrelated A records in the answer section are dropped
    resp = build_resp("target.test", [
        ("target.test", dm.TYPE_A, 60, b"\x01\x02\x03\x04"),
        ("evil.test", dm.TYPE_A, 60, b"\x06\x06\x06\x06"),
        ("other.test", dm.TYPE_AAAA, 60, b"\x20" * 16),
    ])
    rcode, answers = dm.parse_response(resp, qname="target.test")
    vals = [v for (_n, t, _ttl, v) in answers if t == dm.TYPE_A]
    check("qname filter drops unrelated records",
          rcode == 0 and vals == ["1.2.3.4"], str(answers))

    # CNAME chain accepted: alias record + address under the alias
    resp2 = build_resp("chain.test", [
        ("chain.test", 5, 300, enc_name("alias.test")),
        ("evil.test", dm.TYPE_A, 60, b"\x06\x06\x06\x06"),
        ("alias.test", dm.TYPE_A, 60, b"\x09\x09\x09\x09"),
    ])
    rcode, answers = dm.parse_response(resp2, qname="chain.test")
    check("qname filter keeps the CNAME chain",
          any(t == 5 for (_n, t, _ttl, _v) in answers)
          and "9.9.9.9" in [v for (_n, t, _ttl, v) in answers if t == dm.TYPE_A],
          str(answers))

    # no qname -> old behaviour (all records), tests keep working
    rcode, answers = dm.parse_response(resp)
    check("no qname: all records returned (back-compat)", len(answers) == 3)

    # case + trailing dot in the question do not break matching
    resp3 = build_resp("MiXeD.Test", [("mixed.test", dm.TYPE_A, 60, b"\x07\x07\x07\x07")])
    rcode, answers = dm.parse_response(resp3, qname="mixed.test.")
    check("qname matching is case/dot insensitive", len(answers) == 1, str(answers))


# ---- 3. compression pointers + record shapes -------------------------
def test_compression_pointers():
    """Real resolvers pointer-compress owner names — the answer records
    must decode through 0xC0 pointers (with the resume position right)."""
    q = enc_name("ptr.test")
    # header(12) + question(name+qtype+qclass); answer owner = pointer to
    # the question's name at offset 12
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", dm.TYPE_A, 1, 60, 4)
              + b"\x0a\x0b\x0c\x0d")
    resp = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q
            + struct.pack(">HH", dm.TYPE_A, 1) + answer)
    rcode, answers = dm.parse_response(resp, qname="ptr.test")
    vals = [v for (_n, t, _ttl, v) in answers if t == dm.TYPE_A]
    check("0xC0 pointer owner name decodes",
          rcode == 0 and vals == ["10.11.12.13"], str(answers))

    # pointer + A record parses right after (resume position exactness)
    q2 = enc_name("ptr2.test")
    resp2 = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q2
             + struct.pack(">HH", dm.TYPE_A, 1) + (
        b"\xc0\x0c" + struct.pack(">HHIH", dm.TYPE_A, 1, 30, 4) + b"\x01\x02\x03\x04"))
    rcode, answers2 = dm.parse_response(resp2, qname="ptr2.test")
    check("pointer + A record parses after", rcode == 0
          and [v for (_n, t, _ttl, v) in answers2 if t == dm.TYPE_A] == ["1.2.3.4"],
          str(answers2))

    # truncated packet must raise ValueError, not crash the process
    try:
        dm.parse_response(resp[:len(resp) - 2], qname="ptr.test")
        check("truncated packet rejected", False, "no raise")
    except ValueError:
        check("truncated packet rejected", True)


def test_rcode_and_aaaa():
    resp = build_resp("gone.test", [])
    # flip rcode to 3 (NXDOMAIN) in the header
    resp = resp[:2] + struct.pack(">H", 0x8183) + resp[4:]
    rcode, answers = dm.parse_response(resp, qname="gone.test")
    check("NXDOMAIN rcode surfaces as 3", rcode == 3 and answers == [])

    resp6 = build_resp("v6.test", [
        ("v6.test", dm.TYPE_AAAA, 120,
         bytes.fromhex("26064700470000000000000000000011"))])
    rcode, answers = dm.parse_response(resp6, qname="v6.test")
    ips = dm.extract_ips(answers, dm.TYPE_AAAA)
    check("AAAA extracted, zero-compressed",
          ips == ["2606:4700:4700::11"], str(ips))

    # TTL comes through parseable
    ttl = [t for (_n, _t, t, _v) in answers if _t == dm.TYPE_AAAA][0]
    check("AAAA ttl parsed", ttl == 120)


test_trailing_dot()
test_qname_filter()
test_compression_pointers()
test_rcode_and_aaaa()
print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

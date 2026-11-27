"""Tests for hookip.tlsfrag — hand-built ClientHello fixtures, no network.
Run: python tests/test_tlsfrag.py (skips on non-Windows is not needed —
pure stdlib, runs anywhere, but the suite is targeted at the proxy's
Windows use; it runs fine cross-platform).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import tlsfrag as tf  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


def build_hello(host=None, sni_last=False, extra_ext=True, reclen_override=None):
    """Assemble a TLS record: ClientHello with a configurable extension
    order. Layout (matching the parser): rec hdr 5 | hs type 1 + len 3 |
    ver 2 | random 32 | sidlen 1 (0) | clen 2 | ciphers 2 | comp 1 (0) |
    ext_total 2 | extensions."""
    exts = []
    if host is not None:
        name = host.encode("ascii")
        sni_ext = (struct.pack(">H", len(name) + 3)    # server_name_list len
                   + b"\x00"                             # host_name type
                   + struct.pack(">H", len(name))
                   + name)
        exts.append((0, sni_ext))
    if extra_ext:
        exts.append((0x0017, b""))            # extension_type 23, len 0
        exts.append((0x000a, b"\x00\x02\x00\x1d"))  # supported groups
    if sni_last:
        exts.reverse()
    ext_blob = b"".join(struct.pack(">HH", t, len(v)) + v for t, v in exts)
    hs_body = (b"\x03\x03"                   # client version
               + b"\x11" * 32                # random
               + b"\x00"                     # session id len 0
               + b"\x00\x02\x13\x01"         # cipher suites: len 2, 2 bytes
               + b"\x01\x00"                 # compression: 1 method
               + struct.pack(">H", len(ext_blob)) + ext_blob)
    hs = b"\x01" + struct.pack(">I", len(hs_body))[1:] + hs_body
    reclen = len(hs)
    if reclen_override is not None:
        reclen = reclen_override
    return b"\x16\x03\x01" + struct.pack(">H", reclen) + hs


# ---- 1/2/4: round-trip for every strategy and chunk size -------------
hellos = {
    "with SNI": build_hello("example.com"),
    "SNI last": build_hello("example.com", sni_last=True),
    "no SNI": build_hello(None),
    "no SNI no extra": build_hello(None, extra_ext=False),
    "long name": build_hello("a" * 200 + ".example.com"),
}
for label, rec in hellos.items():
    for strat in ("smart", "chunk", "random"):
        for cs in (1, 2, 5):
            parts = tf.fragment(rec, strat, cs)
            joined = b"".join(parts)
            ok = (parts and all(parts) and joined == rec
                  and len(parts) >= 1)
            check(f"round-trip {label} {strat} cs={cs}", ok,
                  f"{len(parts)} parts")

# trailing bytes after the hello must ride along untouched
rec = build_hello("example.com")
tagged = rec + b"\x17\x03\x03\x00\x05hello"
for strat in ("smart", "chunk", "random"):
    parts = tf.fragment(tagged, strat, 2)
    check(f"trailing bytes ride along ({strat})",
          b"".join(parts) == tagged and all(parts))
info = tf.parse_client_hello(rec)
check("parse offsets sane",
      info is not None and rec[info["sni_start"]:info["sni_end"]] == b"example.com"
      and info["host"] == "example.com" and info["total"] == len(rec))

# ---- 1: 'random' with SNI LAST — hostname never whole in one segment --
rec_last = build_hello("example-hostname-12345.com", sni_last=True)
info_last = tf.parse_client_hello(rec_last)
name = b"example-hostname-12345.com"
violations = 0
for _ in range(50):
    parts = tf.fragment(rec_last, "random", 2)
    if any(name in p for p in parts):
        violations += 1
check("random: SNI-last never whole in one segment (50 runs)",
      violations == 0, f"{violations}/50 violations")

# ---- 'smart' and 'chunk' split the SNI across segments ---------------
for strat in ("smart", "chunk", "random"):
    parts = tf.fragment(rec, strat, 2)
    whole = any(b"example.com" in p for p in parts)
    check(f"{strat}: SNI hostname split across segments", not whole)

# ---- 2: hello WITHOUT SNI -> [head] (+ rest as its own part) ---------
rec_nosni = build_hello(None)
for strat in ("smart", "chunk", "random"):
    parts = tf.fragment(rec_nosni, strat, 2)
    tagged = rec_nosni + b"trailer"
    parts_t = tf.fragment(tagged, strat, 2)
    check(f"no-SNI {strat}: [head] (+rest)",
          parts == [rec_nosni] and len(parts_t) == 2 and parts_t[1] == b"trailer",
          f"{[len(p) for p in parts_t]}")

# ---- 4: truncated / non-TLS / empty / reclen 0 / oversized -----------
for label, blob in (("truncated hello", build_hello("example.com")[:40]),
                    ("non-TLS data", b"GET / HTTP/1.1\r\n\r\n"),
                    ("empty input", b""),
                    ("reclen 0", b"\x16\x03\x01\x00\x00"),
                    ("oversized reclen", b"\x16\x03\x01\xff\xff" + b"\x00" * 20)):
    for strat in ("smart", "chunk", "random"):
        try:
            parts = tf.fragment(blob, strat, 2)
            check(f"fallback {label} ({strat})",
                  b"".join(parts) == blob and not any(None == p for p in parts))
        except Exception as e:
            check(f"fallback {label} ({strat})", False, repr(e))

# malformed SNI length: no raise, host None
rec_bad = bytearray(build_hello("example.com"))
# fixed layout: ext_total at 49-50, SNI ext header at 51 (etype 2,
# elen 2), listlen 55-56, type 57, namelen 58-59, name at 60
rec_bad[58:60] = b"\xff\xff"
info = tf.parse_client_hello(bytes(rec_bad))
check("malformed SNI length -> host None, no raise",
      info is not None and info["host"] is None
      and info["sni_start"] is None, str(info))
for strat in ("smart", "chunk", "random"):
    parts = tf.fragment(bytes(rec_bad), strat, 2)
    check(f"malformed SNI fragments fine ({strat})",
          b"".join(parts) == bytes(rec_bad) and all(parts))

# ---- 3/4: hello_needed values ----------------------------------------
check("hello_needed empty -> 1", tf.hello_needed(b"") == 1)
check("hello_needed non-TLS -> 0", tf.hello_needed(b"GET / HTTP/1.1\r\n") == 0)
check("hello_needed partial header -> remaining",
      tf.hello_needed(b"\x16\x03\x01") == 2)
full = build_hello("example.com")
check("hello_needed complete -> 0", tf.hello_needed(full) == 0)
check("hello_needed partial body -> remaining",
      tf.hello_needed(full[:30]) == len(full) - 30)
check("hello_needed oversized -> 0",
      tf.hello_needed(b"\x16\x03\x01\xff\xff" + b"\x00" * 10) == 0)

# ---- chunk_size non-int fallback -------------------------------------
for strat in ("smart", "chunk", "random"):
    for bad in (None, "2"):
        try:
            parts = tf.fragment(rec, strat, bad)
            check(f"chunk_size {bad!r} ({strat})",
                  b"".join(parts) == rec and all(parts))
        except Exception as e:
            check(f"chunk_size {bad!r} ({strat})", False, repr(e))

# reclen 0 / oversized are rejected by parse (fragment falls back)
check("parse rejects reclen 0", tf.parse_client_hello(b"\x16\x03\x01\x00\x00") is None)
check("parse rejects oversized", tf.parse_client_hello(
    b"\x16\x03\x01\xff\xff" + b"\x00" * 20) is None)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""Tests for hookip.dataguard — plain stdlib, run with:
    python tests/test_dataguard.py
"""
import base64
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import dataguard as dg  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


def hlog_lines(path):
    return [l for l in open(path, encoding="utf-8").read().splitlines() if l.strip()]


# ---------------- round-trips, sentinels (bugs 4 + 6) ----------------
line = "[2026-01-01 12:00:00] [ OK  ] tunnel github.com:443 up via smart in 120ms"
enc = dg.encrypt_line(line)
check("encrypt_line magic", enc.startswith(dg.LOG_MAGIC) and "github" not in enc)
check("decrypt_line round-trip", dg.decrypt_line(enc) == line)
check("decrypt_line foreign -> None", dg.decrypt_line("plain text") is None)
check("encrypt_line(None) guarded", dg.encrypt_line(None).startswith(dg.LOG_MAGIC))
try:
    dg.encrypt_line(42)
    check("encrypt_line(42) raises TypeError", False)
except TypeError:
    check("encrypt_line(42) raises TypeError", True)

payload = json.dumps({"port": 8890, "excluded": ["netflix.com"]}).encode()
encb = dg.encrypt_bytes(payload)
check("encrypt_bytes magic", encb.startswith(dg.CFG_MAGIC) and "netflix" not in encb)
check("decrypt_bytes round-trip", dg.decrypt_bytes(encb) == payload)
check("decrypt_bytes plaintext -> None", dg.decrypt_bytes('{"port":1}') is None)

# foreign DPAPI blob WITHOUT our entropy must not decrypt as ours
pin, keep = dg._blob(b"other app secret")
pout = dg._DATA_BLOB()
dg._crypt32.CryptProtectData(ctypes.byref(pin), None, None, None, None, 0,
                             ctypes.byref(pout))
foreign = ctypes.string_at(pout.pbData, pout.cbData)
dg._kernel32.LocalFree(ctypes.cast(pout.pbData, ctypes.c_void_p))
b64 = base64.b64encode(foreign).decode()
check("foreign DPAPI blob -> UNREADABLE",
      dg.decrypt_line(dg.LOG_MAGIC + b64) is dg.UNREADABLE)

# corrupted blob (valid b64, garbage bytes) -> UNREADABLE, no exception
corrupt = dg.LOG_MAGIC + base64.b64encode(b"\x01\x02\x03garbage-not-dpapi").decode()
check("corrupted blob -> UNREADABLE", dg.decrypt_line(corrupt) is dg.UNREADABLE)

# truncated real blob -> UNREADABLE
blob_bytes = base64.b64decode(enc[len(dg.LOG_MAGIC):])
trunc = dg.LOG_MAGIC + base64.b64encode(blob_bytes[: len(blob_bytes) // 2]).decode()
check("truncated blob -> UNREADABLE", dg.decrypt_line(trunc) is dg.UNREADABLE)

# ---------------- migration (bug 1) ----------------------------------
d = tempfile.mkdtemp()

# a) plain conversion; \n-only splitting (a \x0c form-feed stays inline)
src1 = os.path.join(d, "hookip_a.log")
with open(src1, "wb") as fh:
    fh.write(b"[2026-01-01] [INFO] tunnel github.com:443\n"
             b"[INFO] netflix \x0c formfeed stays\n")
conv, total = dg.migrate_plaintext_logs(d)
check("migrate converts", conv == 1 and total == 1, f"{conv}/{total}")
h1 = os.path.join(d, "hookip_a.hlog")
check("migrate removes source", not os.path.exists(src1) and os.path.exists(h1))
raw = open(h1, encoding="utf-8").read()
check("migrate output opaque",
      "github" not in raw and "netflix" not in raw and "HKLOG1:" in raw)
vals = [dg.decrypt_line(x) for x in hlog_lines(h1)]
check("migrate: form-feed NOT treated as a line break",
      len(vals) == 2 and any("\x0c" in v for v in vals), f"{len(vals)} lines")
check("migrate decrypts hosts", any("github.com:443" in (v or "") for v in vals))

# b) BUG 1 regression: .hlog already exists -> MERGE, never clobber
src2 = os.path.join(d, "hookip_b.log")
dst2 = os.path.join(d, "hookip_b.hlog")
with open(src2, "w", encoding="utf-8") as fh:
    fh.write("[2026-01-02] [INFO] tunnel steamcontent.com:443\n")
with open(dst2, "w", encoding="utf-8") as fh:
    fh.write(dg.encrypt_line("[2026-01-01] [INFO] pre-existing encrypted line") + "\n")
conv2, total2 = dg.migrate_plaintext_logs(d)
check("migrate second file", conv2 == 1 and total2 == 1, f"{conv2}/{total2}")
vals2 = [dg.decrypt_line(x) for x in hlog_lines(dst2)]
check("existing .hlog preserved (merge not clobber)",
      any("pre-existing encrypted line" in (v or "") for v in vals2), str(vals2))
check("legacy content appended to existing .hlog",
      any("steamcontent.com:443" in (v or "") for v in vals2))
check("no stray \\r from CRLF legacy files",
      all(not v.endswith("\r") for v in vals2 if v), str(vals2[-1][-12:]))
check("legacy source removed after merge", not os.path.exists(src2))
check("no .mig temp left", not [n for n in os.listdir(d) if n.endswith(".mig")])

# c) non-UTF-8 bytes survive unaltered (latin-1 fallback, not 'replace')
d2 = tempfile.mkdtemp()
weird = "[2026-01-01] caf\xe9 latin byte \xff\n"
with open(os.path.join(d2, "hookip_c.log"), "wb") as fh:
    fh.write(weird.encode("latin-1"))
dg.migrate_plaintext_logs(d2)
vals3 = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d2, "hookip_c.hlog"))]
check("non-UTF-8 survives latin-1 fallback", any("caf\xe9" in (v or "") for v in vals3))
shutil.rmtree(d2, ignore_errors=True)

# ---------------- ACL hardening (bugs 2 + 3) --------------------------
d3 = tempfile.mkdtemp()
check("harden_dir by SID succeeds", dg.harden_dir(d3) is True)
check("acl_is_hardened true after", dg.acl_is_hardened(d3) is True)
out = subprocess.run(["icacls", d3], capture_output=True, text=True).stdout
check("no inherited flag on ACE lines",
      not any("(I)" in ln for ln in out.splitlines()[1:]))
sid = dg._current_user_sid()
check("current-user SID resolvable", bool(sid) and sid.startswith("S-1-"))
check("user or SYSTEM ACE present",
      any((".F)" in ln or "F)" in ln) for ln in out.splitlines()[1:]))
shutil.rmtree(d3, ignore_errors=True)

with mock.patch.object(dg, "_current_user_sid", lambda: None):
    tmp = tempfile.mkdtemp()
    check("harden_dir without SID -> False", dg.harden_dir(tmp) is False)
    shutil.rmtree(tmp, ignore_errors=True)

# acl_is_hardened must not be fooled by a directory whose NAME contains '(I)'
base4 = tempfile.mkdtemp()
d4 = os.path.join(base4, "weird (I) name")
os.makedirs(d4)
check("harden_dir on '(I)'-named dir", dg.harden_dir(d4) is True)
check("acl_is_hardened not fooled by dir name", dg.acl_is_hardened(d4) is True)
shutil.rmtree(base4, ignore_errors=True)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

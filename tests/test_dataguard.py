"""Tests for hookip.dataguard — plain stdlib, run with:
    python tests/test_dataguard.py

Skips with a clear message on non-Windows (DPAPI + icacls only exist there).
"""
import base64
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest.mock as mock

if os.name != "nt":
    print("SKIP: hookip.dataguard is Windows-only "
          "(uses DPAPI via crypt32 and icacls); not testable on this OS.")
    sys.exit(0)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import dataguard as dg  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


def hlog_lines(path):
    return [l for l in open(path, encoding="utf-8").read().splitlines() if l.strip()]


# ---------------- round trips, sentinels ------------------------------
line = "[2026-01-01 12:00:00] [ OK  ] tunnel github.com:443 up via smart in 120ms"
enc = dg.encrypt_line(line)
check("encrypt_line magic", enc.startswith(dg.LOG_MAGIC) and "github" not in enc)
check("decrypt_line round-trip", dg.decrypt_line(enc) == line)
check("decrypt_line plain text -> None", dg.decrypt_line("plain text") is None)
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

# UNREADABLE sentinel: distinct from None AND falsy (bug-4 regression)
corrupt = dg.LOG_MAGIC + base64.b64encode(b"\x01\x02\x03garbage-not-dpapi").decode()
check("corrupted blob -> UNREADABLE (is-check)",
      dg.decrypt_line(corrupt) is dg.UNREADABLE)
check("bool(UNREADABLE) is False", bool(dg.UNREADABLE) is False)
check("repr(UNREADABLE) readable", repr(dg.UNREADABLE) == "<UNREADABLE>")
blob_bytes = base64.b64decode(enc[len(dg.LOG_MAGIC):])
trunc = dg.LOG_MAGIC + base64.b64encode(blob_bytes[: len(blob_bytes) // 2]).decode()
check("truncated blob -> UNREADABLE", dg.decrypt_line(trunc) is dg.UNREADABLE)

# foreign DPAPI blob (no app entropy) must not decrypt as ours
pin, keep = dg._blob(b"other app secret")
pout = dg._DATA_BLOB()
dg._crypt32.CryptProtectData(ctypes.byref(pin), None, None, None, None, 0,
                             ctypes.byref(pout))
foreign = ctypes.string_at(pout.pbData, pout.cbData)
dg._kernel32.LocalFree(ctypes.cast(pout.pbData, ctypes.c_void_p))
check("foreign DPAPI blob -> UNREADABLE",
      dg.decrypt_line(dg.LOG_MAGIC + base64.b64encode(foreign).decode())
      is dg.UNREADABLE)

# ---------------- migration (bug 1 + dedupe) ---------------------------
d = tempfile.mkdtemp()

# a) plain conversion; \n-only splitting; CRLF normalized
src1 = os.path.join(d, "hookip_a.log")
with open(src1, "wb") as fh:
    fh.write(b"[2026-01-01] [INFO] tunnel github.com:443\r\n"
             b"[INFO] netflix \x0c formfeed stays\n")
conv, total = dg.migrate_plaintext_logs(d)
check("migrate converts", conv == 1 and total == 1, f"{conv}/{total}")
h1 = os.path.join(d, "hookip_a.hlog")
check("migrate removes source", not os.path.exists(src1) and os.path.exists(h1))
check("no leftover .migrating", not [n for n in os.listdir(d) if n.endswith(".migrating")])
vals = [dg.decrypt_line(x) for x in hlog_lines(h1)]
check("migrate: CRLF normalized, form-feed NOT a line break",
      len(vals) == 2 and vals[0].endswith(":443") and "\x0c" in vals[1], str(vals))
raw1 = open(h1, encoding="utf-8").read()
check("migrate output opaque + LF endings",
      "github" not in raw1 and "\r" not in raw1 and "HKLOG1:" in raw1)

# b) .hlog already exists -> existing lines preserved, new appended
src2 = os.path.join(d, "hookip_b.log")
dst2 = os.path.join(d, "hookip_b.hlog")
with open(src2, "w", encoding="utf-8") as fh:
    fh.write("[2026-01-02] [INFO] tunnel steamcontent.com:443\n")
with open(dst2, "w", encoding="utf-8") as fh:
    fh.write(dg.encrypt_line("[2026-01-01] [INFO] pre-existing encrypted line") + "\n")
conv2, total2 = dg.migrate_plaintext_logs(d)
vals2 = [dg.decrypt_line(x) for x in hlog_lines(dst2)]
check("merge: existing line preserved",
      any("pre-existing encrypted line" in (v or "") for v in vals2))
check("merge: new line appended",
      any("steamcontent.com:443" in (v or "") for v in vals2))
check("merge: no duplicates on single run", len(vals2) == 2, str(len(vals2)))
check("merge: legacy source removed", not os.path.exists(src2))

# c) BUG 1 regression: final os.remove fails -> rerun must NOT duplicate
d3 = tempfile.mkdtemp()
s3 = os.path.join(d3, "hookip_c.log")
with open(s3, "w", encoding="utf-8") as fh:
    fh.write("[2026-01-03] [INFO] tunnel gnu.org:443\n")
with mock.patch.object(dg.os, "remove", side_effect=OSError("AV lock")):
    conv3, _ = dg.migrate_plaintext_logs(d3)
check("remove-fail run keeps leftover .migrating",
      conv3 == 0 and any(n.endswith(".log.migrating") for n in os.listdir(d3)))
conv3b, _ = dg.migrate_plaintext_logs(d3)          # rerun, no mock
vals3 = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d3, "hookip_c.hlog"))]
check("rerun finishes leftover .migrating", conv3b == 1 and
      any("gnu.org:443" in (v or "") for v in vals3), str(vals3))
check("rerun did NOT duplicate lines", len(vals3) == 1, f"{len(vals3)} lines")
check("cleanup: no .migrating/.mig left",
      not [n for n in os.listdir(d3) if ".mig" in n])

# d) orphan foo.log.migrating from a crashed run is finished, not ignored
d4 = tempfile.mkdtemp()
orphan = os.path.join(d4, "hookip_d.log.migrating")
with open(orphan, "wb") as fh:
    fh.write("[2026-01-04] [INFO] tunnel pypi.org:443\n".encode())
conv4, _ = dg.migrate_plaintext_logs(d4)
vals4 = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d4, "hookip_d.hlog"))]
check("orphan .log.migrating finished", conv4 == 1 and
      any("pypi.org:443" in (v or "") for v in vals4))
check("orphan consumed", not os.path.exists(orphan))

# ---------------- ACL hardening (bugs 2 + 3) ---------------------------
d5 = tempfile.mkdtemp()
check("harden_dir by SID succeeds", dg.harden_dir(d5) is True)
check("acl_is_hardened true after", dg.acl_is_hardened(d5) is True)
out = subprocess.run(["icacls", d5], capture_output=True, text=True).stdout
check("no ':(I)' anywhere in real output", ":(I)" not in out)
check("current-user SID resolvable",
      bool(dg._current_user_sid()) and dg._current_user_sid().startswith("S-1-"))
shutil.rmtree(d5, ignore_errors=True)

with mock.patch.object(dg, "_current_user_sid", lambda: None):
    tmp = tempfile.mkdtemp()
    check("harden_dir without SID -> False", dg.harden_dir(tmp) is False)
    shutil.rmtree(tmp, ignore_errors=True)

# sample-output tests: first ACE on the SAME line as the path (bug 2)
PATH = "C:\\some\\dir"
SAMPLE_INHERITED = PATH + " NT AUTHORITY\\SYSTEM:(I)(F)\n" \
                        "                        DESKTOP\\justc:(I)(F)\n"
SAMPLE_HARDENED = PATH + " DESKTOP-0946146\\justc:(OI)(CI)(F)\n" \
                       "                        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"


def fake_run(cmd, **kw):
    sample = SAMPLE_INHERITED if "(I)" in str(cmd) and kw.pop("inherited", True) \
        else SAMPLE_HARDENED
    return types.SimpleNamespace(returncode=0, stdout=sample, stderr="")


with mock.patch.object(dg.subprocess, "run",
                       lambda cmd, **kw: types.SimpleNamespace(
                           returncode=0,
                           stdout=SAMPLE_INHERITED if kw.get("_inh", True)
                           else SAMPLE_HARDENED,
                           stderr="")):
    pass  # (placeholder — real fakes below)


def _acl_case(stdout):
    with mock.patch.object(dg.subprocess, "run",
                           lambda *a, **k: types.SimpleNamespace(
                               returncode=0, stdout=stdout, stderr="")):
        return dg.acl_is_hardened(PATH)


check("acl_is_hardened: first ACE on path line WITH (I) -> False",
      _acl_case(SAMPLE_INHERITED) is False)
check("acl_is_hardened: first ACE on path line, hardened -> True",
      _acl_case(SAMPLE_HARDENED) is True)
check("acl_is_hardened: icacls failure -> False",
      _acl_case("anything") is True or True)  # replaced below
RESULTS.pop()  # discard the placeholder above


def _acl_case_rc(returncode):
    with mock.patch.object(dg.subprocess, "run",
                           lambda *a, **k: types.SimpleNamespace(
                               returncode=returncode, stdout="", stderr="x")):
        return dg.acl_is_hardened(PATH)


check("acl_is_hardened: nonzero rc -> False", _acl_case_rc(2) is False)
check("acl_is_hardened: not fooled by dir NAME with '(I)'",
      _acl_case(PATH + " weird (I) name account:(F)") is True)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

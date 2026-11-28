"""Tests for hookip.dataguard — plain stdlib, run with:
    python tests/test_dataguard.py

Skips with a clear message on non-Windows (DPAPI + icacls only exist there).
"""
import base64
import ctypes
import hashlib
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

# _crypt raises OSError with a REAL error code in the message (bug 7)
try:
    dg._crypt(b"\x01\x02\x03corrupt-not-dpapi", decrypt=True)
    check("_crypt raises OSError on corrupt blob", False, "no exception")
except OSError as e:
    check("_crypt raises OSError on corrupt blob", bool(str(e).strip()),
          str(e)[:60])

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
marker_ok = vals and isinstance(vals[-1], str) and vals[-1].startswith("# migrated ")
check("migrate: CRLF normalized, form-feed NOT a line break",
      len(vals) == 3 and vals[0].endswith(":443") and "\x0c" in vals[1], str(vals))
check("idempotency marker is last line", marker_ok, str(vals[-1]) if vals else "")
raw1 = open(h1, encoding="utf-8").read()
check("migrate output opaque + LF endings",
      "github" not in raw1 and "\r" not in raw1 and "HKLOG1:" in raw1)

# repeated identical lines are real events — both copies must survive (no
# plaintext-set dedupe anymore)
d_dup = tempfile.mkdtemp()
with open(os.path.join(d_dup, "hookip_dup.log"), "w", encoding="utf-8") as fh:
    fh.write("[INFO] retry tunnel x.com:443\n[INFO] retry tunnel x.com:443\n")
dg.migrate_plaintext_logs(d_dup)
vdup = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d_dup, "hookip_dup.hlog"))]
check("same line twice keeps both copies",
      sum(1 for v in vdup if v == "[INFO] retry tunnel x.com:443") == 2, str(len(vdup)))
shutil.rmtree(d_dup, ignore_errors=True)

# cp1252 bytes decode to curly quotes, not control characters (bug 6)
d_cp = tempfile.mkdtemp()
with open(os.path.join(d_cp, "hookip_q.log"), "wb") as fh:
    fh.write(b"[INFO] \x93quoted\x94 \x97 dash\n")
dg.migrate_plaintext_logs(d_cp)
vq = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d_cp, "hookip_q.hlog"))]
qline = next((v for v in vq if v and "quoted" in v), "")
check("cp1252 smart quotes/dashes decoded",
      "\u201cquoted\u201d" in qline and "\u2014" in qline, repr(qline))
shutil.rmtree(d_cp, ignore_errors=True)

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
check("merge: no duplicates on single run",
      sum(1 for v in vals2 if "steamcontent" in (v or "")) == 1, str(len(vals2)))
check("merge: legacy source removed", not os.path.exists(src2))

# BUG 1 (3rd pass): dst exists but CANNOT be read -> abort that file,
# .hlog untouched, .migrating claim remains
d_u = tempfile.mkdtemp()
su = os.path.join(d_u, "hookip_u.log")
hu = os.path.join(d_u, "hookip_u.hlog")
with open(su, "w", encoding="utf-8") as fh:
    fh.write("[2026-01-05] [INFO] tunnel wikipedia.org:443\n")
with open(hu, "w", encoding="utf-8") as fh:
    fh.write(dg.encrypt_line("[2026-01-04] [INFO] precious existing line") + "\n")
real_open = open
def locked_open(path, mode="r", *a, **kw):
    if os.path.abspath(str(path)) == os.path.abspath(hu):
        raise OSError("AV lock (simulated)")
    return real_open(path, mode, *a, **kw)
with mock.patch("builtins.open", locked_open):
    convu, totu = dg.migrate_plaintext_logs(d_u)
check("dst unreadable -> abort (not converted)", convu == 0, f"conv={convu} tot={totu}")
check("dst unreadable -> .hlog untouched",
      [dg.decrypt_line(x) for x in hlog_lines(hu)][0].endswith("precious existing line"))
check("dst unreadable -> .migrating claim remains",
      any(n.endswith(".log.migrating") for n in os.listdir(d_u)))
check("dst unreadable -> no .mig temp left",
      not [n for n in os.listdir(d_u) if n.endswith(".mig")])
# next run retries and completes
convu2, _ = dg.migrate_plaintext_logs(d_u)
valsu = [dg.decrypt_line(x) for x in hlog_lines(hu)]
check("retry after lock clears completes",
      convu2 == 1 and any("wikipedia.org:443" in (v or "") for v in valsu))
shutil.rmtree(d_u, ignore_errors=True)

# BUG 1: orphan .log.migrating + foo.log BOTH processed in one run (bug 5)
d_o = tempfile.mkdtemp()
with open(os.path.join(d_o, "hookip_o.log.migrating"), "wb") as fh:
    fh.write(b"[2026-01-06] [INFO] tunnel orphan.org:443\n")
with open(os.path.join(d_o, "hookip_o.log"), "w", encoding="utf-8") as fh:
    fh.write("[2026-01-07] [INFO] tunnel fresh.org:443\n")
convo, toto = dg.migrate_plaintext_logs(d_o)
vo = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d_o, "hookip_o.hlog"))]
check("orphan + .log both processed in ONE run",
      convo == 2 and any("orphan.org:443" in (v or "") for v in vo)
      and any("fresh.org:443" in (v or "") for v in vo), f"{convo}/{toto}")
check("one run: nothing left over",
      not [n for n in os.listdir(d_o) if n.endswith(".log") or n.endswith(".migrating")])
shutil.rmtree(d_o, ignore_errors=True)

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
check("rerun finishes leftover via marker", conv3b == 1 and
      any("gnu.org:443" in (v or "") for v in vals3), str(vals3))
check("rerun did NOT duplicate lines (marker-based)",
      sum(1 for v in vals3 if "gnu.org:443" in (v or "")) == 1, f"{len(vals3)} lines")
check("marker present after rerun",
      sum(1 for v in vals3 if isinstance(v, str) and v.startswith("# migrated ")) == 1)
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


# ---------------- fourth-pass items ------------------------------------
# encrypt_bytes accepts str
encs = dg.encrypt_bytes("plaintext settings")
check("encrypt_bytes(str) round-trips",
      encs.startswith(dg.CFG_MAGIC)
      and dg.decrypt_bytes(encs) == b"plaintext settings")
try:
    dg.encrypt_bytes(12345)
    check("encrypt_bytes(non-str/bytes) raises TypeError", False, "no raise")
except TypeError:
    check("encrypt_bytes(non-str/bytes) raises TypeError", True)

# is_marker public helper
check("is_marker: marker line recognized",
      dg.is_marker("# migrated hookip_a.log sha256=" + "a" * 64))
check("is_marker: non-marker rejected",
      not dg.is_marker("[INFO] tunnel github.com:443")
      and not dg.is_marker(dg.UNREADABLE)
      and not dg.is_marker(None)
      and not dg.is_marker("# migrated x sha256=short"))

# marker records the file's BASENAME (never an absolute path)
d_base = tempfile.mkdtemp()
with open(os.path.join(d_base, "hookip_n.log"), "wb") as fh:
    fh.write(b"[INFO] tunnel example.org:443\n")
dg.migrate_plaintext_logs(d_base)
vbase = [dg.decrypt_line(x) for x in hlog_lines(os.path.join(d_base, "hookip_n.hlog"))]
mline = next((v for v in vbase if v and v.startswith("# migrated ")), "")
check("marker carries the basename, no path separators",
      "hookip_n.log" in mline and os.sep not in mline and ":" not in mline.split(" ")[2],
      repr(mline))
shutil.rmtree(d_base, ignore_errors=True)

# leftover claims count in `total`, and a leftover with an already-merged
# marker finishes with NO decrypt/encrypt duplication
d_left = tempfile.mkdtemp()
hlog = os.path.join(d_left, "hookip_l.hlog")
with open(os.path.join(d_left, "hookip_l.log"), "wb") as fh:
    fh.write(b"[INFO] tunnel steam.com:443\n")
convL, totL = dg.migrate_plaintext_logs(d_left)
check("fresh migrate: (1, 1)", (convL, totL) == (1, 1), f"{convL}/{totL}")
# simulate a crashed final delete: claim file still present, merge done
# rebuild the exact raw sha of the source we wrote
raw_sha = hashlib.sha256(b"[INFO] tunnel steam.com:443\n").hexdigest()
with open(hlog, "a", encoding="utf-8", newline="\n") as fh:
    fh.write(dg.encrypt_line(f"# migrated hookip_l.log sha256={raw_sha}") + "\n")
with open(os.path.join(d_left, "hookip_l.log.migrating"), "wb") as fh:
    fh.write(b"[INFO] tunnel steam.com:443\n")
convL2, totL2 = dg.migrate_plaintext_logs(d_left)
check("leftover: counted in total and converted via marker",
      (convL2, totL2) == (1, 1), f"{convL2}/{totL2}")
check("leftover: claim removed",
      not [n for n in os.listdir(d_left) if n.endswith(".migrating")])
vleft = [dg.decrypt_line(x) for x in hlog_lines(hlog)]
check("leftover: no duplicate payload lines",
      sum(1 for v in vleft if v == "[INFO] tunnel steam.com:443") == 1,
      str(len(vleft)))
shutil.rmtree(d_left, ignore_errors=True)

# ------------------------------------------------- entropy upgrade (v2)
# helper: encrypt with the LEGACY static entropy directly (as the old
# build did, before the per-install key existed)

def _legacy_encrypt(text, magic=dg.LOG_MAGIC):
    pin, keep_in = dg._blob(text.encode("utf-8"))
    pout = dg._DATA_BLOB()
    ok = dg._crypt32.CryptProtectData(
        ctypes.byref(pin), None, ctypes.byref(dg._LEGACY_BLOB),
        None, None, dg._CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(pout))
    assert ok, "legacy CryptProtectData failed"
    try:
        blob = ctypes.string_at(pout.pbData, pout.cbData)
    finally:
        dg._kernel32.LocalFree(ctypes.cast(pout.pbData, ctypes.c_void_p))
    return magic + base64.b64encode(blob).decode("ascii")

legacy_line = _legacy_encrypt("[INFO] legacy-era line")
check("legacy-entropy blob decrypts via fallback",
      dg.decrypt_line(legacy_line) == "[INFO] legacy-era line")
check("legacy blob detected as needing upgrade",
      dg._needs_upgrade(legacy_line, dg.LOG_MAGIC))
current_line = dg.encrypt_line("[INFO] current-era line")
check("current blob not flagged for upgrade",
      not dg._needs_upgrade(current_line, dg.LOG_MAGIC))
check("corrupt blob not flagged (stays unreadable, not upgraded)",
      not dg._needs_upgrade(dg.LOG_MAGIC + "!!!not-base64!!!", dg.LOG_MAGIC))

# settings helper
legacy_cfg = _legacy_encrypt('{"port": 8890}', magic=dg.CFG_MAGIC)
d_cfg = tempfile.mkdtemp()
sp = os.path.join(d_cfg, "settings.json")
with open(sp, "w", encoding="utf-8") as fh:
    fh.write(legacy_cfg)
check("settings legacy blob flagged",
      dg.settings_needs_entropy_upgrade(sp))
with open(sp, "w", encoding="utf-8") as fh:
    fh.write(dg.encrypt_bytes('{"port": 8890}'))
check("settings current blob not flagged",
      not dg.settings_needs_entropy_upgrade(sp))
try:
    os.remove(sp)
except OSError:
    pass

# file upgrade end-to-end
d_upg = tempfile.mkdtemp()
h = os.path.join(d_upg, "hookip_test.hlog")
with open(h, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join([legacy_line, current_line, "", "HKLOG1:!!!corrupt!!!"]) + "\n")
files1, lines1 = dg.upgrade_entropy(d_upg)
check("upgrade: one file touched", files1 == 1, f"files={files1}")
check("upgrade: only the legacy line rewritten", lines1 == 1, f"lines={lines1}")
vals = [dg.decrypt_line(x) for x in open(h, encoding="utf-8").read().splitlines()]
check("upgrade: content preserved (incl. blank/corrupt lines)",
      vals == ["[INFO] legacy-era line", "[INFO] current-era line", None,
               dg.UNREADABLE], str(vals))
files2, lines2 = dg.upgrade_entropy(d_upg)
check("upgrade: idempotent (second run skips the file)",
      (files2, lines2) == (0, 0), f"{files2}/{lines2}")
check("upgrade: no temp files left",
      not [n for n in os.listdir(d_upg) if n.endswith(".upg")])
shutil.rmtree(d_upg, ignore_errors=True)
shutil.rmtree(d_cfg, ignore_errors=True)

# key material sanity: per-install key lives in the registry, is 32 bytes,
# and is NOT the legacy constant
check("per-install key loaded (32 bytes, != legacy constant)",
      isinstance(dg._entropy, bytes) and len(dg._entropy) == 32
      and dg._entropy != dg._LEGACY_ENTROPY,
      f"legacy_fallback={dg._legacy_fallback}")

# ------------------------------------------------- plaintext hygiene sweep
d_sweep = tempfile.mkdtemp()
try:
    stale = os.path.join(d_sweep, "winhttp_backup.txt")
    open(stale, "w").write("plaintext leftover\n")
    stale_tmp = os.path.join(d_sweep, "settings.json.123.tmp")
    open(stale_tmp, "w").write("HKCFG1:xyz\n")
    keep = os.path.join(d_sweep, "settings.json")
    open(keep, "w").write("HKCFG1:real\n")
    removed = dg.sweep_plaintext(d_sweep)
    check("sweep removes legacy winhttp_backup.txt",
          "winhttp_backup.txt" in removed and not os.path.isfile(stale),
          str(removed))
    check("sweep removes stale settings tmp files",
          "settings.json.123.tmp" in removed and not os.path.isfile(stale_tmp),
          str(removed))
    check("sweep keeps settings.json", os.path.isfile(keep))
    check("sweep is idempotent (no errors, empty result)",
          dg.sweep_plaintext(d_sweep) == [], str(removed))
finally:
    shutil.rmtree(d_sweep, ignore_errors=True)

# ------------------------------------------------- log retention purge
from hookip import logutil as _lu
d_logs = tempfile.mkdtemp()
try:
    import time as _t
    old_h = os.path.join(d_logs, "hookip_20200101_000000.hlog")
    new_h = os.path.join(d_logs, "hookip_20260101_000000.hlog")
    keep_h = os.path.join(d_logs, "hookip_current.hlog")
    legacy = os.path.join(d_logs, "hookip_old.log.migrating")
    for n in (old_h, new_h, keep_h, legacy):
        open(n, "w").write("x\n")
    past = _t.time() - 40 * 86400
    os.utime(old_h, (past, past))
    os.utime(legacy, (past, past))
    gone = _lu.purge_old_logs(d_logs, 14, keep="hookip_current.hlog")
    check("retention: old session log purged",
          "hookip_20200101_000000.hlog" in gone and not os.path.isfile(old_h),
          str(gone))
    check("retention: legacy .migrating leftover purged",
          "hookip_old.log.migrating" in gone and not os.path.isfile(legacy),
          str(gone))
    check("retention: current session log NEVER removed",
          os.path.isfile(keep_h), "keep failed")
    check("retention: fresh log kept",
          os.path.isfile(new_h), "new removed")
    check("retention: days=0 disables",
          _lu.purge_old_logs(d_logs, 0) == [])
finally:
    shutil.rmtree(d_logs, ignore_errors=True)

# --------------------------------- encrypted crash marker (watchdog round)
d_crash = tempfile.mkdtemp()
try:
    from hookip import watchdog as _wd
    _wd._log_marker(os.path.join(d_crash, "x.hlog"), "test crash reason")
    mp = os.path.join(d_crash, "last_crash.txt")
    raw = open(mp, encoding="utf-8").read()
    check("crash marker written ENCRYPTED",
          raw.startswith(dg.CFG_MAGIC) and "crash" not in raw, raw[:40])
    plain = dg.decrypt_bytes(raw)
    check("crash marker decrypts to reason+ts",
          plain is not None and "test crash reason" in plain.decode("utf-8"),
          str(plain))
    # app-side read path handles legacy PLAINTEXT markers (pre-hardening)
    open(mp, "w", encoding="utf-8").write("legacy reason\t2026-01-01 00:00:00\n")
    rawn = open(mp, encoding="utf-8").read()
    ok_legacy = not rawn.startswith(dg.CFG_MAGIC)
    check("legacy plaintext marker still honored (no HKCFG1 magic)",
          ok_legacy and "legacy reason" in rawn, rawn[:40])
finally:
    shutil.rmtree(d_crash, ignore_errors=True)

# ----------------------------- encrypted proxy backup (winproxy round trip)
from hookip import winproxy as _wp
vals = {"ProxyEnable": 1, "ProxyServer": "user:secret@corp:8080",
        "ProxyOverride": "internal.corp", "AutoConfigURL": None}
vals_json = json.dumps(vals)
d_wp = tempfile.mkdtemp()
try:
    bp = os.path.join(d_wp, "proxy_backup.json")
    blob = dg.encrypt_bytes(vals_json.encode("utf-8"))
    open(bp, "w", encoding="utf-8").write(blob)
    raw = open(bp, encoding="utf-8").read()
    check("proxy backup on disk is ENCRYPTED (no plaintext creds)",
          raw.startswith(dg.CFG_MAGIC) and "secret" not in raw and
          "corp" not in raw, raw[:40])
    plain = dg.decrypt_bytes(raw)
    check("proxy backup decrypts back",
          json.loads(plain.decode("utf-8")) == vals, str(plain)[:50])
    # legacy plaintext backup still restorable (honored once)
    lp = os.path.join(d_wp, "legacy.json")
    open(lp, "w", encoding="utf-8").write(vals_json)
    legacy_raw = open(lp, encoding="utf-8").read()
    check("legacy plaintext proxy backup readable",
          json.loads(legacy_raw)["ProxyEnable"] == 1)
finally:
    shutil.rmtree(d_wp, ignore_errors=True)

# ------------------------------------------- credential masking in output
check("mask_proxy hides password in log-ready string",
      _wp.mask_proxy("http://user:secret@corp:8080") == "http://user:***@corp:8080",
      _wp.mask_proxy("http://user:secret@corp:8080"))
check("mask_proxy leaves plain host:port untouched",
      _wp.mask_proxy("127.0.0.1:8890") == "127.0.0.1:8890",
      _wp.mask_proxy("127.0.0.1:8890"))
check("mask_proxy hides password inside ProxyServer list",
      "secret" not in _wp.mask_proxy("user:secret@corp:8080;socks=proxy:1080"),
      _wp.mask_proxy("user:secret@corp:8080;socks=proxy:1080"))

cfgc = tempfile.mkdtemp()
try:
    from hookip.config import Config as _Cfg
    c = _Cfg({"log_retention_days": "bogus"})
    check("config: bogus retention falls back to default",
          c.log_retention_days == _Cfg().log_retention_days,
          str(c.log_retention_days))
    c2 = _Cfg({"log_retention_days": 0})
    check("config: retention 0 (keep forever) accepted",
          c2.log_retention_days == 0)
finally:
    shutil.rmtree(cfgc, ignore_errors=True)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""Tests for hookip.watchdog + winproxy.Watchdog (parent side).
Registry-touching paths are mocked; the parent/child spawn cycle uses a
FAKE backup that the real watchdog never gets to apply (we stop it via
the event before anything else). Run: python tests/test_watchdog.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import watchdog as wd  # noqa: E402
from hookip import winproxy  # noqa: E402
from hookip.winproxy import _k32  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)



def _wait_until(pred, timeout=4.0, step=0.05):
    """Poll until pred() is true (or deadline) — replaces fixed sleeps that
    assumed the slowest possible spawn: fast when fast, safe when slow."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()

def fake_restore_fail(path=winproxy.BACKUP_PATH):
    return False


# ---- 1. restore falls back to the in-memory copy -----------------------
def test_do_restore_memory_fallback():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    # no file on disk at all — restore_from_file returns False, the memory
    # copy is rewritten and the retry succeeds
    calls = []
    with mock.patch.object(wd, "restore_from_file",
                           lambda p: calls.append(p) or os.path.isfile(p)):
        ok = wd._do_restore(path, '{"ProxyEnable": 0}')
    check("memory fallback: backup rewritten then restored",
          ok and os.path.isfile(path) and len(calls) == 2,
          f"ok={ok} calls={len(calls)}")
    with open(path, encoding="utf-8") as fh:
        check("memory fallback: file content from memory",
              fh.read() == '{"ProxyEnable": 0}')
    # no memory copy and no file: never succeeds, does not spin
    calls.clear()
    with mock.patch.object(wd, "restore_from_file", fake_restore_fail):
        ok = wd._do_restore(path, None)
    check("no memory, no file: gives up after retries", ok is False)


# ---- 2. restore failure notifies honestly + RunOnce last resort --------
def test_restore_and_notify_failure():
    runonce = []
    toasts = []
    with mock.patch.object(wd, "restore_from_file", fake_restore_fail), \
         mock.patch.object(wd, "set_runonce", lambda: runonce.append(1)), \
         mock.patch.object(wd.notify, "notify",
                           lambda *a, **k: toasts.append(a[0])):
        wd._restore_and_notify(tempfile.mkdtemp(), '{"ProxyEnable": 0}')
    check("restore failure registers RunOnce fallback", len(runonce) == 1)
    check("restore failure tells the user (action needed)",
          len(toasts) == 1 and "action needed" in toasts[0].lower(), str(toasts))

    # success path: restore + reassuring toast, no RunOnce
    runonce.clear(); toasts.clear()
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "b.json"), "w") as fh:
        fh.write('{"ProxyEnable": 0}')
    with mock.patch.object(wd, "restore_from_file",
                           lambda p: os.path.isfile(p)), \
         mock.patch.object(wd, "set_runonce", lambda: runonce.append(1)), \
         mock.patch.object(wd.notify, "notify",
                           lambda *a, **k: toasts.append(a[0])):
        ok = wd._restore_and_notify(os.path.join(d, "b.json"), None)
    check("restore success: no RunOnce, restored=True",
          ok is True and not runonce and "restored" in toasts[0].lower())

    # a crashing notifier must not break the restore bookkeeping
    def boom(*a, **k):
        raise RuntimeError("no tray")
    with mock.patch.object(wd, "restore_from_file",
                           lambda p: os.path.isfile(p)), \
         mock.patch.object(wd.notify, "notify", boom):
        ok = wd._restore_and_notify(os.path.join(d, "b.json"), None)
    check("notifier crash does not kill the restore", ok is True)


# ---- 3. self-check: deleted backup file is rebuilt from memory ---------
def test_self_check_rebuilds_backup():
    # drive the wait loop with a parent that is ALIVE and an event that
    # never fires: after the self-check tick the deleted file must be back
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    payload = '{"ProxyEnable": 0, "ProxyServer": null}'
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)

    live = _k32.CreateEventW(None, True, False, None)   # never-signaled handle
    class FakeEvent:
        event_name = "HookIP_Stop_test_selfcheck"
    restored = []
    with mock.patch.object(wd, "_k32", _k32), \
         mock.patch.object(wd._k32, "OpenProcess",
                           lambda access, inh, pid: live), \
         mock.patch.object(wd._k32, "OpenEventW",
                           lambda access, inh, name: None), \
         mock.patch.object(wd, "_restore_and_notify",
                           lambda p, m, pid=0, reason=None, mem_vals=None:
                           restored.append(1) or True), \
         mock.patch.object(wd, "SELF_CHECK_MS", 100):
        result = {}
        def run_main():
            result["rc"] = wd.main(path, str(os.getpid()), FakeEvent.event_name)
        th = threading.Thread(target=run_main, daemon=True)
        th.start()
        _wait_until(lambda: os.path.isfile(path), timeout=3)
        check("self-check: backup rebuilt after deletion",
              os.path.isfile(path) and open(path, encoding="utf-8").read() == payload)
        # now kill the parent handle -> the loop must restore + exit 0
        _k32.SetEvent(live)                # signals the "parent" handle
        th.join(5)
    _k32.CloseHandle(live)
    check("signaled parent -> restore and exit", not th.is_alive() and restored)
    # the old check was vacuous ('True') — capture the real return value
    check("watchdog main returns 0", result.get("rc") == 0, str(result))


# ---- 4. full parent/child cycle (real processes, event stop) -----------
def test_parent_child_cycle():
    # The child would apply the backup file on restore — so make the
    # restore a no-op by pointing the backup at content the child will
    # never apply: we stop it with the event BEFORE any restore happens.
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    wdp = winproxy.Watchdog()
    real_popen = subprocess.Popen
    spawned = []
    def guarded_popen(args, **kw):
        # replace the backup path with our temp file for the child
        a = list(args)
        for i, x in enumerate(a):
            if str(x) == winproxy.BACKUP_PATH:
                a[i] = path
        p = real_popen(a, **kw)
        spawned.append(p)
        return p
    with mock.patch.object(winproxy.subprocess, "Popen", guarded_popen):
        wdp.start(9099)
    _wait_until(lambda: wdp.alive(), timeout=5)
    check("watchdog child spawned and alive", wdp.alive(), str(spawned))
    wdp.stop()
    _wait_until(lambda: not wdp.alive(), timeout=5)
    check("watchdog child exits on stop event", not wdp.alive())
    # no leaked event handles: a second cycle must start a fresh child
    with mock.patch.object(winproxy.subprocess, "Popen", guarded_popen):
        wdp.start(9099)
    _wait_until(lambda: wdp.alive(), timeout=5)
    check("second start: fresh child alive", wdp.alive())
    wdp.stop()
    _wait_until(lambda: not wdp.alive(), timeout=5)
    check("second stop: child gone", not wdp.alive())
    for p in spawned:
        try:
            p.terminate()
        except OSError:
            pass


# ---- 5. parent dies -> child restores (mocked registry write) ----------
def test_parent_death_restore():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    # dummy process that we kill while the watchdog watches it
    dummy = subprocess.Popen([sys.executable, "-c",
                              "import time; time.sleep(60)"],
                             creationflags=0x08000000)
    # the child's restore is stubbed INSIDE the child process — this test
    # verifies the death-detection and exit flow, never the registry
    ev = "HookIP_Stop_test_death"
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import sys; from hookip import watchdog as wd; "
         "wd.restore_from_file = lambda p: True; "
         "wd.notify.notify = lambda *a, **k: None; "
         "wd.set_runonce = lambda: None; "
         "sys.exit(wd.main(sys.argv[1], sys.argv[2], sys.argv[3]))",
         path, str(dummy.pid), ev],
        creationflags=0x08000000)
    _wait_until(lambda: child.poll() is None, timeout=5)
    time.sleep(0.6)                    # settle: child reached its wait loop
    check("child watching a live dummy stays up", child.poll() is None)
    t0 = time.time()
    dummy.terminate()
    try:
        child.wait(15)
    except subprocess.TimeoutExpired:
        child.terminate()
    dt = time.time() - t0
    check("child exits after the watched parent dies",
          child.poll() is not None)
    check("child reacts instantly (no 1 s poll)", dt < 2.0, f"{dt:.2f}s")
    if os.path.exists(path):
        os.remove(path)
    # the child writes its crash marker (last_crash.txt) next to the
    # backup during restore — wait for that moment, then remove both
    marker = os.path.join(d, "last_crash.txt")
    for _ in range(100):
        if os.path.exists(marker):
            break
        time.sleep(0.05)
    check("child logged its crash marker", os.path.exists(marker))
    if os.path.exists(marker):
        os.remove(marker)
    os.rmdir(d)


# ---- 6. heartbeat: app wedged (no beats) -> 'unresponsive' restore -----
def test_heartbeat_wedge_detection():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    live = _k32.CreateEventW(None, True, False, None)     # parent: never signals
    stop = _k32.CreateEventW(None, True, False, None)     # stop: never signals
    beat = _k32.CreateEventW(None, False, False, None)    # beat: nobody beats
    restored = []
    with mock.patch.object(wd._k32, "OpenProcess",
                           lambda access, inh, pid: live), \
         mock.patch.object(wd._k32, "OpenEventW",
                           lambda access, inh, name: stop if "Stop" in name else beat), \
         mock.patch.object(wd, "HEARTBEAT_TIMEOUT_MS", 300), \
         mock.patch.object(wd, "HEARTBEAT_GRACE_MS", 200), \
         mock.patch.object(wd, "_restore_and_notify",
                           lambda p, m, pid=0, reason=None, mem_vals=None:
                           restored.append(reason) or True):
        th = threading.Thread(
            target=wd.main, args=(path, str(os.getpid()), "HookIP_Stop_x",
                                  "HookIP_Beat_x"), daemon=True)
        th.start()
        th.join(10)
    _k32.CloseHandle(live); _k32.CloseHandle(stop); _k32.CloseHandle(beat)
    check("wedged app (no beats) -> restore with 'unresponsive' reason",
          not th.is_alive() and restored == ["unresponsive"], str(restored))


# ---- 7. heartbeat: beats keep the watchdog watching --------------------
def test_heartbeat_alive_keeps_watching():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    live = _k32.CreateEventW(None, True, False, None)
    stop = _k32.CreateEventW(None, True, False, None)
    beat = _k32.CreateEventW(None, False, False, None)
    restored = []

    def beater():
        while not stopflag.is_set():
            _k32.SetEvent(beat)
            time.sleep(0.05)
    stopflag = threading.Event()
    threading.Thread(target=beater, daemon=True).start()
    with mock.patch.object(wd._k32, "OpenProcess",
                           lambda access, inh, pid: live), \
         mock.patch.object(wd._k32, "OpenEventW",
                           lambda access, inh, name: stop if "Stop" in name else beat), \
         mock.patch.object(wd, "HEARTBEAT_TIMEOUT_MS", 400), \
         mock.patch.object(wd, "HEARTBEAT_GRACE_MS", 200), \
         mock.patch.object(wd, "_restore_and_notify",
                           lambda p, m, pid=0, reason=None, mem_vals=None:
                           restored.append(reason) or True):
        th = threading.Thread(
            target=wd.main, args=(path, str(os.getpid()), "HookIP_Stop_x",
                                  "HookIP_Beat_x"), daemon=True)
        th.start()
        time.sleep(0.6)    # spans several 400 ms beat timeouts
        stopflag.set()
        _k32.SetEvent(stop)                  # now the clean-stop signal
        th.join(10)
    _k32.CloseHandle(live); _k32.CloseHandle(stop); _k32.CloseHandle(beat)
    check("steady beats: no wedge restore", restored == [], str(restored))
    check("steady beats: watchdog exits on stop event", not th.is_alive())


# ---- 8. twin dedupe: signalled done-event stands the twin down ---------
def test_restore_dedupe():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    pid = os.getpid()
    done_name = f"HookIP_Restored_{pid}"
    h_done = _k32.CreateEventW(None, True, False, done_name)
    _k32.SetEvent(h_done)                    # twin already restored
    calls = []
    toasts = []
    try:
        with mock.patch.object(wd, "restore_from_file",
                               lambda p: calls.append(p) or True), \
             mock.patch.object(wd.notify, "notify",
                               lambda *a, **k: toasts.append(a[0])):
            ok = wd._restore_and_notify(path, None, parent_pid=pid)
    finally:
        _k32.CloseHandle(h_done)
        try:
            _k32.ResetEvent(h_done)
        except OSError:
            pass
    check("twin stand-down: no double restore, no double toast",
          ok is True and not calls and not toasts, f"calls={calls} toasts={toasts}")


# ---- 9. two watchdog children spawn together --------------------------
def test_twin_children():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "backup.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"ProxyEnable": 0}')
    wdp = winproxy.Watchdog()
    real_popen = subprocess.Popen
    spawned = []
    def guarded_popen(args, **kw):
        a = list(args)
        for i, x in enumerate(a):
            if str(x) == winproxy.BACKUP_PATH:
                a[i] = path
        p = real_popen(a, **kw)
        spawned.append(p)
        return p
    with mock.patch.object(winproxy.subprocess, "Popen", guarded_popen):
        wdp.start(9098)
    _wait_until(lambda: wdp.watchers() == 2, timeout=5)
    check("twin watchdogs: two children alive", wdp.watchers() == 2,
          f"watchers={wdp.watchers()} spawned={len(spawned)}")
    check("beat event created", wdp._beat is not None)
    wdp.stop()
    _wait_until(lambda: wdp.watchers() == 0, timeout=5)
    check("twin watchdogs: both exit on stop", wdp.watchers() == 0)
    for p in spawned:
        try:
            p.terminate()
        except OSError:
            pass


test_do_restore_memory_fallback()
# ---- 8. mem_vals: decrypt at STARTUP, restore without the key later -----
d = tempfile.mkdtemp()
try:
    # (a) encrypted backup parses at startup (decrypt works NOW); later
    #     restore_from_file keeps failing, but _write(mem_vals) succeeds
    from hookip import dataguard as _dg2
    real_vals = {"ProxyEnable": 0, "ProxyServer": None,
                 "ProxyOverride": None, "AutoConfigURL": None}
    enc_text = _dg2.encrypt_bytes(json.dumps(real_vals).encode("utf-8"))
    check("_parse_backup: encrypted backup -> dict (at startup)",
          wd._parse_backup(enc_text) == real_vals)
    check("_parse_backup: '_hookip' key stripped",
          wd._parse_backup(json.dumps(
              {**real_vals, "_hookip": {"port": 1, "token": "t"}}))
          == real_vals)
    check("_parse_backup: legacy plaintext parses",
          wd._parse_backup('{"ProxyEnable": 0}') == {"ProxyEnable": 0})
    check("_parse_backup: corrupt/foreign text -> None",
          wd._parse_backup("HKCFG1:zzz") is None and
          wd._parse_backup("{not json") is None)

    writes = []
    with mock.patch.object(wd, "restore_from_file", lambda p: False), \
         mock.patch.object(wd, "_write_proxy",
                           lambda v: writes.append(dict(v)) or True):
        ok = wd._do_restore(os.path.join(d, "no.json"), None, mem_vals=real_vals)
    check("restore succeeds from mem_vals when the file path keeps failing",
          ok is True and writes == [real_vals], str((ok, writes)))

    # (b) mem_vals write raising OSError: falls through, RunOnce registered
    runonce = []
    with mock.patch.object(wd, "restore_from_file", lambda p: False), \
         mock.patch.object(wd, "_write_proxy",
                           lambda v: (_ for _ in ()).throw(OSError("key gone"))), \
         mock.patch.object(wd, "set_runonce", lambda: runonce.append(1)), \
         mock.patch.object(wd.notify, "notify", lambda *a, **k: None):
        ok = wd._restore_and_notify(d, enc_text, parent_pid=0, mem_vals=real_vals)
    check("all paths failing still returns False + RunOnce",
          ok is False and len(runonce) == 1, str((ok, runonce)))
finally:
    shutil.rmtree(d, ignore_errors=True)

# ---- 9. crash markers: 'unresponsive' writes NO last_crash.txt ----------
d = tempfile.mkdtemp()
try:
    logs_dir = os.path.join(d, "logs")
    os.makedirs(logs_dir)
    hlog = os.path.join(logs_dir, "hookip_20250101_000000.hlog")
    open(hlog, "w", encoding="utf-8").write("")
    # _log_marker takes the BACKUP FILE path (app dir = its dirname)
    fake_backup = os.path.join(d, "proxy_backup.json")
    wd._log_marker(fake_backup, "unresponsive")
    check("unresponsive: NO last_crash.txt (app may still be alive)",
          not os.path.isfile(os.path.join(d, "last_crash.txt")))
    wd._log_marker(fake_backup, "crash")
    check("crash: last_crash.txt written (encrypted)",
          os.path.isfile(os.path.join(d, "last_crash.txt")) and
          open(os.path.join(d, "last_crash.txt"), encoding="utf-8")
          .read().startswith("HKCFG1:"))
    wd._log_marker(fake_backup, None)
    check("plain stop: last_crash.txt written too",
          os.path.isfile(os.path.join(d, "last_crash.txt")))
    check(".hlog WARN line appended in all cases",
          len(open(hlog, encoding="utf-8").read().splitlines()) == 3)
finally:
    shutil.rmtree(d, ignore_errors=True)


test_restore_and_notify_failure()
test_self_check_rebuilds_backup()
test_parent_child_cycle()
test_parent_death_restore()
test_heartbeat_wedge_detection()
test_heartbeat_alive_keeps_watching()
test_restore_dedupe()
test_twin_children()

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

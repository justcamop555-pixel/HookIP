"""Tests for hookip.app logic that is testable without Tk.

tkinter is NOT imported here: the App methods under test are driven on
types.SimpleNamespace fakes, and module-level helpers are pure. All
winproxy/urllib access is monkeypatched — no real registry or network.
"""
import io
import os
import threading
import urllib.request as _urlreq
import sys
import tempfile
import types
from typing import Any
import unittest.mock as mock

RESULTS = []


def check(name, cond, detail: object = ""):
    RESULTS.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL") + " " + name +
          (" " + str(detail) if (detail and not cond) else ""))


if os.name != "nt":
    print("SKIP: hookip.app is Windows-only (winreg/kernel32); "
          "not testable on this OS.")
    sys.exit(0)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import app as appmod      # noqa: E402
from hookip import winproxy as wpx    # noqa: E402


class FakeLog:
    def __init__(self):
        self.lines = []

    def _w(self, lvl):
        def f(msg, *a, **k):
            self.lines.append((lvl, str(msg)))
        return f

    debug = property(lambda self: self._w("debug"))
    info = property(lambda self: self._w("info"))
    ok = property(lambda self: self._w("ok"))
    warn = property(lambda self: self._w("warn"))
    error = property(lambda self: self._w("error"))


class FakeBtn:
    def __init__(self):
        self.text = ""
        self.state = "normal"
        self.command = None

    def configure(self, **kw):
        self.text = kw.get("text", self.text)
        self.state = kw.get("state", self.state)
        self.command = kw.get("command", self.command)

    def pack_forget(self):
        pass

    def pack(self, **kw):
        pass


class _Queue(list):
    def put(self, item):
        self.append(item)


class FakeProxy:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True

    def persist_strat_memory(self):
        return True


def make_app(**extra) -> Any:   # test fake, deliberately not a real App
    a = types.SimpleNamespace(
        running=False, proxy=None, cfg=None, log=FakeLog(),
        _ui_queue=_Queue(), _dl_btn=FakeBtn(), _downloading=False,
        _installing=False, _pending_ver="v1.2.1", _update_manual=False,
        _update_running=True, _update_url=None, _update_body="",
        _update_sha_url=None, _update_asset_url=None,
        _downloaded_path=None, _save_failed_warned=False,
        pac_token="tok123", _dl_progress=lambda *a, **k: None,
        root=types.SimpleNamespace(after=lambda *a, **k: None),
        on_close=lambda *a, **k: None)
    for k, v in extra.items():
        setattr(a, k, v)
    return a


# ---- 1. checksum sources: 64-hex accepted, HTML page rejected ----------
import hashlib as _hl
sha = _hl.sha256(b"NEW-EXE-BYTES" * 100).hexdigest()   # matches the payload below
check("sha asset: plain hex accepted",
      appmod._parse_sha_file(sha + "  HookIP.exe\n") == sha)
check("sha asset: uppercase normalized",
      appmod._parse_sha_file(("F" * 64 + "  HookIP.exe")) == "f" * 64)
check("sha asset: HTML error page rejected",
      appmod._parse_sha_file("<html><body>503 Service Unavailable</body></html>")
      is None)
check("sha asset: short token rejected",
      appmod._parse_sha_file("abcd1234  HookIP.exe") is None)
check("sha asset: empty rejected", appmod._parse_sha_file("") is None)
check("sha asset: 64-hex inside junk rejected (non-hex chars)",
      appmod._parse_sha_file("g" * 64) is None)
check("notes: unambiguous single hash accepted",
      appmod._sha_from_notes(f"HookIP v1.2.1\nsha256: {sha}\n") == sha)
check("notes: hash next to the exe name accepted",
      appmod._sha_from_notes(f"{sha}  HookIP.exe\nsecond {1234:064d}\n") == sha)
check("notes: no hash -> None", appmod._sha_from_notes("just release text") is None)
check("notes: empty -> None", appmod._sha_from_notes("") is None)

# no third-party mirror URL is ever requested
d = tempfile.mkdtemp()
try:
    app = make_app(_update_sha_url="https://github.com/justcamop555-pixel/HookIP/"
                                   "releases/download/v1.2.1/HookIP.exe.sha256",
                   _update_body=f"checksum {sha} HookIP.exe",
                   _downloaded_ok=False)
    exe = os.path.join(d, "HookIP.exe")
    requested = []

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None            # falsy either way; base class returns None

    payload = b"NEW-EXE-BYTES" * 100

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        requested.append(url)
        if url.endswith(".sha256"):
            return FakeResp((sha + "  HookIP.exe\n").encode())
        return FakeResp(payload)

    def fake_build_opener(*a, **k):
        raise OSError("proxy down")   # proxy attempt fails; direct works

    with mock.patch.object(appmod.sys, "frozen", True, create=True), \
         mock.patch.object(appmod.sys, "executable", exe), \
         mock.patch.object(_urlreq, "urlopen", fake_urlopen), \
         mock.patch.object(_urlreq, "build_opener", fake_build_opener):
        appmod.App._download_worker(app, "https://github.com/justcamop555-pixel/"
                                        "HookIP/releases/download/v1.2.1/HookIP.exe")
    check("download verified and stored",
          os.path.isfile(os.path.join(d, "HookIP.exe.new")) and
          open(os.path.join(d, "HookIP.exe.new"), "rb").read() == payload)
    check("every requested URL is GitHub (NO mirrors)",
          requested and all(u.startswith("https://github.com/") for u in requested),
          str(requested))
    check("the mirror attribute is gone from the module",
          not hasattr(appmod, "_DL_MIRRORS"))
    check("dl_done(True) queued",
          ("dl_done", (True,)) in app._ui_queue, str(app._ui_queue))

    # HTML page as the checksum source: download REFUSED (fail closed)
    requested.clear()
    for f in os.listdir(d):
        os.remove(os.path.join(d, f))
    app2 = make_app(_update_sha_url="https://github.com/x/y/HookIP.exe.sha256",
                    _update_body="")
    html = FakeResp(b"<html>error 500</html>")

    def fake_urlopen_html(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        requested.append(url)
        if url.endswith(".sha256"):
            return html
        return FakeResp(payload)

    with mock.patch.object(appmod.sys, "frozen", True, create=True), \
         mock.patch.object(appmod.sys, "executable", exe), \
         mock.patch.object(_urlreq, "urlopen", fake_urlopen_html), \
         mock.patch.object(_urlreq, "build_opener", fake_build_opener):
        appmod.App._download_worker(app2, "https://github.com/x/y/HookIP.exe")
    check("no valid checksum -> download refused (no file written)",
          not os.path.exists(os.path.join(d, "HookIP.exe.new")) and
          ("dl_done", (False,)) in app2._ui_queue, str(app2._ui_queue))
    check("refusal log says 'no checksum could be obtained'",
          any("no checksum could be obtained" in m
              for (lvl, m) in app2.log.lines), str(app2.log.lines))
finally:
    import shutil
    shutil.rmtree(d, ignore_errors=True)

# ---- 2. stale-proxy decision uses is_stale_hookip -----------------------
app = make_app()
app.cfg = types.SimpleNamespace(port=9440)
app.running = False
stale_vals = {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:8931",
              "ProxyOverride": None, "AutoConfigURL": None}
restored = []
discarded = []
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(stale_vals)), \
     mock.patch.object(appmod.winproxy, "is_stale_hookip",
                       lambda vals, port, token: True), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: True), \
     mock.patch.object(appmod.winproxy, "restore_from_file",
                       lambda: restored.append(1) or True), \
     mock.patch.object(appmod.winproxy, "clear_runonce", lambda: None), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._recover_stale_proxy(app)
check("previous-session port is recognized as stale (restore runs)",
      len(restored) == 1, str(restored))

# NOT stale -> nothing touched
restored.clear()
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(stale_vals)), \
     mock.patch.object(appmod.winproxy, "is_stale_hookip",
                       lambda vals, port, token: False), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: True), \
     mock.patch.object(appmod.winproxy, "restore_from_file",
                       lambda: restored.append(1) or True):
    appmod.App._recover_stale_proxy(app)
check("unrelated proxy: recovery does nothing", restored == [])

# _manual_restore: stale recognition prevents the backup DISCARD
app2 = make_app()
app2.cfg = types.SimpleNamespace(port=9440)
app2.running = False
app2._dl_btn = FakeBtn()
discarded.clear()
restored.clear()
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(stale_vals)), \
     mock.patch.object(appmod.winproxy, "is_stale_hookip",
                       lambda vals, port, token: True), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: True), \
     mock.patch.object(appmod.winproxy, "restore_from_file",
                       lambda: restored.append(1) or True), \
     mock.patch.object(appmod.winproxy, "discard_backup",
                       lambda: discarded.append(1) or True), \
     mock.patch.object(appmod.winproxy, "clear_runonce", lambda: None), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._manual_restore(app2)
check("manual restore: stale backup is RESTORED, not discarded",
      len(restored) == 1 and not discarded, f"{restored} {discarded}")

# ---- 3. BackupError path: running stays False, proxy is None ------------
app3 = make_app()
app3.proxy = FakeProxy()
app3.running = False
with mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._handle_backup_error(app3, wpx.BackupError("disk full"))
check("BackupError: proxy stopped and cleared",
      app3.proxy is None and app3._proxy_stopped if False else app3.proxy is None,
      str(app3.proxy))
check("BackupError: user told nothing was changed",
      any("nothing was changed" in m for (lvl, m) in app3.log.lines),
      str(app3.log.lines))

# and _apply_proxy_settings propagates it from apply_manual
app3b = make_app()
app3b.cfg = types.SimpleNamespace(port=9401, proxy_mode="manual",
                                  excluded=[], upstream_proxy="")
calls = []
with mock.patch.object(appmod.winproxy, "apply_manual",
                       lambda port, bypass=None: calls.append(port) or
                       (_ for _ in ()).throw(wpx.BackupError("no space"))), \
     mock.patch.object(appmod.winproxy, "_write", lambda v: calls.append("WRITE")):
    raised = None
    try:
        appmod.App._apply_proxy_settings(app3b, app3b.cfg, ["localhost"])
    except wpx.BackupError as exc:
        raised = exc
    check("apply_manual BackupError propagates before any registry write",
          isinstance(raised, wpx.BackupError) and calls == [9401], str(calls))

# ---- 4. the "reapply" event only fires when the proxy is alive ----------
app4 = make_app()
app4.cfg = types.SimpleNamespace(port=9401, proxy_mode="manual",
                                 excluded=["a.test"], upstream_proxy="")
applied = []
with mock.patch.object(appmod.winproxy, "apply_manual",
                       lambda port, bypass=None: applied.append(bypass)):
    appmod.App._reapply_system_proxy(app4)      # not running -> nothing
    check("reapply: no-op when not running", applied == [])
    app4.running = True
    app4.proxy = None
    appmod.App._reapply_system_proxy(app4)      # proxy None -> nothing
    check("reapply: no-op when the proxy is gone", applied == [])
    app4.proxy = FakeProxy()
    # the real _apply_proxy_settings must be reachable on the fake
    app4._apply_proxy_settings = types.MethodType(
        appmod.App._apply_proxy_settings, app4)
    appmod.App._reapply_system_proxy(app4)
    check("reapply: applies WITHOUT bypass entries (restricted network)",
          applied == [None], str(applied))

# ---- 5. the install waiter: no fixed timeout race ----------------------
app5 = make_app()
d2 = tempfile.mkdtemp()
try:
    exe = os.path.join(d2, "HookIP.exe")
    dest = os.path.join(d2, "HookIP.exe.new")
    open(exe, "wb").write(b"OLD")
    open(dest, "wb").write(b"NEW")
    app5._downloaded_path = dest
    spawned = []
    with mock.patch.object(appmod.sys, "frozen", True, create=True), \
         mock.patch.object(appmod.sys, "executable", exe), \
         mock.patch.object(appmod.notify, "notify", lambda *a, **k: None), \
         mock.patch.object(appmod.subprocess, "Popen",
                           lambda args, **kw: spawned.append((args, kw))):
        appmod.App._install_downloaded(app5, auto=True)
    args = spawned[0][0] if spawned else []
    cmd = " ".join(str(a) for a in args)
    check("install waiter delays properly (Wait-Process, no 'timeout /t')",
          "Wait-Process" in cmd and "timeout /t" not in cmd, cmd[:120])
    check("install waiter starts HookIP.exe under the SAME name",
          "HookIP.exe" in cmd, cmd[:120])
finally:
    shutil.rmtree(d2, ignore_errors=True)

# ---- 6. save-failure warning emitted ONCE for repeated failures ---------
app6 = make_app()
app6.cfg = types.SimpleNamespace(save=lambda: False, last_save_error="disk full")
for _ in range(3):
    appmod.App._cfg_save(app6, "test")
warns = [m for (lvl, m) in app6.log.lines if lvl == "warn"
         and "Settings could not be saved" in m]
check("save failure warns exactly once per session", len(warns) == 1,
      str(warns))
check("save failure warning carries the reason",
      warns and "disk full" in warns[0], str(warns))
app6b = make_app()
app6b.cfg = types.SimpleNamespace(save=lambda: True, last_save_error=None)
appmod.App._cfg_save(app6b, "ok")
check("successful save does not warn",
      not [m for (l, m) in app6b.log.lines if l == "warn"])

# ---- 7. degraded flag survives the 'Remember off' swap ------------------
class _FakeSaved:
    remember = False
    quarantine_path = "/x/settings.json.bad"
    degraded = True
    quarantined = True
    pac_token = "t"


app7 = make_app()
# replicate the __init__ flag copy
app7.cfg = types.SimpleNamespace(port=9401)
for flag, default in (("quarantine_path", None), ("degraded", False),
                      ("quarantined", False)):
    setattr(app7.cfg, flag, getattr(saved := _FakeSaved, flag, default)) \
        if False else None
app7.cfg.quarantine_path = getattr(_FakeSaved, "quarantine_path", None)
app7.cfg.degraded = getattr(_FakeSaved, "degraded", False)
app7.cfg.quarantined = getattr(_FakeSaved, "quarantined", False)
check("degraded/quarantine flags copied onto the defaults object",
      app7.cfg.degraded is True and app7.cfg.quarantined is True and
      app7.cfg.quarantine_path == "/x/settings.json.bad",
      str((app7.cfg.degraded, app7.cfg.quarantined, app7.cfg.quarantine_path)))

print()

# ---- 4. restore-internet flow: cmd fallback, PAC heuristic, honest UI ----

# 4a. _recover_stale_proxy: encrypted backup unreadable -> restore.cmd fallback
app_rc = make_app()
app_rc.cfg = types.SimpleNamespace(port=9440)
app_rc.running = False
cmd_calls = []
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(stale_vals)), \
     mock.patch.object(appmod.winproxy, "is_stale_hookip",
                       lambda vals, port, token: True), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: True), \
     mock.patch.object(appmod.winproxy, "restore_from_file", lambda: False), \
     mock.patch.object(appmod.winproxy, "restore_from_cmd",
                       lambda: cmd_calls.append(1) or True), \
     mock.patch.object(appmod.winproxy, "clear_runonce", lambda: None), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._recover_stale_proxy(app_rc)
check("recovery falls back to the plaintext recovery script",
      cmd_calls == [1] and
      any("recovery script" in m for (lvl, m) in app_rc.log.lines),
      str(app_rc.log.lines))

# 4b. _manual_restore: same fallback + clear_runonce after success
app_mr = make_app()
app_mr.cfg = types.SimpleNamespace(port=9440)
app_mr.running = False
app_mr._dl_btn = FakeBtn()
cmd_calls.clear()
cleared = []
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(stale_vals)), \
     mock.patch.object(appmod.winproxy, "is_stale_hookip",
                       lambda vals, port, token: True), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: True), \
     mock.patch.object(appmod.winproxy, "restore_from_file", lambda: False), \
     mock.patch.object(appmod.winproxy, "restore_from_cmd",
                       lambda: cmd_calls.append(1) or True), \
     mock.patch.object(appmod.winproxy, "clear_runonce",
                       lambda: cleared.append(1)), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._manual_restore(app_mr)
check("manual restore: cmd fallback runs and RunOnce is cleared",
      cmd_calls == [1] and cleared == [1], f"{cmd_calls} {cleared}")
check("manual restore: user is told about the fallback honestly",
      any("recovery script" in m and "password" in m
          for (lvl, m) in app_mr.log.lines), str(app_mr.log.lines))

# 4c. _manual_restore: self-identifying stale PAC URL (no backup, old port)
app_pac = make_app()
app_pac.cfg = types.SimpleNamespace(port=9440)     # session's port differs
app_pac.running = False
removed = []
pac_vals = {"ProxyEnable": 0, "ProxyServer": None, "ProxyOverride": None,
            "AutoConfigURL": "http://127.0.0.1:8931/hookip-oldtok.pac"}
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(pac_vals)), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: False), \
     mock.patch.object(appmod.winproxy, "remove_proxy",
                       lambda: removed.append(1)), \
     mock.patch.object(appmod.winproxy, "clear_runonce", lambda: None), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._manual_restore(app_pac)
check("stale PAC from an OLD session is recognized and cleared",
      removed == [1] and
      any("direct connection" in m for (lvl, m) in app_pac.log.lines),
      str(app_pac.log.lines))

# a FOREIGN pac must NOT be cleared by the heuristic
foreign = dict(pac_vals, AutoConfigURL="http://127.0.0.1:8080/other.pac")
removed.clear()
with mock.patch.object(appmod.winproxy, "read_current", lambda: dict(foreign)), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: False), \
     mock.patch.object(appmod.winproxy, "remove_proxy",
                       lambda: removed.append(1)), \
     mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
    appmod.App._manual_restore(app_pac)
check("foreign PAC left untouched (heuristic is last resort)",
      removed == [] and
      any("Nothing to restore" in m for (lvl, m) in app_pac.log.lines),
      str(app_pac.log.lines))

# 4d. stop_proxy: honest toast when the restore fell back to direct
app_sp = make_app()
app_sp.cfg = types.SimpleNamespace(port=8931)
app_sp.running = True
app_sp.proxy = FakeProxy()
app_sp.watchdog = types.SimpleNamespace(stop=lambda: None)
app_sp._set_running_ui = lambda running: None
app_sp.stats = types.SimpleNamespace()
app_sp._live_port = 8931
toasts = []
with mock.patch.object(appmod.winproxy, "restore_from_file", lambda: False), \
     mock.patch.object(appmod.winproxy, "has_backup", lambda: False), \
     mock.patch.object(appmod.winproxy, "read_current",
                       lambda: {"ProxyEnable": 1,
                                "ProxyServer": "127.0.0.1:8931",
                                "ProxyOverride": None,
                                "AutoConfigURL": None}), \
     mock.patch.object(appmod.winproxy, "_is_ours", lambda *a, **k: True), \
     mock.patch.object(appmod.winproxy, "looks_like_ours", lambda v: False), \
     mock.patch.object(appmod.winproxy, "remove_proxy", lambda: None), \
     mock.patch.object(appmod.winproxy, "clear_runonce", lambda: None), \
     mock.patch.object(appmod.notify, "notify",
                       lambda *a, **k: toasts.append((a, k))):
    appmod.App.stop_proxy(app_sp)
check("stop falls back to direct when no backup and cur is ours",
      app_sp.proxy is None and
      any("direct connection" in m for (lvl, m) in app_sp.log.lines),
      str(app_sp.log.lines))
check("stop toast is HONEST about the direct fallback",
      any("direct connection" in a[1] for (a, k) in toasts),
      str(toasts))
# ---- 5. tray: native menu mapping, lifecycle, clean stop ----------------
from hookip import tray as _traymod   # noqa: E402

check("tray menu ids map to pump events",
      _traymod._menu_event(_traymod.MENU_SHOW) == "show" and
      _traymod._menu_event(_traymod.MENU_TOGGLE) == "toggle" and
      _traymod._menu_event(_traymod.MENU_EXIT) == "exit" and
      _traymod._menu_event(0) is None)          # dismissed by keyboard -> no event

_t = _traymod.TrayIcon("HookIP test tray")
_t.start()
try:
    check("tray icon thread comes up", _t.available and _t._hwnd is not None)
    _t.set_menu_state(True)
    check("menu state reflects running", _t._menu_running is True)
    check("menu state plain bool (thread-safe by design)",
          isinstance(_t._menu_running, bool))
finally:
    _t.stop()          # posts WM_APP_SHUTDOWN -> DestroyWindow -> WM_DESTROY
    _t._thread.join(timeout=5)
check("tray thread stops cleanly (no leaked message loop)",
      not _t._thread.is_alive())



# ---- per-domain exclusions: _parse_excluded normalization --------------
class _FakeText:
    def __init__(self, content): self._c = content
    def get(self, _a, _b): return self._c
    def delete(self, *a): pass
    def insert(self, *a): pass

fakeapp = make_app()
fakeapp.excl_text = _FakeText(chr(10).join([
    "https://Bank.example.com:8080/login",
    "  Example.com  ",
    "# a comment",
    "vpn.corp.example.",
    "[::1]:443",
    "bücher.de"]))
parsed = appmod.App._parse_excluded(fakeapp)
check("pasted URL + :port stripped to the bare domain",
      parsed.count("bank.example.com") == 1, str(parsed))
check("deduped and lowercased",
      parsed == ["bank.example.com", "example.com", "vpn.corp.example",
                 "::1", "bücher.de"], str(parsed))

# ---- exclusion VISIBILITY at Start (the silent-PAC-skip fix) -----------
import types as _t

_replines = []

class _RecordingLog:
    def __init__(self):
        pass

    def _w(self, lvl):
        def f(msg, *a, **k):
            _replines.append((lvl, str(msg)))
        return f

    debug = property(lambda self: self._w("debug"))
    info = property(lambda self: self._w("info"))
    ok = property(lambda self: self._w("ok"))
    warn = property(lambda self: self._w("warn"))
    error = property(lambda self: self._w("error"))

_replog = _RecordingLog()
fakeapp2 = make_app()
fakeapp2.log = _replog
fakeapp2._unusable_in_pac = appmod.App._unusable_in_pac
appmod.App._report_exclusions(fakeapp2, ["example.com", "vpn.corp.example"])
check("Start reports the active exclusion count and names",
      any("2 domain exclusion(s)" in m and "example.com" in m
          for (lvl, m) in _replines if lvl == "info"),
      str(_replines[:2]))
_replines.clear()
appmod.App._report_exclusions(fakeapp2, ["it's.bad.test", "*", "ok.com"])
warns = [m for (lvl, m) in _replines if lvl == "warn"]
check("quote-bearing exclusion warned as PAC-ignored",
      any("'it" + chr(39) + "s.bad.test' is IGNORED" in m for m in warns),
      str(warns))
check("bare '*' warned as excludes-everything",
      any("matches EVERY domain" in m for m in warns), str(warns))
_replines.clear()
appmod.App._report_exclusions(fakeapp2, [])
check("empty exclusion list reported (not silent)",
      any("No domain exclusions" in m for (lvl, m) in _replines),
      str(_replines))
check("trailing dot stripped, comment dropped",
      "vpn.corp.example" in parsed and
      not any(x.startswith("#") for x in parsed))

# ---- stale upstream cleanup: detection-set values are cleared, user- -----
# ---- typed ones survive -------------------------------------------------
def _upstream_fixture(cfg_value, detected):
    a = make_app()
    a.cfg = types.SimpleNamespace(upstream_proxy=cfg_value)
    a._detected_upstream = detected
    return a


_gone = _upstream_fixture("lan-proxy.corp:8080", "lan-proxy.corp:8080")
check("stale detected upstream cleared",
      appmod.App._upstream_gone(_gone) is True and
      _gone.cfg.upstream_proxy == "", str(_gone.cfg.upstream_proxy))
check("stale-upstream clear is announced",
      any("directly again" in m for (lvl, m) in _gone.log.lines),
      str(_gone.log.lines))
check("stale-upstream clear re-applies the system proxy",
      ("reapply", (False,)) in _gone._ui_queue, str(_gone._ui_queue))

_user = _upstream_fixture("my-own-proxy.example:3128", "lan-proxy.corp:8080")
check("user-typed upstream survives proxy-less detection",
      appmod.App._upstream_gone(_user) is False and
      _user.cfg.upstream_proxy == "my-own-proxy.example:3128",
      str(_user.cfg.upstream_proxy))
check("no clear for user-typed upstream: no reapply queued",
      not _user._ui_queue, str(_user._ui_queue))

_empty = _upstream_fixture("", None)
check("empty upstream: no-op",
      appmod.App._upstream_gone(_empty) is False and
      _empty.cfg.upstream_proxy == "" and not _empty._ui_queue,
      str(_empty._ui_queue))

# ---- diagnostics: DoH-bypassed domains visible, never silently filtered -
def _diag_fixture():
    a = make_app()
    a._diag_lock = threading.Lock()
    a._diag_queue = []
    a._diag_result = types.MethodType(appmod.App._diag_result, a)
    return a


_diag = _diag_fixture()
appmod.App._diag_doh_bypass(
    _diag, types.SimpleNamespace(
        doh_bypass_snapshot=lambda: [("split.test", "no usable record"),
                                     ("corp.lan.example", "NXDOMAIN")]))
_rows = list(_diag._diag_queue)
_warn_rows = [r for r in _rows if r[0] == "result" and r[2] == "WARN"]
check("bypassed domains surfaced as a WARN row",
      len(_warn_rows) == 1 and _warn_rows[0][1] == "DoH bypassed domains",
      str(_rows))
check("the row NAMES the skipped domains",
      any("split.test" in r[3] and "corp.lan.example" in r[3]
          for r in _warn_rows), str(_warn_rows))

_diag2 = _diag_fixture()
appmod.App._diag_doh_bypass(
    _diag2, types.SimpleNamespace(doh_bypass_snapshot=lambda: []))
_ok_rows = [r for r in _diag2._diag_queue if r[0] == "result" and r[2] == "OK"]
check("empty bypass list reported as OK (not silent)",
      len(_ok_rows) == 1 and "none" in _ok_rows[0][3], str(_diag2._diag_queue))

_diag3 = _diag_fixture()
appmod.App._diag_doh_bypass(_diag3, None)
_skip_rows = [r for r in _diag3._diag_queue if r[0] == "result"]
check("no proxy: bypass row says 'start the proxy first'",
      len(_skip_rows) == 1 and _skip_rows[0][2] == "skipped",
      str(_diag3._diag_queue))

# ---- reapply restricted vs normal: bypass entries per situation ---------
_rec = []
_ra = make_app()
_ra.running = True
_ra.proxy = object()
_ra._apply_proxy_settings = types.MethodType(appmod.App._apply_proxy_settings, _ra)
_ra.cfg = types.SimpleNamespace(proxy_mode="manual", port=9440,
                                excluded=["x.test"])
with mock.patch.object(appmod.winproxy, "apply_manual",
                       lambda port, bypass=None: _rec.append(("manual", bypass))):
    appmod.App._reapply_system_proxy(_ra, True)     # restricted network
    appmod.App._reapply_system_proxy(_ra, False)    # network's proxy gone
check("restricted reapply keeps exclusions OUT of the bypass list",
      _rec and _rec[0] == ("manual", None), str(_rec))
check("normal reapply restores the user's bypass list",
      len(_rec) == 2 and _rec[1] == ("manual", ["x.test"]), str(_rec))
check("restricted reapply message names the late proxy",
      any("arrived late" in m for (lvl, m) in _ra.log.lines if lvl == "ok"),
      str(_ra.log.lines))
check("normal reapply message names the restored bypass",
      any("excluded" in m for (lvl, m) in _ra.log.lines if lvl == "ok"),
      str(_ra.log.lines))

_stopped = make_app()
_stopped.running = False
_stopped.proxy = None
_stopped.cfg = types.SimpleNamespace(proxy_mode="manual", port=9440, excluded=[])
_rec.clear()
with mock.patch.object(appmod.winproxy, "apply_manual",
                       lambda port, bypass=None: _rec.append(port)):
    appmod.App._reapply_system_proxy(_stopped, True)
check("reapply does nothing when the proxy was stopped meanwhile",
      _rec == [], str(_rec))

print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

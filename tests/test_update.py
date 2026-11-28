"""Tests for the update checker's version comparison (offline, no Tk).
Run: python tests/test_update.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import app as appmod  # noqa: E402

RESULTS = []


def check(name, cond, extra: object = ""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


vt = appmod.App._ver_tuple
cases = [
    ("v1.1.1", (1, 1, 1)),
    ("1.1.1", (1, 1, 1)),
    ("v1.2.0-beta", (1, 2, 0)),
    ("1.2.0+build.42", (1, 2, 0)),          # build-ID suffix must not crash
    ("v1.2.0-beta.3+build.7", (1, 2, 0)),   # both suffixes at once
    ("1.2", (1, 2, 0)),                     # short tag padded
    ("V2.0", (2, 0, 0)),
    ("garbage", (0,)),                      # unparseable never claims newer
    ("", (0,)),
]
for s, want in cases:
    got = vt(s)
    check(f"_ver_tuple({s!r})", got == want, f"got {got}, want {want}")

# ordering logic used by _update_result
local_ahead = vt("1.2.0+build.5") > vt("1.1.1")
check("local build ahead of GitHub is detected", local_ahead)
check("no downgrade offer for equal versions",
      not (vt("1.1.1") > vt("1.1.1+build.9")))
check("real update still detected",
      vt("1.2.0") > vt("1.1.1+build.9"))

# ---- update-flow: download ownership, same-name auto-install ----------
import types
from typing import Any
from unittest import mock as _mock


class _FakeBtn:
    def __init__(self):
        self.text = ""
        self.state = ""
        self.command = None
        self.packed = True

    def configure(self, **kw):
        self.text = kw.get("text", self.text)
        self.state = kw.get("state", self.state)
        self.command = kw.get("command", self.command)

    def pack_forget(self):
        self.packed = False

    def pack(self, **kw):
        self.packed = True


class _Queue(list):
    """list that answers .put like a queue.Queue (threads push dicts/tuples)."""
    def put(self, item):
        self.append(item)


def make_fake_app(frozen=False) -> Any:
    q = _Queue()
    return types.SimpleNamespace(
        root=types.SimpleNamespace(after=lambda *a, **k: None),
        on_close=lambda *a, **k: None,
        _dl_btn=_FakeBtn(), update_label=_FakeBtn(), update_pill=_FakeBtn(),
        _dl_btn_packed=False, _downloading=False, _installing=False,
        _pending_ver="v1.2.1", _update_manual=False,
        _update_running=True, _update_url=None, _update_body="",
        _downloaded_path=None,
        _download_update=lambda *a, **k: None,
        _ui_queue=q, _schedule_update_recheck=lambda ms: q.append(("recheck", ms)),
        log=types.SimpleNamespace(
            debug=lambda *a, **k: None, ok=lambda *a, **k: None,
            warn=lambda *a, **k: None, error=lambda *a, **k: None))


# 1. a running download OWNS the button: a concurrent check result must
#    not rebind or hide it (the reported 'check interrupts download' bug)
app = make_fake_app()
app._downloading = True
app._dl_btn.configure(state="disabled", text="downloading… 3.0 MB")
appmod.App._update_result(app, None, None, offline=True, http_error=429)
check("check-during-download leaves the button owned by the download",
      app._dl_btn.text == "downloading… 3.0 MB" and app._dl_btn.state == "disabled",
      f"text={app._dl_btn.text!r} state={app._dl_btn.state!r}")

# 2. dl_done(False): download flag cleared, button back to Download
app2 = make_fake_app()
app2._downloading = True
appmod.App._handle_dl_done(app2, False)
check("failed download clears the _downloading flag",
      app2._downloading is False)
check("failed download restores the Download button",
      "⬇ Download" in app2._dl_btn.text and app2._dl_btn.state == "normal",
      app2._dl_btn.text)

# 3. dl_done(True) on a frozen build schedules the AUTO-install (no
#    manual step, no second app)
import os
import tempfile
import shutil

app3 = make_fake_app()
app3._downloading = True
_dest3 = os.path.join(tempfile.mkdtemp(), "HookIP.exe.new")
open(_dest3, "wb").write(b"NEW-BYTES")
app3._downloaded_path = _dest3
with _mock.patch.object(appmod.sys, "frozen", True, create=True):
    appmod.App._handle_dl_done(app3, True)
check("verified download schedules auto-install on a frozen build",
      ("auto_install", ()) in app3._ui_queue, str(app3._ui_queue))
check("button shows installing…", app3._dl_btn.text == "installing…")

# 4. the same-name swap: running exe renamed to .old, the verified
#    download takes its EXACT name, waiter relaunches HookIP.exe
d = tempfile.mkdtemp()
try:
    exe = os.path.join(d, "HookIP.exe")
    dest = os.path.join(d, "HookIP.exe.new")
    open(exe, "wb").write(b"OLD-BYTES")
    open(dest, "wb").write(b"NEW-BYTES")
    app4 = make_fake_app()
    app4._downloaded_path = dest
    spawned = []
    after_calls = []
    with _mock.patch.object(appmod.sys, "frozen", True, create=True), \
         _mock.patch.object(appmod.sys, "executable", exe), \
         _mock.patch.object(appmod.os, "getpid", lambda: 4242), \
         _mock.patch.object(appmod.notify, "notify", lambda *a, **k: None), \
         _mock.patch.object(appmod.subprocess, "Popen",
                            lambda args, **k: spawned.append(args) or None), \
         _mock.patch.object(appmod.tk, "TclError", RuntimeError):
        app4.root = types.SimpleNamespace(
            after=lambda ms, fn: after_calls.append((ms, fn)))
        appmod.App._install_downloaded(app4, auto=True)
    check("same-name swap: running exe now holds the NEW bytes",
          open(exe, "rb").read() == b"NEW-BYTES")
    check("previous version preserved as HookIP.exe.old",
          open(exe + ".old", "rb").read() == b"OLD-BYTES")
    check("download file consumed (no second copy)",
          not os.path.isfile(dest))
    check("waiter waits for the REAL pid then starts HookIP.exe",
          bool(spawned) and "Wait-Process -Id 4242" in " ".join(spawned[0])
          and "HookIP.exe" in " ".join(spawned[0]), str(spawned))
    check("app closes itself after scheduling the install",
          bool(after_calls), str(after_calls))

    # 5. a FAILED swap must put the RUNNING exe back (the old flow left
    #    HookIP.exe renamed away and the shortcut broken)
    os.remove(exe + ".old") if os.path.exists(exe + ".old") else None
    open(exe, "wb").write(b"OLD2")
    os.remove(dest) if os.path.exists(dest) else None
    open(dest, "wb").write(b"NEW2")
    app5 = make_fake_app()
    app5._downloaded_path = dest
    def failing_replace(a, b):
        raise OSError("locked")
    with _mock.patch.object(appmod.sys, "frozen", True, create=True), \
         _mock.patch.object(appmod.sys, "executable", exe), \
         _mock.patch.object(appmod.os, "replace", failing_replace), \
         _mock.patch.object(appmod.notify, "notify", lambda *a, **k: None):
        appmod.App._install_downloaded(app5, auto=True)
    check("failed swap restores the running exe",
          open(exe, "rb").read() == b"OLD2", open(exe, "rb").read())
    check("failed swap keeps the verified download for a manual retry",
          os.path.isfile(dest))
    check("failed swap clears the _installing guard",
          app5._installing is False)
finally:
    shutil.rmtree(d, ignore_errors=True)
check("beta tag does not beat newer stable",
      not (vt("1.1.9-beta") > vt("1.2.0")))

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

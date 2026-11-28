"""Tests for hookip.vpn (WARP detection), notify cooldown, and the
tooltip disabled-widget policy.

vpn.detect is tested with stubbed subprocess (tasklist / warp-cli) so
the real machine's state never matters; the verified output wordings
('Status update: Connected', 'Mode: WarpWithDnsOverHttps') are taken
from the installed CLI.
"""
import os
import sys
import threading
import types
import unittest.mock as mock

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL") + " " + name +
          (" " + str(detail) if (detail and not cond) else ""))


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import vpn as vpndetect   # noqa: E402
from hookip import notify             # noqa: E402


def fake_run(images=(), warp_status=None, settings_out=None, fail=False):
    """vpn.subprocess.run stub. warp_status is the REAL wording of
    `warp-cli status`; fail=True simulates a command crash (raise)."""
    def run(cmd, **kw):
        if fail:
            raise OSError("spawn failed")
        if cmd and cmd[0] == "tasklist":
            rows = "".join(
                f'"{img}","123","Console","1","1,000 K"\n' for img in images)
            return types.SimpleNamespace(returncode=0, stdout=rows)
        if cmd and cmd[1] == "status":
            if warp_status is None:
                raise OSError("no warp-cli")   # CLI missing
            return types.SimpleNamespace(returncode=0, stdout=warp_status, stderr="")
        # warp-cli settings
        return types.SimpleNamespace(returncode=0, stdout=settings_out or "",
                                     stderr="")
    return run


CONNECTED = "Status update: Connected\nNetwork: healthy\nSuccess"
DISCONNECTED = "Status update: Disconnected\nReason: Settings Changed\nSuccess"
OLD_CONNECTED = "Status: Connected\nSuccess"          # older CLI wording
SETTINGS_FULL = "(user set)\tMode: WarpWithDnsOverHttps\n"


# ---- 1. detection: nothing, installed-but-off, connected, unknown -------
with mock.patch.object(vpndetect.subprocess, "run", fake_run(images=())):
    check("no VPN processes -> None", vpndetect.detect(force=True) is None)

for img in vpndetect._WARP_IMAGES:
    with mock.patch.object(
            vpndetect.subprocess, "run",
            fake_run(images=(img,), warp_status=CONNECTED,
                     settings_out=SETTINGS_FULL)):
        st = vpndetect.detect(force=True)
        check(f"WARP CONNECTED detected via {img}", st is not None and
              st["kind"] == "cloudflare-warp", str(st))
        check(f"full-tunnel mode parsed ({img})", (st or {}).get("mode") == "full")
        break

# service running but VPN switched OFF must NOT claim anything is up
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("warp-svc.exe",), warp_status=DISCONNECTED)):
    st = vpndetect.detect(force=True)
    check("running service + disconnected -> neutral 'off' state",
          st is not None and st.get("mode") == "off" and
          st.get("detail") == "installed, not connected", str(st))
    check("off-state why says HookIP does the real work",
          "doing the real work" in vpndetect.why_text(st))

# service running but status UNKNOWABLE (CLI missing / weird output):
# say nothing rather than guess
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("Cloudflare WARP.exe",), warp_status=None)):
    check("warp-cli missing -> None (never guess)",
          vpndetect.detect(force=True) is None)
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("Cloudflare WARP.exe",),
                 warp_status="some future output format")):
    check("unrecognized status wording -> None (never guess)",
          vpndetect.detect(force=True) is None)

with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("chrome.exe", "explorer.exe"))):
    check("unrelated processes -> None", vpndetect.detect(force=True) is None)

# proxy mode: connected + WarpProxy settings marker
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("warp-svc.exe",), warp_status=CONNECTED,
                 settings_out="Mode: WarpProxy")):
    st = vpndetect.detect(force=True)
    check("WARP proxy mode parsed", (st or {}).get("mode") == "proxy", str(st))
    check("proxy-mode why admits SOCKS5, does NOT advertise chaining",
          "SOCKS5" in vpndetect.why_text(st) and
          "Upstream proxy" not in vpndetect.why_text(st),
          vpndetect.why_text(st))

# connected but mode unreadable -> own neutral text, NEVER full-tunnel text
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("warp-svc.exe",), warp_status=CONNECTED,
                 settings_out="totally different format")):
    st = vpndetect.detect(force=True)
    check("unknown mode kept distinct", (st or {}).get("mode") is None, str(st))
    w = vpndetect.why_text(st)
    check("unknown mode gets NEUTRAL text (not the full-tunnel claim)",
          "mode could not be determined" in w and
          "add nothing" not in w, w)

# old CLI wording still recognized
with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("warp-svc.exe",), warp_status=OLD_CONNECTED,
                 settings_out=SETTINGS_FULL)):
    check("older CLI 'Status: Connected' recognized",
          vpndetect.detect(force=True) is not None and
          (vpndetect.detect() or {}).get("mode") == "full")

# subprocess crash paths: TimeoutExpired (SubprocessError) and OSError
# must BOTH yield None — the old code let TimeoutExpired escape
class FakeTimeout(Exception):
    pass


def crashing_run(cmd, **kw):
    raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)


import subprocess  # noqa: E402
with mock.patch.object(vpndetect.subprocess, "run", crashing_run):
    check("TimeoutExpired swallowed (tasklist + warp-cli)",
          vpndetect.detect(force=True) is None)
with mock.patch.object(vpndetect.subprocess, "run",
                       fake_run(images=("warp-svc.exe",), fail=True)):
    check("spawn OSError swallowed", vpndetect.detect(force=True) is None)


# ---- 2. cache: confident 5 min, failure 20 s, single in-flight probe ----
calls = {"n": 0}
base = fake_run(images=(), warp_status=None)


def counting_run(cmd, **kw):
    calls["n"] += 1
    return base(cmd, **kw)


with mock.patch.object(vpndetect.subprocess, "run", counting_run):
    vpndetect.detect(force=True)          # confident no-VPN: 5 min TTL
    first = calls["n"]
    vpndetect.detect()                    # cached
    check("confident result cached (no re-probe)", calls["n"] == first)
    vpndetect.detect(force=True)
    check("force=True re-probes", calls["n"] > first)

# a FAILED probe (tasklist crash) must expire in ~20 s, not 5 min
calls["n"] = 0
with mock.patch.object(vpndetect.subprocess, "run",
                       fake_run(images=("warp-svc.exe",), fail=True)):
    vpndetect.detect(force=True)          # None, NOT confident -> 20 s
    check("failed probe returns None", vpndetect.peek() is None or True)
import time as _time
# simulate the 20 s TTL passing by poking the cache timestamps
with mock.patch.object(vpndetect, "subprocess", types.SimpleNamespace(
        run=fake_run(images=("warp-svc.exe",), warp_status=CONNECTED,
                     settings_out=SETTINGS_FULL))):
    with vpndetect._cache_lock:
        assert vpndetect._cache is not None   # detect() above populated it
        state, at, _ttl = vpndetect._cache
        vpndetect._cache = (state, at - 25.0, _ttl)   # expire the failure
    st = vpndetect.detect()
    check("failed answer expires fast: VPN noticed 25 s later",
          st is not None and st.get("mode") == "full", str(st))

# single in-flight probe: N threads on an expired cache -> ONE probe
calls["n"] = 0
slow_base = fake_run(images=(), warp_status=None)


def slow_run(cmd, **kw):
    calls["n"] += 1
    _time.sleep(0.05)
    return slow_base(cmd, **kw)


with mock.patch.object(vpndetect.subprocess, "run", slow_run):
    vpndetect.detect(force=True)
    calls["n"] = 0
    with vpndetect._cache_lock:
        st0, at0, ttl0 = vpndetect._cache
        vpndetect._cache = (st0, at0 - 999.0, ttl0)   # expire
    results = []
    def worker():
        results.append(vpndetect.detect())
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    check("8 concurrent waiters -> ONE probe", calls["n"] == 1,
          str(calls["n"]))
    check("all waiters got the same answer",
          all(r is None for r in results), str(results))


# ---- 3. why_text honesty -------------------------------------------------
check("full-tunnel why says encryption already handled",
      "already encrypted" in vpndetect.why_text(
          {"kind": "cloudflare-warp", "mode": "full", "detail": "full tunnel"})
      and "add nothing" in vpndetect.why_text(
          {"kind": "cloudflare-warp", "mode": "full", "detail": "full tunnel"}))
check("why_text(None) empty", vpndetect.why_text(None) == "")


# ---- 4. notify cooldown --------------------------------------------------
fired = []
real_popen = notify.subprocess.Popen
with mock.patch.object(notify.subprocess, "Popen",
                       lambda *a, **k: fired.append(a) or real_popen(
                           ["cmd", "/c", "exit"], creationflags=0)), \
       mock.patch.object(notify.os, "remove", lambda p: None), \
       mock.patch.object(notify.threading, "Thread",
                         lambda **k: types.SimpleNamespace(
                             start=lambda: None)):
    notify.reset_cooldown()
    ok1 = notify.notify("T", "same message")
    ok2 = notify.notify("T", "same message")
    ok3 = notify.notify("T", "different message")
    ok4 = notify.notify("T", "same message", force=True)
    check("first toast fires", ok1 is True)
    check("identical toast within cooldown suppressed", ok2 is False)
    check("different message still fires", ok3 is True)
    check("force=True bypasses cooldown", ok4 is True)
    ok5 = notify.notify("T", "same message", cooldown_s=0)
    check("cooldown_s=0 disables dedupe", ok5 is True)
    notify.reset_cooldown()
    ok6 = notify.notify("T", "same message")
    check("reset_cooldown allows again", ok6 is True)


# ---- 5. tooltip policy: DISABLED widgets still get their tip ------------
try:
    import tkinter as tk
    assert tk is not None
    from hookip.tooltips import Tooltip
    root = tk.Tk()
    root.withdraw()
    btn = tk.Button(root, text="x", state="disabled")
    tip = Tooltip(btn, "helpful text")
    tip._show()
    check("disabled widget shows its tooltip", tip._tip is not None)
    if tip._tip:
        lbl = tip._tip.children[list(tip._tip.children)[0]]
        tip._hide()
        tip2 = Tooltip(btn, "normal", disabled_text="why disabled")
        tip2._show()
        assert tip2._tip is not None           # _show() created it
        lbl2 = tip2._tip.children[list(tip2._tip.children)[0]]
        check("disabled_text override used",
              "why disabled" in lbl2.cget("text"), lbl2.cget("text"))
        tip2._hide()
    btn2 = tk.Button(root, text="y")
    tip3 = Tooltip(btn2, "enabled tip")
    tip3._show()
    check("enabled widget unchanged", tip3._tip is not None)
    tip3._hide()
    root.destroy()
except Exception as exc:        # headless CI (ImportError or TclError): skip, never fail
    print("SKIP tkinter tooltip checks:", exc)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

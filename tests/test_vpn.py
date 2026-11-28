"""Tests for hookip.vpn (WARP detection), notify cooldown, and the
tooltip disabled-widget policy.

vpn.detect is tested with a stubbed subprocess (tasklist / warp-cli) so
the real machine's state never matters; notify's Popen is stubbed so no
real toast fires.
"""
import os
import sys
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


def fake_run(images=(), warpcli_out=None, warpcli_rc=0):
    """vpn.subprocess.run stub: tasklist returns `images`; warp-cli
    returns `warpcli_out` (or a nonzero rc when warpcli_rc != 0)."""
    def run(cmd, **kw):
        if cmd and cmd[0] == "tasklist":
            rows = "".join(
                f'"{img}","123","Console","1","1,000 K"\n' for img in images)
            return types.SimpleNamespace(returncode=0, stdout=rows)
        # warp-cli
        return types.SimpleNamespace(returncode=warpcli_rc,
                                     stdout=warpcli_out or "")
    return run


# ---- 1. detection: no VPN, WARP full tunnel, WARP proxy mode, unknown ----
with mock.patch.object(vpndetect.subprocess, "run", fake_run(images=())):
    check("no VPN processes -> None", vpndetect.detect(force=True) is None)

for img in vpndetect._WARP_IMAGES:
    with mock.patch.object(
            vpndetect.subprocess, "run",
            fake_run(images=(img,), warpcli_out="Mode: WarpWithDnsOverHttps")):
        st = vpndetect.detect(force=True)
        check(f"WARP detected via {img}", st is not None and
              st["kind"] == "cloudflare-warp", str(st))
        check(f"full-tunnel mode parsed ({img})", st.get("mode") == "full")
        check(f"detail says full tunnel ({img})", st.get("detail") == "full tunnel")
        break   # one image name is enough; all names were listed above

with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("warp-svc.exe",), warpcli_out="Mode: WarpProxy")):
    st = vpndetect.detect(force=True)
    check("WARP proxy mode parsed", st.get("mode") == "proxy" and
          "PROXY mode" in vpndetect.why_text(st), str(st))
    check("proxy-mode why mentions upstream chaining",
          "Upstream proxy" in vpndetect.why_text(st))

with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("Cloudflare WARP.exe",), warpcli_rc=1)):
    st = vpndetect.detect(force=True)
    check("warp-cli failure -> tunnel mode unknown but detected",
          st is not None and st.get("mode") is None, str(st))

with mock.patch.object(
        vpndetect.subprocess, "run",
        fake_run(images=("chrome.exe", "explorer.exe"))):
    check("unrelated processes -> None", vpndetect.detect(force=True) is None)


# ---- 2. cache: second detect() does NOT re-probe; force=True does -------
calls = {"n": 0}
base = fake_run(images=(), warpcli_out="")


def counting_run(cmd, **kw):
    calls["n"] += 1
    return base(cmd, **kw)


with mock.patch.object(vpndetect.subprocess, "run", counting_run):
    vpndetect.detect(force=True)
    first = calls["n"]
    vpndetect.detect()                 # cached
    check("cached detect does not re-probe", calls["n"] == first,
          f"{first} -> {calls['n']}")
    vpndetect.detect(force=True)
    check("force=True re-probes", calls["n"] > first)


# ---- 3. why_text: full-tunnel honesty -----------------------------------
txt = vpndetect.why_text({"kind": "cloudflare-warp", "mode": "full",
                          "detail": "full tunnel"})
check("why_text says encryption already handled",
      "already encrypted" in txt and "add nothing" in txt)
check("why_text says HookIP still works when VPN off",
      "VPN is off" in txt or "the moment the VPN" in txt)
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
    from hookip.tooltips import Tooltip
    root = tk.Tk()
    root.withdraw()
    btn = tk.Button(root, text="x", state="disabled")
    tip = Tooltip(btn, "helpful text")
    tip._show()
    ok = tip._tip is not None
    check("disabled widget shows its tooltip", ok)
    if tip._tip:
        # disabled_text override replaces the normal text
        lbl = tip._tip.children[list(tip._tip.children)[0]]
        tip._hide()
        tip2 = Tooltip(btn, "normal", disabled_text="why disabled")
        tip2._show()
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
except tk.TclError as exc:      # headless CI: skip, never fail
    print("SKIP tkinter tooltip checks:", exc)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""VPN awareness for HookIP — pure stdlib.

HookIP and a VPN never fight each other (HookIP is a local system proxy;
a full-tunnel VPN simply carries HookIP's outbound traffic), but they
OVERLAP: while a full-tunnel VPN is up, all traffic is already encrypted
end-to-end, so HookIP's SNI fragmentation and DoH add nothing. The app
tells the user this honestly instead of implying double protection.

Detection is best-effort process/service presence (Cloudflare WARP),
cached for 5 minutes, with generous failure handling: ANY error returns
None and the app behaves exactly as before.
"""
import subprocess
import threading
import time

CREATE_NO_WINDOW = 0x08000000

_CACHE_TTL = 300.0          # tasklist twice a minute would be silly
_cache_lock = threading.Lock()
_cache = None               # (state, monotonic-at)

# WARP's process names: the GUI app and the background service
_WARP_IMAGES = ("Cloudflare WARP.exe", "warp-svc.exe", "CloudflareWARP.exe")


def _tasklist_images():
    """Set of running image names (lowercased), or None on any failure."""
    try:
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=8,
            creationflags=CREATE_NO_WINDOW)
        if out.returncode != 0:
            return None
        names = set()
        for line in (out.stdout or "").splitlines():
            if line.startswith('"'):
                names.add(line.split('"')[1].lower())
        return names
    except (OSError, ValueError):
        return None


def _warp_proxy_mode():
    """Best-effort: is WARP in proxy mode (127.0.0.1:40000 style) instead
    of a full tunnel? Returns 'proxy' | 'full' | None (unknown)."""
    try:
        out = subprocess.run(
            ["warp-cli", "settings"], capture_output=True, text=True,
            timeout=4, creationflags=CREATE_NO_WINDOW)
        if out.returncode != 0:
            return None
        txt = out.stdout or ""
        if "WarpProxy" in txt or "ProxyMode" in txt:
            return "proxy"
        if "WarpWithDnsOverHttps" in txt or "Mode: Warp" in txt:
            return "full"
        return None
    except (OSError, ValueError):
        return None


def detect(force=False):
    """Best-effort VPN detection.

    Returns None (nothing detected / detection failed) or a dict:
      kind    "cloudflare-warp"
      mode    "full" | "proxy" | None
      detail  short human string, e.g. "full tunnel (MASQUE)"
    Cached for 5 minutes (pass force=True to re-probe)."""
    global _cache
    if force:
        with _cache_lock:
            _cache = None
    with _cache_lock:
        if _cache is not None:
            state, at = _cache
            if time.monotonic() - at < _CACHE_TTL:
                return state
    names = _tasklist_images()
    if not names:
        state = None                 # detection failed OR nothing running —
                                     # both mean 'no VPN pill shown'
    else:
        warp = [n for n in _WARP_IMAGES if n.lower() in names]
        if warp:
            mode = _warp_proxy_mode()
            detail = {"full": "full tunnel",
                      "proxy": "proxy mode (127.0.0.1:40000-style)",
                      None: "tunnel"}.get(mode, "tunnel")
            state = {"kind": "cloudflare-warp", "mode": mode, "detail": detail}
        else:
            state = None
    with _cache_lock:
        _cache = (state, time.monotonic())
    return state


def why_text(state):
    """The honest WHY a user should see when a VPN and HookIP are both on."""
    if not state:
        return ""
    if state.get("mode") == "proxy":
        return ("The VPN is in PROXY mode — HookIP's own connections do not "
                "ride through it automatically. Set Upstream proxy in "
                "Settings to the VPN's local proxy (e.g. 127.0.0.1:40000) "
                "to chain through it.")
    return ("All traffic is already encrypted end-to-end by the VPN, so "
            "HookIP's SNI fragmentation and DoH add nothing while it is up. "
            "HookIP still works (and still protects the moment the VPN is "
            "off); the VPN's own filtering still applies on top.")

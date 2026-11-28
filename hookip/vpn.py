"""VPN awareness for HookIP — pure stdlib (best effort, Cloudflare WARP).

What is true and what is not:

- A FULL-TUNNEL VPN (normal WARP mode) and HookIP coexist cleanly: HookIP
  is a local system proxy whose outbound traffic simply rides the tunnel.
  While such a VPN is up, all traffic is already encrypted end-to-end, so
  HookIP's SNI fragmentation and DoH add nothing — and the app says so
  instead of implying double protection.
- A PROXY-MODE VPN is different: WARP's proxy mode is SOCKS5, which
  HookIP cannot chain through (its upstream support speaks HTTP CONNECT
  only). The honest advice is to use the VPN's full-tunnel mode.
- A VPN that rewrites DNS or filters inside its tunnel limits HookIP the
  same way it limits everything else; that is stated, not hidden.

Detection is deliberately narrow and verified against THIS app's
environment: it recognizes Cloudflare WARP by its process/service names
and REQUIRES a confirmed `warp-cli status: Connected` before claiming
anything is "up" — the service process runs whenever WARP is installed,
including when the user has it switched off. Other VPNs (WireGuard,
OpenVPN, …) are NOT detected; the module would rather be silent than
wrong. All probes are best effort: ANY failure (timeout, missing CLI,
undecodable output) yields None and the app behaves exactly as before.
"""
import re
import subprocess
import threading
import time

CREATE_NO_WINDOW = 0x08000000

_CACHE_OK = 300.0            # a CONFIDENT answer is trusted for 5 minutes
_CACHE_FAIL = 20.0           # a transient failure is retried quickly
_cache_lock = threading.Lock()
_cache = None                # (state, monotonic-at, ttl)
_last = None                 # most recent answer, however stale (peek)
_probe_lock = threading.Lock()   # ONE in-flight probe; others wait

# WARP's process names: the GUI app and the background service. The
# service runs whenever WARP is INSTALLED — presence alone never means
# connected (see _warp_status).
_WARP_IMAGES = ("Cloudflare WARP.exe", "warp-svc.exe", "CloudflareWARP.exe")


def _tasklist_images():
    """Set of running image names (lowercased), or None on any failure.
    tasklist with 8 s of headroom; decoding never raises (errors=replace)."""
    try:
        out = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=8, errors="replace",
            creationflags=CREATE_NO_WINDOW)
        if out.returncode != 0:
            return None
        names = set()
        for line in (out.stdout or "").splitlines():
            if line.startswith('"'):
                names.add(line.split('"')[1].lower())
        return names
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def _warp_status():
    """'connected' | 'disconnected' | None (CLI missing / unknown output).

    Verified against the installed CLI: `warp-cli status` prints
    'Status update: Connected' / 'Status update: Disconnected' (older
    builds: 'Status: Connected'). Both wordings are accepted; anything
    unrecognized returns None so we never claim a state we have not seen."""
    try:
        out = subprocess.run(
            ["warp-cli", "status"], capture_output=True, text=True,
            timeout=4, errors="replace", creationflags=CREATE_NO_WINDOW)
        txt = (out.stdout or "") + "\n" + (out.stderr or "")
    except (subprocess.SubprocessError, OSError, ValueError):
        return None
    low = txt.lower()
    if "disconnected" in low:
        return "disconnected"
    if re.search(r"status(\s+update)?:\s*connected", low):
        return "connected"
    return None


def _warp_mode():
    """'full' | 'proxy' | None. Best effort read of `warp-cli settings`.

    'Mode: WarpWithDnsOverHttps' is VERIFIED output of the installed CLI;
    a proxy mode is detected by the 'WarpProxy' marker (UNVERIFIED —
    verified only in the tests of this module via stubs). None means we
    could not tell, and the caller gets a neutral explanation instead of
    a guess stated as fact."""
    try:
        out = subprocess.run(
            ["warp-cli", "settings"], capture_output=True, text=True,
            timeout=4, errors="replace", creationflags=CREATE_NO_WINDOW)
        if out.returncode != 0:
            return None
        txt = out.stdout or ""
    except (subprocess.SubprocessError, OSError, ValueError):
        return None
    if "WarpProxy" in txt:
        return "proxy"
    if "WarpWithDnsOverHttps" in txt or re.search(r"mode:\s*warp\b", txt,
                                                  re.IGNORECASE):
        return "full"
    return None


def _probe():
    """One detection round. Returns (state, confident):
    confident=True means the process table was actually read (an empty
    table is a CONFIDENT 'no VPN'); confident=False means detection ran
    into trouble and the answer must expire quickly."""
    names = _tasklist_images()
    if not names:
        return None, False            # tasklist failed — not confident
    warp = [n for n in _WARP_IMAGES if n.lower() in names]
    if not warp:
        return None, True             # WARP not running — confident no
    status = _warp_status()
    if status == "connected":
        mode = _warp_mode()
        detail = {"full": "full tunnel",
                  "proxy": "proxy mode (SOCKS5)",
                  None: "tunnel (mode unknown)"}.get(mode)
        return {"kind": "cloudflare-warp", "mode": mode,
                "detail": detail}, True
    if status == "disconnected":
        # installed but switched OFF — a neutral, honest state
        return {"kind": "cloudflare-warp", "mode": "off",
                "detail": "installed, not connected"}, True
    return None, False                # service runs, state unknown —
                                      # say nothing rather than guess


def detect(force=False):
    """Best-effort VPN detection.

    Returns None (nothing detected / detection failed / state unknown) or
    a dict: kind, mode ("full" | "proxy" | "off" | None), detail.
    A confident answer is cached 5 minutes; a failed probe only 20 s so a
    VPN started moments later is noticed. Concurrent callers share ONE
    in-flight probe instead of each spawning their own tasklist."""
    global _cache, _last
    if force:
        with _cache_lock:
            _cache = None
    with _cache_lock:
        if _cache is not None:
            state, at, ttl = _cache
            if time.monotonic() - at < ttl:
                return state
    with _probe_lock:                 # first caller probes, others wait
        with _cache_lock:             # the waiter may now find it fresh
            if _cache is not None:
                state, at, ttl = _cache
                if time.monotonic() - at < ttl:
                    return state
        state, confident = _probe()
        ttl = _CACHE_OK if confident else _CACHE_FAIL
        with _cache_lock:
            _cache = (state, time.monotonic(), ttl)
            _last = state
    return state


def peek():
    """The most recent detection result WITHOUT probing (never blocks,
    never spawns a process). None when nothing has been detected yet.
    Used where a synchronous probe would be unacceptable (UI thread)."""
    return _last


def why_text(state):
    """The honest WHY a user should see. Every mode gets its own text —
    an unknown mode NEVER receives the full-tunnel explanation, because
    that could state something false."""
    if not state:
        return ""
    mode = state.get("mode")
    if mode == "off":
        return ("Cloudflare WARP is installed but NOT connected — "
                "HookIP's SNI fragmentation and DoH are doing the real "
                "work right now.")
    if mode == "proxy":
        return ("The VPN is in SOCKS5 proxy mode. HookIP can only chain "
                "through HTTP proxies, so it cannot ride this VPN — use "
                "the VPN's full-tunnel mode for whole-device coverage, "
                "or run HookIP on its own.")
    if mode is None:
        return ("The VPN is connected but its mode could not be "
                "determined. HookIP still works; what the VPN does to "
                "your traffic is between you and the VPN app.")
    return ("All traffic is already encrypted end-to-end by the VPN, so "
            "HookIP's SNI fragmentation and DoH add nothing while it is "
            "up. HookIP still works (and still protects the moment the "
            "VPN is off); the VPN's own filtering still applies on top.")

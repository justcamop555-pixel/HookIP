"""Windows system-proxy management with crash-safe restore.

- Original settings are backed up before any change (JSON in %LOCALAPPDATA%).
- A detached watchdog process restores them if HookIP is killed or crashes.
- A RunOnce entry restores them at next sign-in after power loss.
- Clean Stop/exit restores immediately.
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import sys
from typing import Any
import threading
import time
import winreg

from . import APP_NAME

# One properly-configured kernel32 for ALL handle work in the app.
# ctypes.windll's GetLastError() is clobbered by ctypes internals, so we
# must use use_last_error=True + ctypes.get_last_error(), and give handles
# their true 64-bit type instead of truncating to c_int.
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateMutexW.restype = wt.HANDLE
_k32.CreateMutexW.argtypes = [wt.HANDLE, wt.BOOL, wt.LPCWSTR]
_k32.ReleaseMutex.argtypes = [wt.HANDLE]
_k32.ReleaseMutex.restype = wt.BOOL
_k32.CreateEventW.restype = wt.HANDLE
_k32.CreateEventW.argtypes = [wt.HANDLE, wt.BOOL, wt.BOOL, wt.LPCWSTR]
_k32.OpenEventW.restype = wt.HANDLE
_k32.OpenEventW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.SetEvent.argtypes = [wt.HANDLE]
_k32.SetEvent.restype = wt.BOOL
_k32.ResetEvent.argtypes = [wt.HANDLE]
_k32.ResetEvent.restype = wt.BOOL
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.WaitForSingleObject.restype = wt.DWORD
_k32.WaitForMultipleObjects.argtypes = [wt.DWORD, ctypes.POINTER(wt.HANDLE), wt.BOOL, wt.DWORD]
_k32.WaitForMultipleObjects.restype = wt.DWORD
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.CloseHandle.restype = wt.BOOL

HWND_BROADCAST = 0xFFFF
WM_SETTINGCHANGE = 0x001A
SYNCHRONIZE = 0x00100000


def _app_dir():
    return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME)


KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
RUNONCE_PATH = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
RUNONCE_NAME = "HookIP_Restore"
WATCHDOG_FLAG = "--hookip-watchdog"
BACKUP_PATH = os.path.join(_app_dir(), "proxy_backup.json")
RESTORE_CMD = os.path.join(_app_dir(), "restore.cmd")



# ----------------------------------------------------------------------
def read_current():
    vals = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH) as k:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
                try:
                    vals[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    vals[name] = None
    except OSError:
        pass
    return vals


def _write(vals):
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY_PATH) as k:
        for name in ("ProxyServer", "ProxyOverride", "AutoConfigURL"):
            v = vals.get(name)
            if v is None:
                try:
                    winreg.DeleteValue(k, name)
                except OSError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(v))
        enable = 1 if vals.get("ProxyEnable") else 0
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, enable)
    notify_shell()


def notify_shell():
    """Tell running apps that proxy settings changed.

    Two mechanisms, because different apps listen to different things:
    - wininet!InternetSetOptionW (SETTINGS_CHANGED + REFRESH): what WinINET
      clients (Microsoft Store, mail, many desktop apps) actually need —
      without it they keep their old proxy state and refuse to connect
    - WM_SETTINGCHANGE broadcast: everything else
    """
    try:
        wininet = ctypes.windll.wininet
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
    except Exception:
        pass

    def _send():
        try:
            ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Internet Settings",
                0x0002, 3000, None)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


def _split_prefix(seg):
    """('scheme://' or 'scheme=' prefix, remainder) — so the scheme colon
    is never mistaken for the user:pass separator."""
    import re
    m = re.match(r"^(\w+://|\w+=)(.*)$", seg, re.S)
    return (m.group(1), m.group(2)) if m else ("", seg)


def mask_proxy(proxy):
    """Mask embedded credentials in a proxy string before it reaches any
    log, toast or diagnostics line. Handles scheme URLs
    ('http://user:pass@corp:8080'), per-scheme entries ('socks=user:pass@h:p')
    and the IE ProxyServer list format ('u:p@h:8080;socks=proxy:1080') —
    per-segment and @-anchored (rpartition: a password containing '@',
    u:p@ss@h, used to leak its tail past the mask)."""
    def _seg(seg):
        prefix, rest = _split_prefix(seg)
        if "@" in rest:
            creds, _, host = rest.rpartition("@")
            if ":" in creds:
                rest = creds.split(":", 1)[0] + ":***@" + host
        return prefix + rest

    return ";".join(_seg(seg) for seg in str(proxy or "").split(";"))


def strip_creds(proxy):
    """Remove credentials entirely (restore.cmd must not carry a masked —
    i.e. BROKEN — password: 'user:***@h' would literally become the new
    ProxyServer after a crash restore). The host:port survives; auth
    re-prompts. The real values live only in the encrypted backup."""
    def _seg(seg):
        prefix, rest = _split_prefix(seg)
        if "@" in rest:
            rest = rest.rpartition("@")[2]
        return prefix + rest

    return ";".join(_seg(seg) for seg in str(proxy or "").split(";"))


def describe(vals, pac_token=""):
    """Human-readable proxy summary for logs and the Diagnostics report.

    pac_token is masked out of the PAC URL: the report is designed to be
    copy-pasted into bug reports, and the token lets anyone POST a PAC
    request that looks like this install's."""
    if not vals or not vals.get("ProxyEnable") and not vals.get("AutoConfigURL"):
        return "direct connection (no proxy)"
    parts = []
    if vals.get("ProxyEnable"):
        parts.append(f"manual proxy {mask_proxy(vals.get('ProxyServer'))}")
    if vals.get("AutoConfigURL"):
        acu = str(vals["AutoConfigURL"])
        if pac_token:
            acu = acu.replace(pac_token, "***")
        parts.append(f"PAC {acu}")
    if vals.get("ProxyOverride"):
        parts.append("bypass: " + vals["ProxyOverride"])
    return "; ".join(parts) if parts else "direct"


# ----------------------------------------------------------------------
class BackupError(OSError):
    """The encrypted proxy backup could not be written (DPAPI failure,
    disk error). Raised by backup() so apply_manual/apply_pac/apply_both
    abort BEFORE any registry write — without a backup, Stop's fallback
    remove_proxy() would erase the user's original (possibly corporate)
    proxy configuration with no way back."""


def backup(port=None, token=""):
    """Snapshot the CURRENT system proxy into the encrypted backup.

    port/token identify the HookIP session this backup belongs to (stored
    inside the encrypted JSON under "_hookip"; legacy backups without it
    keep working). Raises BackupError when the backup itself cannot be
    written — callers (apply_*) must abort with nothing changed. It still
    succeeds SILENTLY when it deliberately skips: the registry already
    holds this very session's state (an exact _is_ours match), so there
    is nothing new to save."""
    cur = read_current()
    # Never overwrite the saved original with HookIP's own proxy state —
    # that would happen if a second instance (or a restart) backed up while
    # the first instance's proxy was already active. EXACT match on this
    # session's port/token: the old heuristic also swallowed a local
    # Clash/Fiddler on 127.0.0.1:<other port>.
    if has_backup() and _is_ours(cur, port, token):
        return
    os.makedirs(_app_dir(), exist_ok=True)
    # ENCRYPTED at rest (HKCFG1): the backup holds the user's ORIGINAL
    # system-proxy config — corporate ProxyServer strings can embed
    # credentials (user:pass@proxy:8080) and ProxyOverride lists internal
    # hostnames. In plaintext this file was the single most profile-able
    # object HookIP wrote.
    from . import dataguard
    # atomic write: a crash mid-write must not leave a truncated HKCFG1:
    # file that restore_from_file would (correctly) refuse — losing the
    # backup means losing the user's original proxy config
    tmp = None
    try:
        payload = dict(cur)
        payload["_hookip"] = {"port": port, "token": token}
        blob = dataguard.encrypt_bytes(json.dumps(payload).encode("utf-8"))
        tmp = BACKUP_PATH + f".{threading.get_ident()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, BACKUP_PATH)
    except OSError as exc:
        try:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        # NOT silent: apply_* must not overwrite the proxy settings with
        # no backup on disk
        raise BackupError(f"could not write the proxy backup: {exc}") from exc
    _write_restore_cmd(cur)


def _parse_backup_text(raw):
    """Backup text -> dict or None (HKCFG1-encrypted or legacy plaintext).
    Shared by restore_from_file / backup_meta / the watchdog child."""
    if not isinstance(raw, str):
        return None
    vals = None
    if raw.startswith("HKCFG1:"):
        from . import dataguard
        plain = dataguard.decrypt_bytes(raw)
        if plain is not None:
            try:
                vals = json.loads(plain.decode("utf-8"))
            except ValueError:
                vals = None
    else:
        try:
            vals = json.loads(raw)   # legacy plaintext backup
        except ValueError:
            vals = None
    return vals if isinstance(vals, dict) else None


def backup_meta():
    """(port, token) of the session that WROTE the current backup, or
    (None, ""). Decrypts the backup; never raises."""
    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return (None, "")
    vals = _parse_backup_text(raw)
    meta = vals.get("_hookip") if isinstance(vals, dict) else None
    if isinstance(meta, dict):
        port = meta.get("port")
        token = meta.get("token")
        if isinstance(port, int) and not isinstance(port, bool) and \
                1 <= port <= 65535:
            return (port, str(token or ""))
    return (None, "")


def is_stale_hookip(vals, port, token):
    """Does this registry state belong to HOOKIP — the current session OR
    the session that wrote the backup?

    After a crash with 'Remember settings' off, the new session's
    port/PAC token differ from the crashed one, so an exact
    _is_ours(cur, port, token) missed the stale entry — and the caller
    then discarded the only backup. Matching EITHER session fixes that;
    an unrelated third-party proxy still returns False."""
    return _is_ours(vals, port, token) or _is_ours(vals, *backup_meta())


def looks_like_ours(vals):
    """Last-resort HookIP identification WITHOUT session context.

    Our PAC URLs are self-identifying:
    http://127.0.0.1:<port>/hookip-<token>.pac — the '/hookip-' marker is
    part of the URL no other tool is expected to produce. Used ONLY after
    the exact session match fails: a crashed session's stale PAC entry
    (different port/token, backup already gone) used to fall through to
    'nothing to restore' while the internet was still broken."""
    ac = str((vals or {}).get("AutoConfigURL") or "")
    return "/hookip-" in ac and ac.endswith(".pac")


def has_backup():
    return os.path.isfile(BACKUP_PATH)


def discard_backup(path=None):
    """Delete a stale proxy backup WITHOUT applying it.

    False-positive guard: a backup exists whenever a session did not end
    cleanly — but the user (or another tool) may have already fixed the
    system proxy manually. Restoring the stale backup over their manual
    config would silently CLOBBER it. When the registry no longer points
    at HookIP, the right move is to drop the backup."""
    # default bound at CALL time: a def-time default would freeze the
    # module constant forever (tests redirect BACKUP_PATH; the same
    # frozen-default pattern in restore_from_file is kept for API
    # stability — there it is equivalent in production)
    if path is None:
        path = BACKUP_PATH
    try:
        os.remove(path)
        return True
    except OSError:
        return False


# restore.cmd line grammar (see _write_restore_cmd):
#   reg add "HKCU\<KEY_PATH>" /v <Name> /t REG_<TYPE> /d "<value>" /f
#   reg delete "HKCU\<KEY_PATH>" /v <Name> /f
_ADD_RE = re.compile(
    r'reg\s+add\s+"HKCU\\(?P<key>[^"]+)"\s+/v\s+(?P<name>\w+)\s+'
    r'/t\s+REG_(?P<typ>[A-Z]+)\s+/d\s+(?:"(?P<val>[^"]*)"|(?P<val2>\S+))\s+/f',
    re.IGNORECASE)
_DEL_RE = re.compile(
    r'reg\s+delete\s+"HKCU\\(?P<key>[^"]+)"\s+/v\s+(?P<name>\w+)\s+/f',
    re.IGNORECASE)


def restore_from_cmd(path=None):
    """Recover the original proxy settings from the PLAINTEXT restore.cmd
    script that backup() writes alongside every encrypted backup.

    Fallback for the case the ENCRYPTED backup cannot be decrypted (a
    degraded DPAPI session used to make 'Restore internet' fail with no
    second chance). The script's values have credentials STRIPPED (it is
    plaintext on disk by nature) — a user with an authenticated upstream
    must re-enter the password afterwards; that is stated in the log.
    Returns True when the registry was written; never raises."""
    if path is None:
        path = RESTORE_CMD
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return False
    vals = {"ProxyEnable": 0, "ProxyServer": None,
            "ProxyOverride": None, "AutoConfigURL": None}
    parsed = False
    for m in _ADD_RE.finditer(text):
        if m.group("key").lower() != KEY_PATH.lower():
            continue
        name = m.group("name")
        if name not in vals:
            continue
        raw = m.group("val") if m.group("val") is not None else m.group("val2")
        if name == "ProxyEnable":
            vals[name] = 1 if raw.strip() in ("1", "0x1") else 0
        else:
            vals[name] = raw or None
        parsed = True
    for m in _DEL_RE.finditer(text):
        if m.group("key").lower() != KEY_PATH.lower():
            continue
        name = m.group("name")
        if name in vals:
            vals[name] = None
            parsed = True
    if not parsed:
        return False
    try:
        _write(vals)
    except OSError:
        return False
    return True


def restore_from_file(path=None):
    if path is None:
        path = BACKUP_PATH    # bound at CALL time: a def-time default
                              # would freeze the module constant forever
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return False
    # current format: encrypted (HKCFG1). A legacy plaintext backup is
    # honored once (restore is best-effort and the file is removed
    # afterwards either way) — fail-closed on unreadable ours-format blobs
    vals = _parse_backup_text(raw)
    if not isinstance(vals, dict):
        return False
    _write(vals)
    try:
        os.remove(path)
    except OSError:
        pass
    return True


def _norm_override_pattern(p):
    """bypass-pattern normalization — the SAME form the browser sends and
    the tunnel side compares (proxy._norm_domain semantics, kept local to
    avoid a circular import):
      - trimmed/lowered, trailing dot AND a trailing :port stripped
        (a pasted 'https://host:8080/x' used to leave 'host:8080' —
        which never matched anything in WinINET, the PAC or the tunnel)
      - IDN labels in punycode (WinINET compares the punycode wire form;
        a Unicode pattern like 'bücher.de' used to never match)
      - [::1]:8080 bracket form -> ::1 (the built-in local rules cover it)
    """
    p = str(p).strip().lower()
    if re.match(r"^[a-z0-9+.-]+://", p):
        p = re.sub(r"^[a-z0-9+.-]+://", "", p)   # pasted URL -> its host
    p = p.split("/")[0].split("?")[0].split("@")[-1].rstrip(".")
    if not p:
        return p
    if p.startswith("[") and "]" in p:
        p = p[1:].split("]")[0]
    elif p.count(":") == 1 and p.split(":", 1)[1].isdigit():
        p = p.split(":", 1)[0]
    if any(ord(c) > 127 for c in p):
        try:
            p = ".".join(
                l if (not l or l.startswith("*"))
                else l.encode("idna").decode("ascii")
                for l in p.split("."))
        except (UnicodeError, OSError):
            pass
    return p


def bypass_patterns(excluded):
    """Translate HookIP excluded patterns into WinINET ProxyOverride
    entries: bare dotted domains match both the domain and its subdomains;
    '*.example.com' ALSO emits the bare domain (the PAC and the tunnel
    side both match it — the ProxyOverride did not, so manual mode sent
    the bare domain through HookIP while PAC mode bypassed it)."""
    parts = []
    seen = set()
    for p in (excluded or []):
        p = _norm_override_pattern(p)
        if not p or p.startswith("#") or "/" in p:
            continue
        if p in seen:
            continue        # 'example.com' and 'example.com:8080' normalize
        seen.add(p)         # to the same entry — keep the list unique
        if p.startswith("*."):
            parts.append(p)
            parts.append(p[2:])           # bare domain (PAC/tunnel parity)
        elif "." in p and not p.replace(".", "").isdigit():
            parts.append(p)
            parts.append(f"*.{p}")
        else:
            parts.append(p)
    return parts


def _dedupe_override(override, extra):
    """Merge user bypass entries into the built-in list without duplicates
    (the default list already contains 'localhost' — the user's excluded
    list added it again, producing 'localhost;…;<local>;localhost')."""
    seen = []
    for part in override.split(";") + list(extra):
        p = part.strip().lower()
        if p and p not in seen:
            seen.append(p)
    return ";".join(seen)


def apply_manual(port, bypass=None):
    backup(port)
    override = LOCAL_PROXY_OVERRIDE
    extra = bypass_patterns(bypass)
    if extra:
        override = _dedupe_override(override, extra)
    vals = {
        "ProxyEnable": 1,
        "ProxyServer": f"127.0.0.1:{port}",
        "ProxyOverride": override,
        "AutoConfigURL": None,
    }
    _write(vals)


def apply_pac(port, token):
    backup(port, token)
    vals = {
        "ProxyEnable": 0,
        "ProxyServer": None,
        "ProxyOverride": None,
        "AutoConfigURL": f"http://127.0.0.1:{port}/{token}.pac",
    }
    _write(vals)


def apply_both(port, token, bypass=None):
    """Manual proxy AND PAC at once: every app that honours either
    mechanism now goes through HookIP. Both point at the same local
    listener, so there is no conflict — this simply widens coverage to
    apps that ignore one of the two settings."""
    backup(port, token)
    override = LOCAL_PROXY_OVERRIDE
    extra = bypass_patterns(bypass)
    if extra:
        override = _dedupe_override(override, extra)
    vals = {
        "ProxyEnable": 1,
        "ProxyServer": f"127.0.0.1:{port}",
        "ProxyOverride": override,
        "AutoConfigURL": f"http://127.0.0.1:{port}/{token}.pac",
    }
    _write(vals)


LOCAL_PROXY_OVERRIDE = ("localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;"
                        "172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;"
                        "172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;"
                        "172.31.*;<local>")


def _lan_address(addr):
    """True when *addr* points at a real LAN proxy (not HookIP itself)."""
    a = str(addr or "").lower()
    return bool(a) and "127.0.0.1" not in a and "localhost" not in a and "[::1]" not in a


def detect_network_proxy(vals, pac=True):
    """Restricted-network support: many Wi-Fi networks (offices, hotels,
    campuses) block DIRECT internet and require all traffic to go through
    the network's own proxy (WPAD/PAC or a manually configured one). When
    HookIP replaces that setting, its own direct connects would all fail —
    so detect the network's proxy BEFORE overwriting and tunnel through it.

    Returns 'host:port' or ''. Never raises (a malformed AutoConfigURL
    raising ValueError used to abort Start outright).

    pac=False skips the PAC FETCH (up to 4 s) and only reads the
    registry-form proxy — that part is what the UI thread may call
    synchronously; the fetch belongs on a worker.
    """
    try:
        # 1. manual proxy: '1.2.3.4:8080' or 'http=…;https=…' form.
        # socks= segments are SKIPPED: _via_upstream speaks HTTP CONNECT,
        # pointed at a SOCKS port it would send plain HTTP into a SOCKS
        # listener and every connection would fail oddly.
        ps = str(vals.get("ProxyServer") or "")
        if vals.get("ProxyEnable") and ps:
            if "=" in ps:
                segs = [s.split("=", 1)[1].strip() for s in ps.split(";")
                        if "=" in s and not s.lower().startswith("socks")]
            else:
                segs = [ps]
            for seg in segs:
                seg = _clean_upstream(seg)
                if seg and _lan_address(seg):
                    return seg
        # 2. PAC: fetch it (best effort) and take the first non-local
        # PROXY entry. ONLY http/https schemes — a file:// (or ftp://)
        # AutoConfigURL passed _lan_address and used to be fetched
        # directly. NOTE the first match is best-effort: a PAC script can
        # return different proxies per condition; we cannot evaluate JS.
        # (Skipped entirely when pac=False — see docstring.)
        acu = str(vals.get("AutoConfigURL") or "")
        if pac and acu.lower().startswith(("http://", "https://")) \
                and _lan_address(acu):
            import re
            import urllib.request
            req = urllib.request.Request(acu, headers={"User-Agent": "HookIP"})
            with urllib.request.urlopen(req, timeout=4) as r:
                pac_text = r.read(65536).decode("latin1", "replace")
            for cand in re.findall(r"PROXY\s+([^;\s]+:\d+)", pac_text,
                                   re.IGNORECASE):
                cand = _clean_upstream(cand)
                if cand and _lan_address(cand):
                    return cand
    except Exception:  # noqa: BLE001 — detection is best-effort, never fatal
        pass
    return ""


def _clean_upstream(addr):
    """Normalize a candidate upstream proxy to 'host:port' — a scheme
    prefix ('http://') or embedded user:pass@ would break _via_upstream,
    which splits on ':' and would resolve 'http' as the host."""
    a = str(addr or "").strip()
    if "://" in a:
        a = a.split("://", 1)[1]
    if "@" in a:
        a = a.rpartition("@")[2]
    return a.strip("/")


def remove_proxy():
    """Last-resort cleanup: switch Windows back to a direct connection."""
    _write({"ProxyEnable": 0, "ProxyServer": None,
            "ProxyOverride": None, "AutoConfigURL": None})


# ----------------------------------------------------------------------
INSTANCE_MUTEX = "HookIP_Instance_Mutex"
ACTIVATE_EVENT = "HookIP_Activate_Event"
ERROR_ALREADY_EXISTS = 183
EVENT_MODIFY_STATE = 0x0002


def acquire_single_instance():
    """Hold a named mutex for the app's lifetime.

    Returns the handle, None if another HookIP instance is running, or
    False when the mutex could not be created for another reason — the
    old code returned None for a NULL handle too, and run() then
    reported 'already running' for a plain CreateMutexW failure."""
    handle = _k32.CreateMutexW(None, False, INSTANCE_MUTEX)
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        if handle:
            _k32.CloseHandle(handle)
        return None
    if not handle:
        return False
    return handle


def notify_running_instance():
    """Signal the running instance to show its window. True on success."""
    ev = _k32.OpenEventW(EVENT_MODIFY_STATE, False, ACTIVATE_EVENT)
    if not ev:
        return False
    ok = bool(_k32.SetEvent(ev))
    _k32.CloseHandle(ev)
    return ok


def _is_ours(vals, port=None, pac_token=""):
    """Is this proxy configuration one HookIP set itself?

    Exact match on 127.0.0.1:{port} plus the PAC token — the old
    startswith('127.0.0.1') heuristic counted a local Clash/Fiddler/
    V2Ray as HookIP's, and a subsequent stop/restore then WIPED that
    other tool's configuration (backup() skipped saving it). When the
    port/token are unknown the heuristic stays as a last resort, but
    every in-app caller passes both."""
    ps = str(vals.get("ProxyServer") or "")
    ac = str(vals.get("AutoConfigURL") or "")
    if port:
        ps_ours = ps == f"127.0.0.1:{port}"
        ac_ours = bool(pac_token) and pac_token in ac and ac.endswith(".pac")
        if ps or ac:
            return ps_ours or ac_ours
        return False
    # heuristic fallback (no port context available)
    return ps.startswith("127.0.0.1") or ("127.0.0.1" in ac and ".pac" in ac)


def _write_restore_cmd(vals):
    # NOTE: ProxyServer values that embed credentials are STRIPPED here —
    # the cmd is a plaintext recovery artifact by nature (reg.exe must read
    # it), and writing 'user:***@host' would make *** the literal password
    # after a crash restore. host:port survives; auth re-prompts. The
    # complete unmasked values live only in the ENCRYPTED proxy backup.
    lines = ["@echo off"]
    lines.append(f'reg add "HKCU\\{KEY_PATH}" /v ProxyEnable /t REG_DWORD /d {1 if vals.get("ProxyEnable") else 0} /f')
    if vals.get("ProxyServer"):
        lines.append(f'reg add "HKCU\\{KEY_PATH}" /v ProxyServer /t REG_SZ /d "{strip_creds(vals["ProxyServer"])}" /f')
    else:
        lines.append(f'reg delete "HKCU\\{KEY_PATH}" /v ProxyServer /f >nul 2>&1')
    if vals.get("ProxyOverride"):
        lines.append(f'reg add "HKCU\\{KEY_PATH}" /v ProxyOverride /t REG_SZ /d "{vals["ProxyOverride"]}" /f')
    else:
        lines.append(f'reg delete "HKCU\\{KEY_PATH}" /v ProxyOverride /f >nul 2>&1')
    if vals.get("AutoConfigURL"):
        lines.append(f'reg add "HKCU\\{KEY_PATH}" /v AutoConfigURL /t REG_SZ /d "{vals["AutoConfigURL"]}" /f')
    else:
        lines.append(f'reg delete "HKCU\\{KEY_PATH}" /v AutoConfigURL /f >nul 2>&1')
    lines.append(f'reg delete "HKCU\\{RUNONCE_PATH}" /v {RUNONCE_NAME} /f >nul 2>&1')
    os.makedirs(_app_dir(), exist_ok=True)
    # atomic: a truncated cmd in RunOnce runs HALF a script (the reg
    # delete lines execute, the restore adds do not) — a power loss
    # mid-write must not leave a cmd that only deletes our RunOnce marker
    tmp = RESTORE_CMD + f".{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\r\n".join(lines))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, RESTORE_CMD)
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def set_runonce():
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUNONCE_PATH) as k:
            winreg.SetValueEx(k, RUNONCE_NAME, 0, winreg.REG_SZ, f'"{RESTORE_CMD}"')
    except OSError:
        pass


def clear_runonce():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUNONCE_PATH, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUNONCE_NAME)
    except OSError:
        pass
    try:
        os.remove(RESTORE_CMD)
    except OSError:
        pass


# ----------------------------------------------------------------------
class Watchdog:
    """Owns the crash-safety watchdog child processes.

    v3: TWO independent children (twins) watch the app, plus a 2 s
    heartbeat event the children monitor:
    - each child alone restores the proxy the moment the app process
      dies (instant reaction via WaitForMultipleObjects);
    - if one child is killed first (Task Manager 'End task' on one of
      the identical-looking HookIP.exe rows, an AV heuristic kill, OOM),
      the twin keeps protecting;
    - if the app process stays alive but stops beating (wedged accept
      loop, deadlock — a crash that doesn't terminate the process), the
      children restore after ~40 s of silence.
    Twins dedupe the restore/notify through a named event (watchdog.py)."""

    def __init__(self):
        self._event = None
        self._beat = []      # one auto-reset beat event per child
        self._beat_stop: Any = None   # Event (or a duck-typed fake in tests)
        self._beat_thread = None
        self._procs = []
        self._proc = None
        self.event_name = None
        self.beat_name: Any = None    # str once children spawn; None before

    def _spawn(self, args, flags, env):
        try:
            return subprocess.Popen(args, creationflags=flags, close_fds=True, env=env)
        except OSError:
            return None

    def _beat_loop(self):
        # SetEvent every 2 s while the watchdog owns beat events: the
        # children treat silence as 'app not responding'. ONE auto-reset
        # event wakes only ONE waiter per SetEvent — with two children on
        # a single event, one child could starve past 25 s + 15 s grace
        # and restore the proxy under a LIVE app. Each child now waits on
        # its OWN event and every tick signals both.
        beats = self._beat
        while beats and self._beat_stop and not self._beat_stop.wait(2.0):
            for h in beats:
                _k32.SetEvent(h)

    def start(self, port):
        self.stop()
        pid = os.getpid()
        # BUGFIX: the stop-event is manual-reset and a clean stop() SIGNALS
        # it. CreateEventW on the same name returned that still-signaled
        # event, so every watchdog spawned AFTER a stop→start cycle saw the
        # stop flag at birth and exited instantly — crash protection was
        # silently gone for the whole session. Unique name per start + an
        # explicit reset both prevent it.
        self._start_count = getattr(self, "_start_count", 0) + 1
        self.event_name = f"HookIP_Stop_{pid}_{port}_{self._start_count}"
        self.beat_name = f"HookIP_Beat_{pid}_{port}_{self._start_count}"
        self._event = _k32.CreateEventW(None, True, False, self.event_name)
        if self._event:
            _k32.ResetEvent(self._event)
        # ONE auto-reset beat event per child: a SetEvent wakes exactly one
        # waiter, so with a shared event one twin could starve. Child i
        # waits on "<beat_name>_<i>"; _beat_loop signals both every tick.
        # self.beat_name stays the prefix (diagnostics name it in logs).
        self._beat = []
        beat_names = []
        for i in range(2):
            name = f"{self.beat_name}_{i}"
            h = _k32.CreateEventW(None, False, False, name)   # auto-reset
            if h:
                self._beat.append(h)
                beat_names.append(name)
        backup, ppid = BACKUP_PATH, str(pid)
        if getattr(sys, "frozen", False):
            # packaged exe: the exe itself understands --hookip-watchdog
            base_args = [sys.executable, WATCHDOG_FLAG, backup, ppid, self.event_name]
            env = None
        else:
            pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            launcher = os.path.join(pkg_parent, "run_hookip.py")
            if os.path.isfile(launcher):
                base_args = [sys.executable, launcher, WATCHDOG_FLAG, backup, ppid,
                             self.event_name]
                env = None
            else:
                base_args = [sys.executable, "-c",
                             "import sys; from hookip.watchdog import main; main(*sys.argv[1:])",
                             backup, ppid, self.event_name]
                env = dict(os.environ, PYTHONPATH=pkg_parent)
        flags = 0x08000000  # CREATE_NO_WINDOW
        # TWO children: killing one (Task Manager end-task on the wrong
        # HookIP.exe row, AV heuristic) must not leave the proxy unwatched
        procs = []
        for i in range(2):
            extra = [beat_names[i]] if i < len(beat_names) else []
            procs.append(self._spawn(base_args + extra, flags, env))
        self._procs = procs
        self._beat_stop = threading.Event()
        self._beat_thread = threading.Thread(target=self._beat_loop, daemon=True)
        self._beat_thread.start()
        # a watchdog that died at birth (broken cwd / python) used to leave
        # crash protection silently OFF for the whole session — verify it
        # actually survived startup, and respawn once before giving up.
        # OFF THE CALLER'S THREAD: this slept 0.4 s inline, and
        # _refresh_dashboard calls start() on the UI thread — a dead
        # watchdog froze the window ~2 s per re-arm.
        # per-child full command lines (child i waits on its own beat
        # event, so a respawned child must get THAT child's name back)
        child_args = [base_args + ([beat_names[i]] if i < len(beat_names) else [])
                      for i in range(2)]

        def _verify(all_args, spawn_flags, spawn_env, snapshot):
            time.sleep(0.4)
            if self._procs is not snapshot:
                return          # stop() ran meanwhile — do not respawn
            fresh = [p if (p is not None and p.poll() is None)
                     else self._spawn(all_args[i], spawn_flags, spawn_env)
                     for i, p in enumerate(snapshot)]
            if self._procs is snapshot:
                self._procs = fresh
                self._proc = next((p for p in fresh if p is not None), None)
        threading.Thread(target=_verify, args=(child_args, flags, env, procs),
                         daemon=True).start()

    def stop(self):
        beat_stop = getattr(self, "_beat_stop", None)
        if beat_stop:
            beat_stop.set()
        t = getattr(self, "_beat_thread", None)
        if t is not None and t.is_alive():
            t.join(1.0)          # stop beating before closing the beat handle
        procs = list(getattr(self, "_procs", None) or [])
        if not procs and getattr(self, "_proc", None):
            procs = [self._proc]
        if self._event:
            event = self._event
            _k32.SetEvent(self._event)
            self._event = None
            # the onefile children react to the event instantly (~0.01 s) —
            # the wait-for-exit + terminate fallback runs on a WORKER: the
            # old inline 1.5 s poll blocked the UI thread on every Stop
            # (the children exit on the event by themselves; terminate()
            # only catches a child that ignored it)
            def _reap():
                deadline = time.time() + 1.5
                while time.time() < deadline:
                    if all(p is None or p.poll() is not None for p in procs):
                        break
                    time.sleep(0.05)
                _k32.CloseHandle(event)   # one handle per start cycle
                for p in procs:
                    if p and p.poll() is None:
                        try:
                            p.terminate()
                        except OSError:
                            pass
            threading.Thread(target=_reap, daemon=True).start()
        self._procs = []
        self._proc = None
        for h in getattr(self, "_beat", None) or []:
            _k32.CloseHandle(h)
        self._beat = []

    def alive(self):
        return any(p is not None and p.poll() is None
                   for p in getattr(self, "_procs", []))

    def watchers(self):
        """Number of live watchdog children (0–2) — for Diagnostics."""
        return sum(1 for p in getattr(self, "_procs", [])
                   if p is not None and p.poll() is None)

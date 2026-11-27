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
import subprocess
import sys
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


def describe(vals):
    if not vals or not vals.get("ProxyEnable") and not vals.get("AutoConfigURL"):
        return "direct connection (no proxy)"
    parts = []
    if vals.get("ProxyEnable"):
        parts.append(f"manual proxy {vals.get('ProxyServer')}")
    if vals.get("AutoConfigURL"):
        parts.append(f"PAC {vals['AutoConfigURL']}")
    if vals.get("ProxyOverride"):
        parts.append("bypass: " + vals["ProxyOverride"])
    return "; ".join(parts) if parts else "direct"


# ----------------------------------------------------------------------
def backup():
    cur = read_current()
    # Never overwrite the saved original with HookIP's own proxy state —
    # that would happen if a second instance (or a restart) backed up while
    # the first instance's proxy was already active.
    if has_backup() and _is_ours(cur):
        return
    os.makedirs(_app_dir(), exist_ok=True)
    with open(BACKUP_PATH, "w", encoding="utf-8") as fh:
        json.dump(cur, fh)
    _write_restore_cmd(cur)


def has_backup():
    return os.path.isfile(BACKUP_PATH)


def restore_from_file(path=BACKUP_PATH):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            vals = json.load(fh)
    except (OSError, ValueError):
        return False
    _write(vals)
    try:
        os.remove(path)
    except OSError:
        pass
    return True


def bypass_patterns(excluded):
    """Translate HookIP excluded patterns into WinINET ProxyOverride
    entries: bare dotted domains match both the domain and its subdomains."""
    parts = []
    for p in (excluded or []):
        p = str(p).strip().lower().rstrip(".")
        if not p or p.startswith("#") or "/" in p:
            continue
        if p.startswith("*."):
            parts.append(p)
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
    backup()
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
    backup()
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
    backup()
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


def detect_network_proxy(vals):
    """Restricted-network support: many Wi-Fi networks (offices, hotels,
    campuses) block DIRECT internet and require all traffic to go through
    the network's own proxy (WPAD/PAC or a manually configured one). When
    HookIP replaces that setting, its own direct connects would all fail —
    so detect the network's proxy BEFORE overwriting and tunnel through it.

    Returns 'host:port' or ''.
    """
    # 1. manual proxy: '1.2.3.4:8080' or 'http=…;https=…' form
    ps = str(vals.get("ProxyServer") or "")
    if vals.get("ProxyEnable") and ps:
        if "=" in ps:
            # per-protocol form: prefer https, then any first segment
            segs = [s.split("=", 1)[1].strip() for s in ps.split(";") if "=" in s]
            for seg in segs:
                if _lan_address(seg):
                    return seg
        elif _lan_address(ps):
            return ps
    # 2. PAC: fetch it (best effort) and take the first non-local PROXY entry
    acu = str(vals.get("AutoConfigURL") or "")
    if acu and _lan_address(acu):
        try:
            import re
            import urllib.request
            req = urllib.request.Request(acu, headers={"User-Agent": "HookIP"})
            with urllib.request.urlopen(req, timeout=4) as r:
                pac = r.read(65536).decode("latin1", "replace")
            for cand in re.findall(r"PROXY\s+([^;\s]+:\d+)", pac, re.IGNORECASE):
                if _lan_address(cand):
                    return cand
        except OSError:
            pass
    return ""


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
    Returns the handle, or None if another HookIP instance is running."""
    handle = _k32.CreateMutexW(None, False, INSTANCE_MUTEX)
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        _k32.CloseHandle(handle)
        return None
    return handle


def notify_running_instance():
    """Signal the running instance to show its window. True on success."""
    ev = _k32.OpenEventW(EVENT_MODIFY_STATE, False, ACTIVATE_EVENT)
    if not ev:
        return False
    ok = bool(_k32.SetEvent(ev))
    _k32.CloseHandle(ev)
    return ok


def _is_ours(vals):
    """Does this proxy configuration look like one HookIP set itself?"""
    ps = str(vals.get("ProxyServer") or "")
    ac = str(vals.get("AutoConfigURL") or "")
    return ps.startswith("127.0.0.1") or ("127.0.0.1" in ac and ".pac" in ac)


def _write_restore_cmd(vals):
    lines = ["@echo off"]
    lines.append(f'reg add "HKCU\\{KEY_PATH}" /v ProxyEnable /t REG_DWORD /d {1 if vals.get("ProxyEnable") else 0} /f')
    if vals.get("ProxyServer"):
        lines.append(f'reg add "HKCU\\{KEY_PATH}" /v ProxyServer /t REG_SZ /d "{vals["ProxyServer"]}" /f')
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
    with open(RESTORE_CMD, "w", encoding="utf-8") as fh:
        fh.write("\r\n".join(lines))


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
    """Owns the crash-safety watchdog child process."""

    def __init__(self):
        self._event = None
        self._proc = None
        self.event_name = None

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
        self._event = _k32.CreateEventW(None, True, False, self.event_name)
        if self._event:
            _k32.ResetEvent(self._event)
        backup, ppid, event = BACKUP_PATH, str(pid), self.event_name
        if getattr(sys, "frozen", False):
            # packaged exe: the exe itself understands --hookip-watchdog
            args = [sys.executable, WATCHDOG_FLAG, backup, ppid, event]
            env = None
        else:
            pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            launcher = os.path.join(pkg_parent, "run_hookip.py")
            if os.path.isfile(launcher):
                args = [sys.executable, launcher, WATCHDOG_FLAG, backup, ppid, event]
                env = None
            else:
                args = [sys.executable, "-c",
                        "import sys; from hookip.watchdog import main; main(*sys.argv[1:])",
                        backup, ppid, event]
                env = dict(os.environ, PYTHONPATH=pkg_parent)
        flags = 0x08000000  # CREATE_NO_WINDOW
        self._proc = subprocess.Popen(args, creationflags=flags, close_fds=True, env=env)
        # a watchdog that died at birth (broken cwd / python) used to leave
        # crash protection silently OFF for the whole session — verify it
        # actually survived startup, and respawn once before giving up
        time.sleep(0.4)
        if self._proc.poll() is not None:
            try:
                self._proc = subprocess.Popen(args, creationflags=flags,
                                              close_fds=True, env=env)
                time.sleep(0.4)
            except OSError:
                self._proc = None

    def stop(self):
        if self._event:
            _k32.SetEvent(self._event)
            _k32.CloseHandle(self._event)     # one handle per start cycle
            self._event = None
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except OSError:
                pass
        self._proc = None

    def alive(self):
        return bool(self._proc and self._proc.poll() is None)

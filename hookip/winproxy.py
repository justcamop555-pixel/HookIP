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
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.WaitForSingleObject.restype = wt.DWORD
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
    """Tell running apps that proxy settings changed."""
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


def apply_manual(port):
    backup()
    vals = {
        "ProxyEnable": 1,
        "ProxyServer": f"127.0.0.1:{port}",
        "ProxyOverride": LOCAL_PROXY_OVERRIDE,
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


LOCAL_PROXY_OVERRIDE = ("localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;"
                        "172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;"
                        "172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;"
                        "172.31.*;<local>")


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
        self.event_name = f"HookIP_Stop_{pid}_{port}"
        self._event = _k32.CreateEventW(None, True, False, self.event_name)
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

    def stop(self):
        if self._event:
            _k32.SetEvent(self._event)
            self._event = None
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except OSError:
                pass
        self._proc = None

    def alive(self):
        return bool(self._proc and self._proc.poll() is None)

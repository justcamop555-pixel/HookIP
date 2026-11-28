"""Windows toast notifications for HookIP — pure stdlib."""
import os
import subprocess
import tempfile
import threading
import time

CREATE_NO_WINDOW = 0x08000000

PROTOCOL_KEY = r"Software\Classes\hookip"


def ensure_protocol(exe_path=None):
    """Register hookip:// for this user (no admin) so toast clicks can open
    the app. Idempotent; silently ignores failures (notifications still work
    without it)."""
    try:
        import winreg
        if exe_path is None:
            exe_path = sys_executable()
        exe_path = os.path.abspath(exe_path)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, PROTOCOL_KEY) as k:
            winreg.SetValueEx(k, None, 0, winreg.REG_SZ, "URL:HookIP protocol")
            winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, PROTOCOL_KEY + r"\shell\open\command") as k:
            winreg.SetValueEx(k, None, 0, winreg.REG_SZ, f'"{exe_path}" "%1"')
        return True
    except OSError:
        return False


def sys_executable():
    import sys
    return sys.executable if getattr(sys, "frozen", False) else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "HookIP.exe")


def _esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace("'", "&apos;"))


def notify(title, message, timeout_s=8):
    """Fire a Windows toast. Fire-and-forget; failures are silent (it is a
    nicety, never a reason to disturb the user)."""
    try:
        ps = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml('<toast activationType="protocol" launch="hookip:show" scenario="default"><visual><binding template="ToastGeneric"><text>{_esc(title)}</text><text>{_esc(message)}</text></binding></visual><audio src="ms-winsoundevent:Notification.Default"/></toast>')
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('HookIP.Desktop').Show($toast)
"""
        # unique per toast: two rapid notifications from one process used
        # to share a path — the second write could clobber the first before
        # its PowerShell had read it (or serve a half-written script)
        path = os.path.join(
            tempfile.gettempdir(),
            f"hookip_toast_{os.getpid()}_{time.time_ns()}.ps1")
        with open(path, "w", encoding="utf-8-sig") as fh:   # BOM: PS 5.1 needs it
            fh.write(ps)
        subprocess.Popen(
            ["powershell", "-NoProfile", "-STA", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-File", path],
            creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # clean up the temp script shortly after (best effort)
        def cleanup():
            try:
                time.sleep(timeout_s + 4)
                os.remove(path)
            except OSError:
                pass
        threading.Thread(target=cleanup, daemon=True).start()
        return True
    except Exception:
        return False

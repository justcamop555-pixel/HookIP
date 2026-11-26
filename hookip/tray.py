"""System tray icon for HookIP — pure ctypes, no third-party deps.

Runs a tiny hidden Win32 window in its own thread that owns the tray icon.
Mouse events are pushed onto a queue; the tkinter main thread drains it
(tkinter is not thread-safe, so the tray thread never touches Tk directly).
"""
import ctypes
import os
import queue
import sys
import threading
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_user32 = ctypes.WinDLL("user32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# --- Shell_NotifyIconW ------------------------------------------------------
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x01, 0x02, 0x04

WM_APP_TRAY = 0x8000 + 0x4B1          # our callback message id
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_LBUTTONUP = 0x0202
WM_DESTROY = 0x0002


class NOTIFYICONDATAW(ctypes.Structure):
    # V2 layout (no GUID/balloon-icon tail): maximally compatible, cbSize is
    # set to this struct's size so old and new shells both accept it.
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
    ]


_shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
_shell32.Shell_NotifyIconW.restype = wintypes.BOOL
_user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.DefWindowProcW.restype = ctypes.c_longlong

WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_longlong, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HCURSOR),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


def _load_app_icon():
    """hIcon for the tray: the packaged exe's own icon resource, or the
    project's hookip.ico when running from source."""
    try:
        _shell32.ExtractIconExW.restype = wintypes.UINT
        _shell32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                                            ctypes.POINTER(wintypes.HICON),
                                            ctypes.POINTER(wintypes.HICON), wintypes.UINT]
        big = wintypes.HICON()
        if _shell32.ExtractIconExW(sys.executable, 0, None, ctypes.byref(big), 1) and big.value:
            return big.value
    except Exception:
        pass
    try:
        paths = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "hookip.ico")]
        if getattr(sys, "frozen", False):
            paths.insert(0, os.path.join(sys._MEIPASS, "hookip.ico"))
        for p in paths:
            IMAGE_ICON, LR_LOADFROMFILE = 1, 0x0010
            _user32.LoadImageW.restype = wintypes.HANDLE
            h = _user32.LoadImageW(None, p, IMAGE_ICON, 0, 0,
                                   LR_LOADFROMFILE | 0x00000040)  # LR_DEFAULTSIZE
            if h:
                return h
    except Exception:
        pass
    return None


class TrayIcon:
    """Owns the tray icon. Events are delivered on self.events:
       ("show",), ("menu", x, y), ("exit",)  — all raised from the Tk side."""

    def __init__(self, title):
        self.events = queue.Queue()
        self._title = title[:127]
        self._hicon = _load_app_icon()
        self._hwnd = None
        self._thread = None
        self._ready = threading.Event()
        self._visible = False
        self._failed = False

    # -- public ------------------------------------------------------------
    def start(self):
        if self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="hookip-tray", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=3)

    def stop(self):
        try:
            if self._hwnd:
                _user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)
        except Exception:
            pass

    def set_tip(self, tip):
        self._title = tip[:127]
        if self._visible:
            self._modify()

    @property
    def available(self):
        return self._ready.is_set() and not self._failed

    # -- internals -----------------------------------------------------------
    def _run(self):
        """Tray thread: hidden window + message loop."""
        try:
            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == WM_APP_TRAY:
                    if lparam in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                        self.events.put(("show",))
                    elif lparam == WM_RBUTTONUP:
                        pt = POINT()
                        _user32.GetCursorPos(ctypes.byref(pt))
                        self.events.put(("menu", pt.x, pt.y))
                    return 0
                if msg == WM_DESTROY:
                    self._remove()
                    _user32.PostQuitMessage(0)
                    return 0
                return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            self._proc_ref = WNDPROC(wnd_proc)          # keep callback alive
            hinst = _kernel32.GetModuleHandleW(None)
            wc = WNDCLASSW()
            wc.lpfnWndProc = self._proc_ref
            wc.hInstance = hinst
            wc.lpszClassName = "HookIPTrayWnd"
            _user32.RegisterClassW(ctypes.byref(wc))
            # never-visible top-level window (message-only windows are not
            # reliably delivered tray callbacks by all shells)
            self._hwnd = _user32.CreateWindowExW(
                0, "HookIPTrayWnd", "HookIP tray", 0, 0, 0, 0, 0,
                None, None, hinst, None)
            if not self._hwnd:
                self._failed = True
                self._ready.set()
                return
            if self._add():
                self._visible = True
            self._ready.set()
            msg = wintypes.MSG()
            while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                _user32.TranslateMessage(ctypes.byref(msg))
                _user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            self._failed = True
            self._ready.set()

    def _add(self):
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_TIP | (NIF_ICON if self._hicon else 0)
        nid.uCallbackMessage = WM_APP_TRAY
        nid.hIcon = self._hicon or None
        nid.szTip = self._title
        return bool(_shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))

    def _modify(self):
        if not self._hwnd:
            return
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_TIP | (NIF_ICON if self._hicon else 0)
        nid.hIcon = self._hicon or None
        nid.szTip = self._title
        _shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))

    def _remove(self):
        if not self._hwnd or not self._visible:
            return
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        _shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        self._visible = False

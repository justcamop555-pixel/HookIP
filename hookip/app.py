"""HookIP desktop app (tkinter, dark theme)."""
import os
import queue
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from . import __version__, APP_NAME
from . import dnsmsg
from . import logutil
from .config import Config, SETTINGS_PATH, DEFAULTS
from .logutil import Log
from .proxy import ProxyServer, Stats
from .tooltips import Tooltip
from . import winproxy
from . import notify
from .tray import TrayIcon
from .doh import RESOLVERS, _DoHConn

BG = "#0f1115"
PANEL = "#161a21"
ACCENT = "#4f8cff"
OK = "#3fb950"
WARN = "#d29922"
ERR = "#f85149"
FG = "#e6edf3"
MUTED = "#8b949e"


def resource_path(name):
    """Locate a bundled data file (works frozen under PyInstaller and from source)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, name)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        saved = Config.load()
        # "Remember settings" unchecked → start from defaults (settings were forgotten)
        self.cfg = saved if saved.remember else Config()
        self.log = Log()
        self.log.verbose = self.cfg.verbose
        # session log file (mirrors everything; helps bug reports)
        from .config import APP_DIR
        self._log_dir = os.path.join(APP_DIR, "logs")
        Log.prune_session_files(self._log_dir, keep=7)
        self._log_file = os.path.join(self._log_dir, time.strftime("hookip_%Y%m%d_%H%M%S.log"))
        self.log.attach_file(self._log_file)
        self._hook_exception_logging()
        self.stats = Stats()
        self.pac_token = self.cfg.pac_token or secrets.token_hex(8)
        if self.cfg.pac_token != self.pac_token:
            self.cfg.pac_token = self.pac_token
            try:
                self.cfg.save()
            except OSError:
                pass
        self.proxy = None
        self.running = False
        self.watchdog = winproxy.Watchdog()

        root.title(f"{APP_NAME} v{__version__}")
        root.geometry("880x640")
        root.minsize(760, 560)
        root.configure(bg=BG)
        try:
            root.iconbitmap(resource_path("hookip.ico"))
        except (tk.TclError, OSError):
            pass
        self._style()
        self._build()
        self._lock_window_style()
        self._recover_stale_proxy()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_request)
        # thread-safe UI event queue: background threads NEVER call tk
        self._ui_queue = queue.Queue()
        self._closing = threading.Event()
        self.root.after(150, self._pump_ui)
        # user-facing protocol so clicking a toast brings HookIP up
        notify.ensure_protocol()
        # system tray (X button hides to tray; minimize stays a normal
        # minimize — hiding on minimize made double taskbar clicks "lose"
        # the window, which is why there is no <Unmap> binding)
        self.tray = TrayIcon(f"{APP_NAME} — stopped")
        self.tray.start()
        if self.tray.available:
            self.root.after(120, self._pump_tray)
        else:
            self.log.debug("System tray unavailable — window-only mode.")
        # update check (quiet at startup; manual button in Settings)
        self.root.after(15000, self.check_updates)
        self._log_pos = 0  # kept for compatibility; pump now uses drain()
        self.root.after(250, self._pump_log)
        self.root.after(500, self._refresh_dashboard)
        self._watch_activation()
        self.log.info(f"{APP_NAME} {__version__} ready. Press Start to turn the proxy on.")

    def _watch_activation(self):
        """Watch the named event a second instance signals to bring this
        window to the front (single-instance support)."""
        try:
            ev = winproxy._k32.CreateEventW(None, False, False, winproxy.ACTIVATE_EVENT)
            if not ev:
                return

            def watcher():
                while not self._closing.is_set():
                    if winproxy._k32.WaitForSingleObject(ev, 1000) == 0:
                        try:
                            self._ui_queue.put(("show", ()))
                        except Exception:
                            return
                    time.sleep(0.05)
                    if self._closing.is_set():
                        return

            threading.Thread(target=watcher, daemon=True).start()
        except Exception:
            pass

    def _pump_ui(self):
        """Drain events posted by background threads (activation, updates)."""
        try:
            while True:
                kind, args = self._ui_queue.get_nowait()
                if kind == "show":
                    self._show_self()
                elif kind == "update":
                    self._update_result(*args)
                elif kind == "diag_done":
                    for b in self._diag_buttons:
                        try:
                            b.configure(state="normal")
                        except tk.TclError:
                            pass
        except queue.Empty:
            pass
        except Exception as exc:  # noqa: BLE001 — never stop the UI pump;
            # only a real shutdown may end it (a stray RuntimeError used to
            # kill the pump silently — the app then looked alive but deaf)
            if getattr(self, "_closing", None) and self._closing.is_set():
                return
            try:
                self.log.error(f"UI pump error: {exc}")
            except Exception:
                pass
        try:
            self.root.after(150, self._pump_ui)
        except (tk.TclError, RuntimeError):
            return

    def _pump_tray(self):
        try:
            while True:
                ev = self.tray.events.get_nowait()
                kind = ev[0]
                if kind == "show":
                    self._show_self()
                elif kind == "menu":
                    self._tray_menu(ev[1], ev[2])
                elif kind == "exit":
                    self.on_close()
                    return
        except queue.Empty:
            pass
        except Exception as exc:  # noqa: BLE001 — never stop the tray pump
            if getattr(self, "_closing", None) and self._closing.is_set():
                return
            try:
                self.log.error(f"tray pump error: {exc}")
            except Exception:
                pass
        try:
            self.root.after(120, self._pump_tray)
        except (tk.TclError, RuntimeError):
            return

    def _tray_menu(self, x, y):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Show HookIP", command=self._show_self)
        menu.add_command(label=("⏹ Stop proxy" if self.running else "▶ Start proxy"),
                         command=self.toggle)
        menu.add_separator()
        menu.add_command(label="Exit", command=self.on_close)
        try:
            menu.tk_popup(x, y)
        finally:
            menu.grab_release()

    # -- update check ----------------------------------------------------
    UPDATE_REPO = "justcamop555-pixel/HookIP"

    def _validate_numeric_fields(self, *_):
        """Live port/fragment validation: invalid entries turn red and show
        the valid range right next to the field."""
        try:
            ok_p = 1 <= int(self.port_var.get()) <= 65535
        except (ValueError, tk.TclError):
            ok_p = False
        try:
            ok_f = 1 <= int(self.frag_var.get()) <= 255
        except (ValueError, tk.TclError):
            ok_f = False
        try:
            self.port_e.configure(foreground=FG if ok_p else ERR)
            self.frag_e.configure(foreground=FG if ok_f else ERR)
            self.port_hint.configure(text="" if ok_p else "1–65535")
            self.frag_hint.configure(text="" if ok_f else "1–255")
            # live availability probe — identical to Start's exclusive bind,
            # so what it says here is exactly what Start will see
            avail_txt, avail_fg = "", MUTED
            if ok_p and not self.running:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    p_num = int(self.port_var.get())
                    s.bind(("127.0.0.1", p_num))
                    if p_num <= 1023:
                        avail_txt, avail_fg = "well-known port — may clash", WARN
                    else:
                        avail_txt, avail_fg = "free", OK
                except OSError:
                    avail_txt, avail_fg = "in use — Start may fail", ERR
                finally:
                    try:
                        s.close()
                    except OSError:
                        pass
            try:
                self.port_avail.configure(text=avail_txt, fg=avail_fg)
            except (tk.TclError, AttributeError):
                pass
            # header badge follows the live entry while the proxy is off
            if not self.running and ok_p:
                self.port_badge.configure(text=f"127.0.0.1:{self.port_var.get()}")
        except (tk.TclError, AttributeError):
            pass
        return ok_p and ok_f

    def _find_free_port(self):
        """Pick a random verified-free port near the default range and fill
        the entry (same exclusive bind Start uses)."""
        if self.running:
            self.log.info("The proxy is running on its own port — stop it "
                          "before changing the setting.")
            return
        import random
        for _ in range(60):
            p = random.randint(9000, 9899)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
            finally:
                try:
                    s.close()
                except OSError:
                    pass
            self.port_var.set(str(p))
            self.log.info(f"Port {p} is free — filled into Settings "
                          "(applies on next Start).")
            return
        self.log.error("No free port found in 9000–9899 — type one manually.")

    def _parse_excluded(self):
        """Read the excluded-domains box: trimmed, lowercased, deduped,
        tolerant of pasted URLs (https://sub.example.com/ → sub.example.com)
        and of comment lines."""
        out, seen = [], set()
        for ln in self.excl_text.get("1.0", "end").splitlines():
            ln = ln.strip().lower()
            if not ln or ln.startswith("#"):
                continue
            ln = re.sub(r"^[a-z0-9+.-]+://", "", ln)      # strip scheme
            ln = ln.split("/")[0].split("?")[0].split("@")[-1]
            ln = ln.strip(". ")                            # stray dots
            if ln and ln not in seen:
                seen.add(ln)
                out.append(ln)
        return out

    def _reset_excluded(self):
        if self.running:
            self.log.info("The proxy is running — stop it before changing "
                          "excluded domains.")
            return
        self.excl_text.delete("1.0", "end")
        self.excl_text.insert("1.0", "\n".join(DEFAULTS["excluded"]))
        self.log.info("Excluded domains reset to defaults (applied on next Start).")

    def check_updates(self):
        if getattr(self, "_update_running", False):
            self.log.info("Update check already running.")
            return
        self._update_running = True
        self.update_label.configure(text="checking…", fg=MUTED)
        threading.Thread(target=self._update_worker, daemon=True).start()

    def _update_worker(self):
        import json as _json
        import urllib.request
        import urllib.error
        latest, url = None, None
        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{self.UPDATE_REPO}/releases/latest",
                headers={"User-Agent": "HookIP-updater", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = _json.loads(r.read().decode("utf-8"))
                latest, url = data.get("tag_name", ""), data.get("html_url") or \
                    f"https://github.com/{self.UPDATE_REPO}/releases"
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                latest = None
                url = f"https://github.com/{self.UPDATE_REPO}/releases"
            # 404: private repo — try the redirect form (works once public)
            if latest is None:
                try:
                    req2 = urllib.request.Request(
                        f"https://github.com/{self.UPDATE_REPO}/releases/latest",
                        headers={"User-Agent": "HookIP-updater"})
                    with urllib.request.urlopen(req2, timeout=10) as r2:
                        tag = r2.geturl().rsplit("/tag/", 1)[-1]
                        if tag and tag != "latest":
                            latest, url = tag, f"https://github.com/{self.UPDATE_REPO}/releases/tag/{tag}"
                except OSError:
                    pass
        except OSError:
            pass
        self._ui_queue.put(("update", (latest, url)))
    @staticmethod
    def _ver_tuple(s):
        try:
            return tuple(int(p) for p in s.lstrip("v").split(".")[:3])
        except ValueError:
            return (0,)

    def _update_result(self, latest, url):
        self._update_running = False
        try:
            if not latest:
                self.update_label.configure(
                    text="unavailable (private repo? — works once public)", fg=MUTED)
                self.update_pill.configure(text="", fg=MUTED)
                self.log.debug("Update check: no reachable release info (repo private or offline).")
                return
            self._update_url = url
            if self._ver_tuple(latest) > self._ver_tuple(__version__):
                self.update_label.configure(text=f"update available: {latest}", fg=WARN)
                self.update_pill.configure(text=f"⬆ {latest} — click to update", fg=WARN)
                self.log.ok(f"Update available: {latest} — you are on v{__version__}.")
                notify.notify("HookIP update available",
                              f"{latest} is out (you have v{__version__}). "
                              "Click the banner in the app to get it.",
                              timeout_s=12)
                if messagebox.askyesno(
                        APP_NAME,
                        f"HookIP {latest} is available\n(you have v{__version__}).\n\n"
                        f"Open the Releases page to download it?"):
                    import webbrowser
                    webbrowser.open(url or f"https://github.com/{self.UPDATE_REPO}/releases")
            else:
                self.update_label.configure(text=f"up to date (v{__version__})", fg=OK)
                self.update_pill.configure(text=f"✓ v{__version__}", fg=MUTED)
        except (tk.TclError, RuntimeError):
            pass
        # re-check every 12 h so a published update is noticed without a restart
        try:
            self.root.after(12 * 3600 * 1000, self.check_updates)
        except (tk.TclError, RuntimeError):
            pass

    def _update_pill_click(self, _event=None):
        if getattr(self, "_update_url", None) and "⬆" in self.update_pill.cget("text"):
            import webbrowser
            webbrowser.open(self._update_url)
        else:
            self.check_updates()

    def _show_self(self):
        try:
            self.root.deiconify()
            self._lock_window_style()   # re-assert: no maximize/fullscreen
            self.root.lift()
            self.root.focus_force()
        except (tk.TclError, RuntimeError):
            pass

    def _lock_window_style(self):
        """Fullscreen is disabled, forever: strip WS_MAXIMIZEBOX from the
        window, which removes the maximize button and blocks Win+Up / title
        double-click maximizing. The window stays freely resizable."""
        try:
            import ctypes
            user32 = ctypes.windll.user32
            GWL_STYLE = -16
            WS_MAXIMIZEBOX = 0x00010000
            hwnd = user32.GetParent(self.root.winfo_id())
            if not hwnd:
                return
            style = user32.GetWindowLongW(hwnd, GWL_STYLE)
            if style & WS_MAXIMIZEBOX:
                user32.SetWindowLongW(hwnd, GWL_STYLE, style & ~WS_MAXIMIZEBOX)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _style(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor="#2a3040", lightcolor=PANEL, darkcolor=PANEL)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                    padding=(14, 7), font=("Segoe UI", 10))
        s.map("TNotebook.Tab", background=[("selected", "#202634")],
              foreground=[("selected", FG)])
        s.configure("Card.TFrame", background=PANEL)
        s.configure("TLabel", background=PANEL, foreground=FG)
        s.configure("Muted.TLabel", foreground=MUTED)
        s.configure("TButton", background="#202634", foreground=FG, padding=(12, 6))
        s.map("TButton", background=[("active", "#2a3244")])
        s.configure("TCheckbutton", background=PANEL, foreground=FG)
        s.map("TCheckbutton", background=[("active", PANEL)])
        s.configure("TEntry", fieldbackground="#0d1017", foreground=FG, insertcolor=FG,
                    selectbackground="#2d3b5c", selectforeground=FG)
        s.configure("TCombobox", fieldbackground="#0d1017", foreground=FG,
                    background="#202634", arrowcolor=FG, bordercolor="#2a3040",
                    lightcolor="#0d1017", darkcolor="#0d1017",
                    selectbackground="#0d1017", selectforeground=FG)
        s.map("TCombobox", fieldbackground=[("readonly", "#0d1017"), ("active", "#0d1017")],
              foreground=[("readonly", FG), ("active", FG)],
              selectbackground=[("readonly", "#0d1017")],
              selectforeground=[("readonly", FG)])

        # Treeview (tables) — clam's default is white-on-white otherwise
        s.configure("Treeview", background="#0d1017", foreground=FG,
                    fieldbackground="#0d1017", rowheight=24, bordercolor="#2a3040",
                    lightcolor="#0d1017", darkcolor="#0d1017")
        s.map("Treeview", background=[("selected", "#2d3b5c")],
              foreground=[("selected", FG)])
        s.configure("Treeview.Heading", background="#202634", foreground=FG,
                    relief="flat", padding=(6, 5), font=("Segoe UI Semibold", 9))
        s.map("Treeview.Heading", background=[("active", "#2a3244")])

        # combobox dropdown list
        self.root.option_add("*TCombobox*Listbox.background", "#0d1017")
        self.root.option_add("*TCombobox*Listbox.foreground", FG)
        self.root.option_add("*TCombobox*Listbox.selectBackground", "#2d3b5c")
        self.root.option_add("*TCombobox*Listbox.selectForeground", FG)

    def _build(self):
        # header ----------------------------------------------------------
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=16, pady=(14, 8))
        tk.Label(head, text="⚓ HookIP", font=("Segoe UI Semibold", 18),
                 bg=BG, fg=FG).pack(side="left")
        self.status_pill = tk.Label(head, text="● Stopped", font=("Segoe UI Semibold", 11),
                                    bg=BG, fg=MUTED)
        self.status_pill.pack(side="left", padx=16)
        Tooltip(self.status_pill,
                "Proxy state: '● Running' means Windows traffic goes through "
                "HookIP right now; '● Stopped' means direct connection.")
        self.port_badge = tk.Label(head, text=f"127.0.0.1:{self.cfg.port}",
                                   font=("Consolas", 10), bg="#202634", fg=MUTED,
                                   padx=10, pady=3)
        self.port_badge.pack(side="left")
        Tooltip(self.port_badge,
                "The local port Windows is (or will be) pointed at. Follows "
                "the port field in Settings live while the proxy is off.")
        self.start_btn = tk.Button(head, text="▶  Start", command=self.toggle,
                                   font=("Segoe UI Semibold", 12), bd=0, cursor="hand2",
                                   bg=OK, fg="white", activebackground="#46c06a",
                                   activeforeground="white", padx=26, pady=8)
        self.start_btn.pack(side="right")
        self.start_tip = Tooltip(
            self.start_btn,
            "▶ Turn the proxy on: fragments TLS handshakes so DPI can't read "
            "the site name, and points Windows at HookIP.\n"
            "Also sends a 'protecting you' notification.")
        self.restore_btn = tk.Button(head, text="↺  Restore internet",
                                     command=self._manual_restore,
                                     font=("Segoe UI", 10), bd=0, cursor="hand2",
                                     bg="#202634", fg=FG, activebackground="#2a3244",
                                     activeforeground=FG, padx=14, pady=8)
        self.restore_btn.pack(side="right", padx=(0, 10))
        Tooltip(self.restore_btn,
                "Rescue button. If HookIP crashed and Windows is still pointed "
                "at it, this restores your previous connection — with a "
                "confirmation notification. While running it stops the proxy.")
        self.update_pill = tk.Label(head, text="", font=("Segoe UI", 10),
                                    bg=BG, fg=MUTED, cursor="hand2", padx=6)
        self.update_pill.pack(side="right", padx=(0, 4))
        self.update_pill.bind("<Button-1>", self._update_pill_click)
        Tooltip(self.update_pill,
                "Update banner: '⬆ vX' means a newer HookIP is out (click to "
                "open the release page). '✓ vX' means you are up to date.")
        # flat-button hover feedback (header buttons)
        for btn, hot, cold in ((self.restore_btn, "#2a3244", "#202634"),):
            btn.bind("<Enter>", lambda e, b=btn, c=hot: b.configure(bg=c), add="+")
            btn.bind("<Leave>", lambda e, b=btn, c=cold: b.configure(bg=c), add="+")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.nb = nb

        # dashboard --------------------------------------------------------
        dash = ttk.Frame(nb, style="Card.TFrame", padding=14)
        nb.add(dash, text=" Dashboard ")
        self.dash_vars = {}
        row = tk.Frame(dash, bg=PANEL)
        row.pack(fill="x")
        self._stat_card(row, "connections", "Total connections", 0)
        self._stat_card(row, "active", "Active now", 0)
        self._stat_card(row, "down", "Data received", "0 B")
        self._stat_card(row, "up", "Data sent", "0 B")
        self._stat_card(row, "failed", "Failed", 0)
        self._stat_card(row, "blocked", "Blocked", 0)
        tk.Label(dash, text="Throughput (last 3 min)", bg=PANEL, fg=MUTED).pack(anchor="w", pady=(14, 2))
        self.spark = tk.Canvas(dash, height=110, bg="#0d1017", highlightthickness=0)
        self.spark.pack(fill="x")
        Tooltip(self.spark,
                "Down/up traffic per second over the last 3 minutes\n"
                "(green = received, blue = sent). Shows 'now' and 'peak' "
                "rates while running; a 'stopped' note when off.")
        tk.Label(dash, text="Top domains this session", bg=PANEL, fg=MUTED).pack(anchor="w", pady=(14, 2))
        cols = ("domain", "conns", "up", "down")
        self.dom_tree = ttk.Treeview(dash, columns=cols, show="headings", height=7)
        for cid, text, w in (("domain", "Domain", 320), ("conns", "Conns", 70),
                             ("up", "Sent", 90), ("down", "Received", 100)):
            self.dom_tree.heading(cid, text=text)
            self.dom_tree.column(cid, width=w, anchor="w")
        self.dom_tree.pack(fill="both", expand=True)
        Tooltip(self.dom_tree,
                "The sites your apps used most this session, ranked by "
                "traffic — updates live while the proxy runs.")

        # log ----------------------------------------------------------------
        logf = ttk.Frame(nb, style="Card.TFrame", padding=10)
        nb.add(logf, text=" Activity log ")
        bar = tk.Frame(logf, bg=PANEL)
        bar.pack(fill="x", pady=(0, 6))
        tk.Label(bar, text="Show:", bg=PANEL, fg=MUTED).pack(side="left")
        self._log_min_rank = 1
        self._log_all = []                       # full in-app history for filter/export
        self.log_filter = ttk.Combobox(
            bar, state="readonly", width=20,
            values=["Everything", "Info and above", "Warnings and above", "Errors only"])
        self.log_filter.current(1)
        self.log_filter.pack(side="left", padx=(6, 8))
        Tooltip(self.log_filter,
                "Filter the on-screen log by importance.\n"
                "'Everything' also reveals per-connection detail;\n"
                "the log FILE on disk always keeps it all.")
        self.log_filter.bind("<<ComboboxSelected>>", lambda _e: self._apply_log_filter())
        save_btn = tk.Button(bar, text="Save log…", command=self._export_log,
                             bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                             activebackground="#2a3244", activeforeground=FG,
                             cursor="hand2")
        save_btn.pack(side="right")
        Tooltip(save_btn,
                "Save the complete log (every detail, no filter) to a file —\n"
                "perfect for attaching to a bug report. The log is also always\n"
                "written to disk automatically: %LOCALAPPDATA%\\HookIP\\logs.")
        copy_btn = tk.Button(bar, text="Copy all", command=self._copy_log,
                             bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                             activebackground="#2a3244", activeforeground=FG,
                             cursor="hand2")
        copy_btn.pack(side="right", padx=(0, 6))
        Tooltip(copy_btn, "Copy the complete log to the clipboard.")
        sf_lbl = tk.Label(bar, text=f"Session file: {self._log_file}", bg=PANEL,
                          fg=MUTED, font=("Segoe UI", 8))
        sf_lbl.pack(side="right", padx=8)
        Tooltip(sf_lbl,
                "The log file for this session (debug detail is always "
                "written here, even with the on-screen filter set higher). "
                "Logs are kept in %LOCALAPPDATA%\\HookIP\\logs and pruned "
                "after 7 days.")
        self.log_text = tk.Text(logf, bg="#0d1017", fg=FG, insertbackground=FG,
                                font=("Consolas", 9), state="disabled", wrap="none",
                                height=10)
        self.log_text.pack(fill="both", expand=True)
        Tooltip(self.log_text,
                "Live log view — filtered by the 'Show' selector above. "
                "Use 'Save log…' for the complete unfiltered file; colors: "
                "blue = DNS, teal = resolves, dim = per-connection detail.")
        for tag, color in (("info", FG), ("ok", OK), ("warn", WARN),
                           ("error", ERR), ("debug", MUTED)):
            self.log_text.tag_configure(tag, foreground=color)
        self.log_text.tag_configure("ts", foreground="#5a6478")
        # semantic sub-colors so the debug stream stays scannable:
        #   DoH lookups  = soft blue · resolved IPs = teal · fragment/relay
        #   bookkeeping = dim gray · failures stay amber/red
        self.log_text.tag_configure("doh", foreground="#8ab4f8")
        self.log_text.tag_configure("res", foreground="#79c7c5")
        self.log_text.tag_configure("dim", foreground="#4a5468")
        self.log_text.tag_configure("connok", foreground="#6ea86e")

        # settings -------------------------------------------------------------
        setf = ttk.Frame(nb, style="Card.TFrame", padding=14)
        nb.add(setf, text=" Settings ")
        self.set_widgets = []
        grid = tk.Frame(setf, bg=PANEL)
        grid.pack(fill="x")

        def add_row(label, widget, row):
            tk.Label(grid, text=label, bg=PANEL, fg=MUTED, anchor="e", width=18)\
                .grid(row=row, column=0, sticky="e", padx=(0, 10), pady=5)
            widget.grid(row=row, column=1, sticky="w", pady=5)
            self.set_widgets.append(widget)

        self.port_var = tk.StringVar(value=str(self.cfg.port))
        port_row = tk.Frame(grid, bg=PANEL)
        port_e = ttk.Entry(port_row, textvariable=self.port_var, width=10)
        port_e.pack(side="left")
        self.port_e = port_e
        self.port_hint = tk.Label(port_row, text="", bg=PANEL, fg=WARN,
                                  font=("Segoe UI", 8))
        self.port_hint.pack(side="left", padx=6)
        self.port_avail = tk.Label(port_row, text="", bg=PANEL, fg=MUTED,
                                   font=("Segoe UI", 8))
        self.port_avail.pack(side="left", padx=(2, 0))
        fp_btn = tk.Button(port_row, text="Find free", command=self._find_free_port,
                           bg="#202634", fg=FG, bd=0, padx=6, pady=1,
                           activebackground="#2a3244", activeforeground=FG,
                           cursor="hand2")
        fp_btn.pack(side="left", padx=(6, 0))
        self.set_widgets.append(fp_btn)   # disabled while the proxy runs
        Tooltip(fp_btn,
                "Picks a random free port near the default (9000–9899),\n"
                "verified with the same exclusive bind Start uses, and\n"
                "fills the field. Use when the current port is taken.")
        add_row("Local port", port_row, 0)
        self.set_widgets.append(port_e)   # the frame can't be disabled
        Tooltip(port_e,
                "Local TCP port HookIP listens on (default 8890).\n"
                "Windows is pointed here while the proxy runs.\n"
                "Valid range: 1–65535; must be free when you press Start.")

        self.frag_var = tk.StringVar(value=str(self.cfg.fragment_size))
        frag_row = tk.Frame(grid, bg=PANEL)
        frag_e = ttk.Entry(frag_row, textvariable=self.frag_var, width=10)
        frag_e.pack(side="left")
        self.frag_e = frag_e
        self.frag_hint = tk.Label(frag_row, text="", bg=PANEL, fg=WARN,
                                  font=("Segoe UI", 8))
        self.frag_hint.pack(side="left", padx=6)
        add_row("Fragment size (bytes)", frag_row, 1)
        self.set_widgets.append(frag_e)
        Tooltip(frag_e,
                "Size of each TLS ClientHello fragment in bytes (1–255).\n"
                "2 is the stealthiest (every byte split apart);\n"
                "larger values are faster but easier to spot. Only change\n"
                "this if a network has trouble with the default.")

        self.strategy_var = tk.StringVar(value=self.cfg.strategy)
        strat_c = ttk.Combobox(grid, textvariable=self.strategy_var, width=12,
                               state="readonly",
                               values=["smart", "chunk", "random"])
        add_row("Strategy", strat_c, 2)
        self.port_var.trace_add("write", self._validate_numeric_fields)
        self.frag_var.trace_add("write", self._validate_numeric_fields)
        self._validate_numeric_fields()
        Tooltip(strat_c,
                "How the TLS ClientHello is split to slip past blocking:\n"
                "smart = adaptive, chunk = fixed-size pieces,\n"
                "random = random sizes. Try a different one if a site fails.")

        self.mode_var = tk.StringVar(value=self.cfg.proxy_mode)
        mode_c = ttk.Combobox(grid, textvariable=self.mode_var, width=12,
                              state="readonly", values=["manual", "pac", "both"])
        add_row("System proxy mode", mode_c, 3)
        Tooltip(mode_c,
                "How Windows is pointed at HookIP:\n"
                "manual = fixed proxy setting (most apps obey).\n"
                "pac = proxy-autoconfig script (some apps prefer it).\n"
                "both = set both at once — the widest app coverage,\n"
                "since both point at the same HookIP listener.")

        self.doh_var = tk.BooleanVar(value=self.cfg.doh_enabled)
        doh_c = ttk.Checkbutton(grid, text="Use DNS-over-HTTPS (recommended)",
                                variable=self.doh_var)
        add_row("Secure DNS", doh_c, 4)
        Tooltip(doh_c,
                "DNS-over-HTTPS: resolves names over an encrypted, fragmented\n"
                "connection so DNS itself can't be blocked or tampered with.\n"
                "Keep this on unless a network requires plain DNS.")

        self.verbose_var = tk.BooleanVar(value=self.cfg.verbose)
        verb_c = ttk.Checkbutton(grid, text="Verbose log", variable=self.verbose_var,
                                 command=lambda: setattr(self.log, "verbose",
                                                         self.verbose_var.get()))
        add_row("Logging", verb_c, 5)
        Tooltip(verb_c,
                "Shows per-connection detail on screen (DNS timings, ports,\n"
                "fragment counts). The log FILE always keeps this detail\n"
                "regardless of this switch.")

        self.remember_var = tk.BooleanVar(value=self.cfg.remember)
        rem_c = ttk.Checkbutton(grid, text="Remember settings for next launch",
                                variable=self.remember_var)
        add_row("Persistence", rem_c, 6)
        Tooltip(rem_c,
                "Save port, fragment size, strategy, mode and the excluded\n"
                "list to %LOCALAPPDATA%\\HookIP\\settings.json.\n"
                "Off = forget everything when HookIP closes.")

        self.tray_var = tk.BooleanVar(value=self.cfg.minimize_to_tray)
        tray_c = ttk.Checkbutton(grid, text="Hide to tray when the window is closed (X)",
                                 variable=self.tray_var)
        add_row("Window", tray_c, 7)
        Tooltip(tray_c,
                "On: the X button hides HookIP to the system tray and the "
                "proxy keeps running — the tray icon restores it.\n"
                "Off: the X button really exits (stopping the proxy).\n"
                "Minimize is always a normal minimize.")

        upd = tk.Frame(grid, bg=PANEL)
        upd_btn = tk.Button(upd, text="Check for updates", command=self.check_updates,
                            bg="#202634", fg=FG, bd=0, padx=10, pady=4,
                            activebackground="#2a3244", activeforeground=FG,
                            cursor="hand2")
        upd_btn.pack(side="left")
        Tooltip(upd_btn,
                "Checks GitHub Releases for a newer HookIP version.\n"
                "Also runs automatically ~15 s after launch and every 12 h.")
        self.update_label = tk.Label(upd, text="", bg=PANEL, fg=MUTED,
                                     font=("Segoe UI", 9))
        self.update_label.pack(side="left", padx=10)
        add_row("Updates", upd, 8)

        row = tk.Frame(setf, bg=PANEL)
        tk.Label(row, text="Excluded domains (one per line, wildcards allowed).\n"
                           "These sites skip HookIP completely — useful for\n"
                           "banking apps or anything that dislikes modified\n"
                           "handshakes.",
                 bg=PANEL, fg=MUTED, justify="left").pack(side="left")
        rb = tk.Button(row, text="Reset defaults", command=self._reset_excluded,
                       bg="#202634", fg=FG, bd=0, padx=8, pady=2,
                       activebackground="#2a3244", activeforeground=FG,
                       cursor="hand2")
        rb.pack(side="right")
        self.set_widgets.append(rb)   # disabled while the proxy runs
        Tooltip(rb, "Put the excluded list back to the default entries.")
        row.pack(fill="x", pady=(10, 2))
        self.excl_text = tk.Text(setf, bg="#0d1017", fg=FG, insertbackground=FG,
                                 font=("Consolas", 9), height=5)
        self.excl_text.insert("1.0", "\n".join(self.cfg.excluded))
        self.excl_text.pack(fill="x")
        self.set_widgets.append(self.excl_text)
        Tooltip(self.excl_text,
                "Domains that skip HookIP completely, in every proxy mode:\n"
                "they are added to the Windows bypass list (manual) or served\n"
                "as DIRECT (PAC/both). One per line; wildcards like\n"
                "*.example.com are allowed; lines starting with # are ignored.\n"
                "Handy for banking apps, games with anti-cheat, or captive\n"
                "portals that dislike modified handshakes.")
        sf_set = tk.Label(setf, text=f"Settings file: {SETTINGS_PATH}",
                          bg=PANEL, fg=MUTED)
        sf_set.pack(anchor="w", pady=(8, 0))
        Tooltip(sf_set,
                "Where your settings live (saved when 'Remember settings' "
                "is on). Safe to delete — HookIP recreates defaults.")

        # diagnostics ------------------------------------------------------------
        diagf = ttk.Frame(nb, style="Card.TFrame", padding=14)
        nb.add(diagf, text=" Diagnostics ")
        btns = tk.Frame(diagf, bg=PANEL)
        btns.pack(fill="x")
        self._diag_buttons = []
        tips = {
            "Run full check": "Runs every diagnostic: settings sanity, system state,\n"
                              "antivirus, DNS resolvers and a real end-to-end\n"
                              "tunnel test (start the proxy for the tunnel part).",
            "DNS only": "Tests each DNS-over-HTTPS resolver with a real lookup.",
            "Tunnel only": "Opens a real HTTPS connection through HookIP to two\n"
                           "well-known sites (needs the proxy to be running).",
            "System only": "Shows Windows/antivirus/proxy state and flags a stale\n"
                           "proxy left behind by a crash.",
        }
        for text, cmd in (("Run full check", lambda: self.run_diagnostics("all")),
                          ("DNS only", lambda: self.run_diagnostics("dns")),
                          ("Tunnel only", lambda: self.run_diagnostics("tunnel")),
                          ("System only", lambda: self.run_diagnostics("system"))):
            b = tk.Button(btns, text=text, command=cmd,
                          bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                          activebackground="#2a3244", activeforeground=FG,
                          cursor="hand2")
            b.pack(side="left")
            Tooltip(b, tips[text])
            self._diag_buttons.append(b)
        cc_btn = tk.Button(btns, text="Clear DNS cache", command=self._clear_cache,
                           bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                           activebackground="#2a3244", activeforeground=FG,
                           cursor="hand2")
        cc_btn.pack(side="left", padx=8)
        Tooltip(cc_btn,
                "DNS answers are cached in RAM inside the running proxy —\n"
                "nothing is written to disk. The cache refills automatically\n"
                "as you browse. Clearing drops every saved answer, so the\n"
                "next connections do brand-new DoH lookups (use after a\n"
                "network change, or if a site moved to a new server).")
        cr_btn = tk.Button(btns, text="Copy report", command=self._copy_diag_report,
                           bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                           activebackground="#2a3244", activeforeground=FG,
                           cursor="hand2")
        cr_btn.pack(side="right")
        Tooltip(cr_btn,
                "Copy everything above to the clipboard — perfect for "
                "attaching to a bug report.")
        cols = ("check", "result", "details")
        self.diag_tree = ttk.Treeview(diagf, columns=cols, show="headings", height=13)
        for cid, text, w in (("check", "Check", 220), ("result", "Result", 90),
                             ("details", "Details", 420)):
            self.diag_tree.heading(cid, text=text)
            self.diag_tree.column(cid, width=w, anchor="w")
        self.diag_tree.tag_configure("section", font=("Segoe UI Semibold", 9),
                                     background="#1b2130")
        self.diag_tree.tag_configure("ok", foreground=OK)
        self.diag_tree.tag_configure("fail", foreground=ERR)
        self.diag_tree.tag_configure("warn", foreground=WARN)
        self.diag_tree.tag_configure("info", foreground=MUTED)
        self.diag_tree.pack(fill="both", expand=True, pady=(10, 0))
        Tooltip(self.diag_tree,
                "Diagnostic results: green = pass, amber = needs attention, "
                "red = failed. Rows appear as each check finishes.")
        self._diag_queue = []
        self._diag_lock = threading.Lock()
        self._diag_results = []          # (section, check, result, details) for report
        self._diag_running = False
        self.root.after(200, self._pump_diag)

    # -- diagnostics helpers -------------------------------------------------
    def _diag_section(self, title):
        with self._diag_lock:
            self._diag_queue.append(("section", title, "", ""))

    def _diag_result(self, check, result, details="", tag="info"):
        with self._diag_lock:
            self._diag_queue.append(("result", check, result, details, tag))

    def _pump_diag(self):
        try:
            with self._diag_lock:
                msgs = list(self._diag_queue)
                self._diag_queue.clear()
            for m in msgs:
                if m[0] == "section":
                    self._diag_results.append((m[1], "", "", ""))
                    iid = self.diag_tree.insert("", "end", values=(m[1], "", ""), tags=("section",))
                else:
                    _, check, result, details, tag = m
                    self._diag_results.append(("", check, result, details))
                    iid = self.diag_tree.insert("", "end", values=(check, result, details), tags=(tag,))
                if self.diag_tree.yview()[1] >= 0.99:
                    self.diag_tree.see(iid)   # Treeview.see() needs an item id, not "end"
            self.root.after(200, self._pump_diag)
        except Exception as exc:  # noqa: BLE001 — never stop the diag pump
            if getattr(self, "_closing", None) and self._closing.is_set():
                return
            try:
                self.log.error(f"diagnostics pump error: {exc}")
            except Exception:
                pass
            try:
                self.root.after(200, self._pump_diag)
            except (tk.TclError, RuntimeError):
                return

    def _stat_card(self, parent, key, label, initial):
        card = tk.Frame(parent, bg="#1b2130", padx=14, pady=10)
        card.pack(side="left", padx=(0, 10))
        tips = {
            "connections": "Total connections made through HookIP this "
                           "session (counts attempts, good or bad).",
            "active": "Connections open right now — normally a handful.",
            "failed": "Attempts that failed after every strategy: real "
                      "connectivity problems, not dead ad domains.",
            "blocked": "Hosts refused at DNS level (dead or blocked "
                       "ad/tracker endpoints) — expected and harmless.",
            "up": "Total data sent through the proxy this session.",
            "down": "Total data received through the proxy this session.",
        }
        Tooltip(card, tips.get(key, ""))
        colors = {"failed": (ERR, FG), "active": (OK, FG), "blocked": (WARN, FG)}   # (lit color, normal)
        lit, normal = colors.get(key, (FG, FG))
        val = tk.Label(card, text=str(initial), font=("Segoe UI Semibold", 15),
                       bg="#1b2130", fg=normal if initial == 0 else lit)
        val.pack()
        tk.Label(card, text=label, bg="#1b2130", fg=MUTED,
                 font=("Segoe UI", 9)).pack()
        val._lit, val._normal = lit, normal
        self.dash_vars[key] = val

    # ------------------------------------------------------------------
    def _recover_stale_proxy(self):
        """Startup recovery after an unexpected crash: if the app died while
        the proxy was active, Windows still routes everything through a
        HookIP port nobody listens on — the user 'can't connect'. The saved
        backup surviving a clean stop means exactly that happened."""
        try:
            cur = winproxy.read_current()
        except OSError:
            return
        if self.running or not winproxy._is_ours(cur):
            return
        if winproxy.has_backup():
            # backup exists only when the last activation never stopped
            # cleanly (clean stop deletes it) — restore the original settings
            if winproxy.restore_from_file():
                winproxy.clear_runonce()   # stale crash-cleanup entry
                self.log.ok("Recovered from a crash: system proxy restored to "
                            "your previous settings — internet should work again.")
                notify.notify("HookIP — internet restored",
                              "The app crashed earlier and Windows was still "
                              "pointed at it. Your original connection is back.",
                              timeout_s=12)
                return
        # no backup, but the registry still points at our own port
        port_s = f"127.0.0.1:{self.cfg.port}"
        if port_s in str(cur.get("ProxyServer") or "") or \
                port_s in str(cur.get("AutoConfigURL") or ""):
            winproxy.remove_proxy()
            self.log.ok("Recovered from a crash: stale HookIP proxy settings "
                        "cleared — internet set to direct connection.")

    def _manual_restore(self):
        """'Restore internet' button: fix a system proxy left pointing at a
        dead HookIP port (crash, watchdog failure, power loss)."""
        if self.running:
            self.stop_proxy()   # stopping already restores from backup (+ toast)
            self.log.ok("Proxy stopped — internet restored to your previous settings.")
            return
        try:
            cur = winproxy.read_current()
        except OSError as exc:
            self.log.error(f"Cannot read proxy settings: {exc}")
            return
        try:
            if winproxy.has_backup() and winproxy.restore_from_file():
                self.log.ok("Internet restored: system proxy set back to your "
                            "previous settings.")
                notify.notify("HookIP — internet restored",
                              "Windows points at your original connection again.")
            elif winproxy._is_ours(cur):
                winproxy.remove_proxy()
                self.log.ok("Internet restored: HookIP proxy settings cleared "
                            "(direct connection).")
                notify.notify("HookIP — internet restored",
                              "Stale HookIP proxy settings cleared — direct "
                              "connection is back.")
            else:
                self.log.info("Nothing to restore — system proxy is already "
                              + winproxy.describe(cur))
        except OSError as exc:
            self.log.error(f"Restore failed: {exc}")

    def toggle(self):
        if self.running:
            self.stop_proxy()
        else:
            self.start_proxy()

    def start_proxy(self):
        if self.running:
            return
        self._apply_settings_from_ui()
        cfg = self.cfg
        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError(port)
            cfg.port = port
            frag = int(self.frag_var.get())
            if not (1 <= frag <= 255):
                raise ValueError(frag)
            cfg.fragment_size = frag
            cfg.strategy = self.strategy_var.get()
            if cfg.strategy not in ("smart", "chunk", "random"):
                cfg.strategy = "smart"
            cfg.proxy_mode = self.mode_var.get()
            cfg.doh_enabled = self.doh_var.get()
            cfg.verbose = self.verbose_var.get()
            cfg.remember = self.remember_var.get()
            cfg.minimize_to_tray = self.tray_var.get()
            cfg.excluded = self._parse_excluded()
            self.log.verbose = cfg.verbose
        except ValueError as exc:
            bad = exc.args[0] if exc.args else None
            if isinstance(bad, int) and not (1 <= bad <= 255) and 1 <= bad <= 65535:
                self.log.error(f"Fragment size must be 1–255 (you typed {bad}).")
            else:
                self.log.error("Local port must be a number from 1 to 65535.")
            self.log.info("Check the red-highlighted field in Settings.")
            return

        self.log.info(f"Starting proxy on 127.0.0.1:{cfg.port} …")
        try:
            self.proxy = ProxyServer(cfg, self.log, self.stats, self.pac_token)
            self.proxy.on_accept_death = self._on_accept_death
            self.proxy.start()
        except OSError as exc:
            self.log.error(f"Cannot bind port {cfg.port}: {exc}")
            self.proxy = None
            return

        # system proxy + crash safety
        try:
            self.log.info("Current system proxy: " + winproxy.describe(winproxy.read_current()))
            if cfg.proxy_mode == "manual":
                winproxy.apply_manual(cfg.port, bypass=cfg.excluded)
            elif cfg.proxy_mode == "pac":
                winproxy.apply_pac(cfg.port, self.pac_token)
            else:
                winproxy.apply_both(cfg.port, self.pac_token, bypass=cfg.excluded)
            self.watchdog.start(cfg.port)
            winproxy.set_runonce()
            self.log.ok("System proxy configured. Crash protection active.")
        except OSError as exc:
            self.log.warn(f"System proxy not fully configured: {exc}")

        if cfg.remember:
            cfg.save()
        else:
            # user chose not to remember — forget any previously stored settings
            try:
                if os.path.isfile(SETTINGS_PATH):
                    os.remove(SETTINGS_PATH)
            except OSError:
                pass
        self.running = True
        self._set_running_ui(True)
        notify.notify("HookIP is protecting you",
                      f"Proxy running on 127.0.0.1:{cfg.port}.\n"
                      "Close (X) hides to the tray; Stop restores your "
                      "internet.")
        # restricted-network probe (captive portals, proxy-only Wi-Fi):
        # direct, unproxied NCSI test — this is exactly the path app
        # installers and Windows services use, so its failure predicts
        # 'app install refuses to connect'
        threading.Thread(target=self._captive_probe, daemon=True).start()

    def _captive_probe(self):
        try:
            s = socket.create_connection(("www.msftconnecttest.com", 80), timeout=6)
            s.sendall(b"GET /connecttest.txt HTTP/1.1\r\nHost: "
                      b"www.msftconnecttest.com\r\nConnection: close\r\n\r\n")
            resp = s.recv(4096).decode(errors="replace")
            s.close()
            body = resp.split("\r\n\r\n", 1)[-1].strip()
            if "Microsoft Connect Test" in body:
                self.log.debug("Restricted-network probe: direct unproxied "
                               "internet works.")
            else:
                first = resp.split("\r\n", 1)[0].strip()
                self.log.warn(
                    "This network looks RESTRICTED or behind a captive "
                    "portal (probe answered: " + (first or "no data") + "). "
                    "Log into the network's portal in a browser first — "
                    "until then app installs and Store downloads may "
                    "refuse to connect. Stopping HookIP also removes any "
                    "interference from our side.")
        except OSError as exc:
            self.log.warn(
                "Direct unproxied internet probe failed (" + str(exc) + "). "
                "This network limits direct traffic — app installs (Store "
                "downloads, Windows services) do not go through HookIP and "
                "may refuse to connect here regardless of the proxy. Browsing "
                "through HookIP is unaffected.")

    def _on_accept_death(self):
        """The listener died while Windows still points at it — without this
        hook the user's internet would be broken and the app would still say
        'Running'. Emergency: restore the original proxy settings NOW."""
        try:
            self.log.error("Proxy listener died unexpectedly — restoring your "
                           "internet immediately.")
            notify.notify("HookIP — proxy crashed",
                          "The proxy stopped unexpectedly; your original "
                          "internet settings were restored.", timeout_s=12)
            self._emergency_restore()
        except Exception:
            pass

    def _emergency_restore(self):
        """Stop everything and put Windows back on the user's own settings,
        even if the proxy object is half-dead."""
        self.running = False
        try:
            if self.proxy:
                try:
                    self.proxy.stop()
                except Exception:
                    pass
            self.proxy = None
            try:
                self.watchdog.stop()
                winproxy.clear_runonce()
            except Exception:
                pass
            if winproxy.has_backup():
                winproxy.restore_from_file()
            else:
                winproxy.remove_proxy()
            self.log.ok("Emergency restore done — internet is back.")
        except Exception as exc:
            self.log.error(f"Emergency restore failed: {exc}")
        self._set_running_ui(False)

    def stop_proxy(self, tell_user=True):
        if not self.running:
            return
        self.running = False
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        try:
            self.watchdog.stop()
            winproxy.clear_runonce()
            if winproxy.restore_from_file():
                self.log.ok("System proxy restored to previous settings.")
            else:
                # no backup (e.g. wiped while running) — clear our own entries
                cur = winproxy.read_current()
                ours = "127.0.0.1" in str(cur.get("ProxyServer") or "") or \
                    "127.0.0.1" in str(cur.get("AutoConfigURL") or "")
                if ours:
                    winproxy.remove_proxy()
                    self.log.ok("Proxy backup missing — cleared HookIP proxy settings (direct connection).")
                else:
                    self.log.warn("No proxy backup found and current proxy is not HookIP's; left untouched.")
        except OSError as exc:
            self.log.error(f"Restore failed: {exc}")
        self._set_running_ui(False)
        if tell_user:
            notify.notify("HookIP — internet restored",
                          "Proxy stopped. Your normal connection is back.")

    def _set_running_ui(self, running):
        self.start_btn.configure(
            text="⏹  Stop" if running else "▶  Start",
            bg=ERR if running else OK,
            activebackground="#ff6b6b" if running else "#46c06a")
        if getattr(self, "start_tip", None):
            self.start_tip.set_text(
                "⏹ Stop the proxy and restore your previous internet "
                "settings (you will get a confirmation notification)."
                if running else
                "▶ Turn the proxy on: fragments TLS handshakes so DPI can't "
                "read the site name, and points Windows at HookIP.\n"
                "Also sends a 'protecting you' notification.")
        self.status_pill.configure(
            text="● Running" if running else "● Stopped",
            fg=OK if running else MUTED)
        if self.tray.available:
            self.tray.set_tip(f"{APP_NAME} — {'running' if running else 'stopped'}")
        try:
            self.root.title(f"{APP_NAME} v{__version__} — "
                            f"{'running' if running else 'stopped'}")
        except (tk.TclError, RuntimeError):
            pass
        state = "disabled" if running else "normal"
        for w in self.set_widgets:
            try:
                w.configure(state=state)
            except tk.TclError:
                pass
        self.nb.select(0 if running else self.nb.index(self.nb.select()))

    # ------------------------------------------------------------------
    def _apply_settings_from_ui(self):
        pass  # read directly in start_proxy

    @staticmethod
    def _log_semantic_tag(msg):
        """Extra color tag for known debug-stream patterns."""
        if msg.startswith("DoH "):
            return "doh"
        if msg.startswith("resolve "):
            return "res"
        if ": smart fragment" in msg or "relay closed" in msg or ": attempt " in msg:
            return "dim"
        return None

    def _pump_log(self):
        try:
            entries = self.log.drain()
            if entries:
                self._log_all.extend(entries)
                if len(self._log_all) > 3000:
                    self._log_all = self._log_all[-3000:]
                new_entries = [e for e in entries
                               if logutil.LEVEL_RANK.get(e[0], 1) >= self._log_min_rank]
                if new_entries:
                    self.log_text.configure(state="normal")
                    # decide BEFORE inserting — insertion itself shifts the view
                    at_bottom = self.log_text.yview()[1] >= 0.98
                    for level, ts, msg in new_entries:
                        extra = self._log_semantic_tag(msg)
                        tags = (level, extra) if extra else (level,)
                        self.log_text.insert("end", f"[{ts}] ", "ts")
                        self.log_text.insert("end", f"{msg}\n", tags)
                    self.log_text.configure(state="disabled")
                    # follow new lines only when the reader was already at the
                    # bottom — otherwise scrolling up gets yanked back down
                    if at_bottom:
                        self.log_text.see("end")
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > 2500:
                self.log_text.delete("1.0", f"{lines - 2000}.0")
            self.root.after(250, self._pump_log)
        except Exception as exc:  # noqa: BLE001 — never stop the log pump;
            # only a real shutdown may end it (stray RuntimeErrors used to
            # kill the pump silently, freezing the log)
            if getattr(self, "_closing", None) and self._closing.is_set():
                return
            try:
                self.log.error(f"log pump error: {exc}")
            except Exception:
                pass
            try:
                self.root.after(250, self._pump_log)
            except (tk.TclError, RuntimeError):
                return

    def _apply_log_filter(self):
        names = ["Everything", "Info and above", "Warnings and above", "Errors only"]
        ranks = [0, 1, 2, 3]
        self._log_min_rank = ranks[names.index(self.log_filter.get())]
        # re-render the visible log from the in-app history
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            today = time.strftime("%Y-%m-%d")
            for level, ts, msg in self._log_all:
                if logutil.LEVEL_RANK.get(level, 1) >= self._log_min_rank:
                    extra = self._log_semantic_tag(msg)
                    tags = (level, extra) if extra else (level,)
                    self.log_text.insert("end", f"[{ts}] ", "ts")
                    self.log_text.insert("end", f"{msg}\n", tags)
            self.log_text.configure(state="disabled")
            self.log_text.see("end")
        except tk.TclError:
            pass

    def _log_report_text(self, min_rank=None):
        rank = self._log_min_rank if min_rank is None else min_rank
        today = time.strftime("%Y-%m-%d")
        lines = [f"HookIP {__version__} log — {today}"]
        for level, ts, msg in self._log_all:
            if logutil.LEVEL_RANK.get(level, 1) >= rank:
                lines.append(f"[{today} {ts}] [{level.upper():5}] {msg}")
        return "\n".join(lines)

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=time.strftime("hookip_log_%Y%m%d_%H%M%S.log"),
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._log_report_text(min_rank=0))
            self.log.ok(f"Log exported to {path}")
        except OSError as exc:
            self.log.error(f"Log export failed: {exc}")

    def _copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._log_report_text(min_rank=0))
        self.log.info("Log copied to clipboard.")

    def _refresh_dashboard(self):
        try:
            total, active, up, down, failed, blocked = self.stats.totals()
            live_port = self.cfg.port if self.running else (
                self.port_var.get() if self.port_var.get().isdigit()
                else str(self.cfg.port))
            port_txt = f"127.0.0.1:{live_port}"
            if self.port_badge.cget("text") != port_txt:
                self.port_badge.configure(text=port_txt)
            self.dash_vars["connections"].configure(text=str(total))
            av = self.dash_vars["active"]
            av.configure(text=str(active), fg=av._lit if active else av._normal)
            fv = self.dash_vars["failed"]
            fv.configure(text=str(failed), fg=fv._lit if failed else fv._normal)
            bv = self.dash_vars["blocked"]
            bv.configure(text=str(blocked), fg=bv._lit if blocked else bv._normal)
            self.dash_vars["down"].configure(text=self._fmt_bytes(down))
            self.dash_vars["up"].configure(text=self._fmt_bytes(up))
            # crash protection must never silently vanish: the watchdog is a
            # separate process and can die without anyone noticing
            if self.running:
                if not self.watchdog.alive():
                    self._wd_restarts = getattr(self, "_wd_restarts", 0) + 1
                    if self._wd_restarts <= 3:
                        try:
                            self.watchdog.start(self.cfg.port)
                            self.log.warn("Watchdog died — restarted "
                                          "automatically (crash protection "
                                          "was unprotected).")
                        except OSError:
                            pass
                else:
                    self._wd_restarts = 0
            self._draw_spark()
            top = self.stats.top_domains()
            key = str(top)
            if key != getattr(self, "_last_top", None):
                self._last_top = key
                for iid in self.dom_tree.get_children():
                    self.dom_tree.delete(iid)
                for host, conns, bup, bdown in top:
                    self.dom_tree.insert("", "end", values=(
                        host, conns, self._fmt_bytes(bup), self._fmt_bytes(bdown)))
        except Exception as exc:  # noqa: BLE001 — one bad frame must not
            # permanently kill the dashboard (it would freeze silently)
            if getattr(self, "_closing", None) and self._closing.is_set():
                return
            try:
                self.log.error(f"dashboard refresh error: {exc}")
            except Exception:
                pass
        try:
            self.root.after(500, self._refresh_dashboard)
        except (tk.TclError, RuntimeError):
            return

    def _draw_spark(self):
        self.spark.delete("all")
        w = max(50, self.spark.winfo_width() - 8)
        h = self.spark.winfo_height() - 8
        samples = list(self.stats.samples)[-180:]
        if not self.running:
            self.spark.create_text(
                w // 2, max(12, h // 2), text="stopped — live traffic appears here",
                fill=MUTED, font=("Segoe UI", 9))
            return
        if len(samples) < 2 or h <= 14:
            return
        peak = max((max(u, d) for u, d in samples), default=1.0) or 1.0
        step = w / max(1, len(samples) - 1)

        def line(idx, color):
            pts = []
            for i, (u, d) in enumerate(samples):
                v = u if idx == 0 else d
                y = h - 4 - (v / peak) * (h - 10)
                pts.append(4 + i * step)
                pts.append(max(2, y))
            if len(pts) >= 4:
                self.spark.create_line(*pts, fill=color, width=1.6, smooth=True)

        line(0, ACCENT)     # up
        line(1, OK)         # down
        # live rate right now (last sample)
        if samples:
            u_now, d_now = samples[-1]
            self.spark.create_text(
                10, 12, anchor="w",
                text=f"now ↓{self._fmt_bytes(d_now)}/s  ↑{self._fmt_bytes(u_now)}/s",
                fill=FG, font=("Segoe UI", 8))
        self.spark.create_text(w - 10, 12, anchor="e",
                               text=f"peak {self._fmt_bytes(peak)}/s",
                               fill=MUTED, font=("Segoe UI", 8))

    @staticmethod
    def _fmt_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if abs(n) < 1024:
                return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
            n /= 1024
        return f"{n:.1f} TB"

    # ------------------------------------------------------------------
    def _hook_exception_logging(self):
        """Persist every uncaught error to the session log — even after the
        app closes or crashes, the file on disk shows what went wrong."""
        def fmt(val):
            return "".join(traceback.format_exception_only(type(val), val)).strip()

        def tk_exc(_exc, val, _tb):
            try:
                self.log.error(f"Internal error: {fmt(val)}")
            except Exception:
                pass

        def th_exc(args):
            if args.exc_type is SystemExit:
                return
            name = args.thread.name if args.thread else "thread"
            try:
                self.log.error(f"Internal error in {name}: {fmt(args.exc_value)}")
            except Exception:
                pass

        self.root.report_callback_exception = tk_exc
        threading.excepthook = th_exc

    def _clear_cache(self):
        if not self.proxy:
            self.log.info("The DNS cache lives in RAM inside a running proxy "
                          "(nothing is stored on disk) — start the proxy first.")
            return
        r = self.proxy.resolver
        pos, neg = r.cache_stats()
        if pos + neg == 0:
            self.log.info("DNS cache is already empty — entries build up "
                          "automatically as you browse.")
            return
        sample = ", ".join(r.cache_hosts()[:5])
        more = f" (+{pos - 5} more)" if pos > 5 else ""
        r.clear_cache()
        pos2, neg2 = r.cache_stats()
        self.log.ok(
            f"DNS cache cleared: {pos} host entries and {neg} negative "
            f"(blocked/NXDOMAIN) entries dropped"
            f"{f' — e.g. {sample}{more}' if sample else ''}. "
            f"Before: {pos}+{neg}, after: {pos2}+{neg2}. New lookups start "
            "immediately as you browse.")

    def run_diagnostics(self, sections="all"):
        """sections: 'all' | 'dns' | 'tunnel' | 'system'"""
        if self._diag_running:
            self.log.info("Diagnostics are already running — one moment.")
            return
        self._diag_running = True
        for iid in self.diag_tree.get_children():
            self.diag_tree.delete(iid)
        self._diag_results = []
        for b in self._diag_buttons:
            b.configure(state="disabled")
        self._diag_result("Diagnostics", "running", time.strftime("%H:%M:%S"), "info")

        def work():
            try:
                if sections in ("all", "system"):
                    self._diag_system()
                if sections == "all":
                    self._diag_settings()
                if sections in ("all", "dns"):
                    self._diag_dns()
                if sections in ("all", "tunnel"):
                    self._diag_tunnel()
                self._diag_result("Summary", "done", "", "info")
            except Exception as exc:  # noqa: BLE001
                self._diag_result("Diagnostics", "error", str(exc), "fail")
            finally:
                self._diag_running = False
                self._ui_queue.put(("diag_done", ()))

        threading.Thread(target=work, daemon=True).start()

    def _diag_settings(self):
        """Sanity of the numeric settings + port availability."""
        self._diag_section("Settings")
        try:
            port = int(self.port_var.get())
            ok = 1 <= port <= 65535
            self._diag_result("Local port", "OK" if ok else "FAIL",
                              f"{port}" if ok else f"{port} is not in 1–65535",
                              "ok" if ok else "fail")
            if ok:
                if self.running and port == self.cfg.port:
                    self._diag_result("Port availability", "OK",
                                      "in use by HookIP itself (running)", "ok")
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        s.bind(("127.0.0.1", port))
                        self._diag_result("Port availability", "OK", f"{port} is free", "ok")
                    except OSError as exc:
                        self._diag_result("Port availability", "WARN",
                                          f"{port} is already in use — Start would "
                                          f"refuse it ({exc})", "warn")
                    finally:
                        s.close()
        except (ValueError, tk.TclError):
            self._diag_result("Local port", "FAIL", "not a number (1–65535)", "fail")
        try:
            frag = int(self.frag_var.get())
            ok = 1 <= frag <= 255
            self._diag_result("Fragment size", "OK" if ok else "FAIL",
                              f"{frag} bytes" if ok else f"{frag} is not in 1–255",
                              "ok" if ok else "fail")
        except (ValueError, tk.TclError):
            self._diag_result("Fragment size", "FAIL", "not a number (1–255)", "fail")
        pats = self._parse_excluded()
        self._diag_result("Excluded domains", "OK", f"{len(pats)} valid pattern(s)", "ok")
        try:
            Config.save(self.cfg)
            self._diag_result("Settings file", "OK", SETTINGS_PATH, "ok")
        except OSError as exc:
            self._diag_result("Settings file", "WARN", f"cannot save: {exc}", "warn")

    def _diag_system(self):
        self._diag_section("System")
        import platform
        self._diag_result("Environment", "info",
                          f"HookIP {__version__} · Python {sys.version.split()[0]} · "
                          f"{platform.system()} {platform.release()} ({platform.machine()})")
        cur = winproxy.read_current()
        self._diag_result("System proxy", "info", winproxy.describe(cur))
        # stale-proxy detection: registry points at HookIP while we're off
        if not self.running and winproxy._is_ours(cur):
            port_s = f"127.0.0.1:{self.cfg.port}"
            stale = (winproxy.has_backup() or
                     port_s in str(cur.get("ProxyServer") or "") or
                     port_s in str(cur.get("AutoConfigURL") or ""))
            if stale:
                self._diag_result("Stale proxy detected", "WARN",
                                  "Windows still routes traffic through a HookIP "
                                  "port nobody is listening on — press '↺ Restore "
                                  "internet' to fix", "warn")
        self._diag_result("Crash protection",
                          "active" if self.watchdog.alive() else "inactive",
                          "watchdog process" if self.watchdog.alive() else "", "info")
        # antivirus (helps interpret Defender false positives)
        try:
            ps = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "$s = Get-MpComputerStatus; "
                 "Write-Output ('enabled=' + $s.AntivirusEnabled); "
                 "Write-Output ('sig=' + $s.AntivirusSignatureVersion); "
                 "Write-Output ('updated=' + $s.AntivirusSignatureLastUpdated); "
                 "$d = Get-MpThreatDetection | Where-Object { $_.Resources -like '*HookIP*' }; "
                 "Write-Output ('hookip_detections=' + ($d | Measure-Object).Count)"],
                capture_output=True, text=True, timeout=20, creationflags=0x08000000)
            info = dict(line.split("=", 1) for line in ps.stdout.strip().splitlines() if "=" in line)
            if info.get("enabled") == "True":
                det = info.get("hookip_detections", "0")
                self._diag_result("Windows Defender", "info",
                                  f"enabled · definitions {info.get('sig', '?')} "
                                  f"(updated {info.get('updated', '?')}) · "
                                  f"{det} past HookIP detection(s)")
            else:
                self._diag_result("Windows Defender", "info", "antivirus disabled or not found")
        except (OSError, subprocess.SubprocessError) as exc:
            self._diag_result("Windows Defender", "info", f"status unavailable ({type(exc).__name__})")

    def _diag_dns(self):
        self._diag_section("DNS resolvers (DNS-over-HTTPS)")
        try:
            frag = max(1, int(self.frag_var.get()))
        except (ValueError, tk.TclError, RuntimeError):
            frag = max(1, self.cfg.fragment_size)
        query = dnsmsg.encode_query("example.com")
        ok_count = 0
        for name, host, ip in RESOLVERS:
            t0 = time.time()
            try:
                conn = _DoHConn(ip, host, timeout=4, chunk=frag)
                try:
                    resp = conn.request(host, query)
                    rcode, answers = dnsmsg.parse_response(resp)
                    ips = dnsmsg.extract_ips(answers, 1)
                    dt = time.time() - t0
                    if rcode == 0 and ips:
                        ok_count += 1
                        self._diag_result(name, "OK", f"{dt:.2f}s · A records: {', '.join(ips[:2])}", "ok")
                    else:
                        self._diag_result(name, "WARN", f"{dt:.2f}s · rcode={rcode}", "warn")
                finally:
                    conn.close()
            except Exception as exc:  # noqa: BLE001
                self._diag_result(name, "FAIL",
                                  f"{time.time()-t0:.2f}s · {type(exc).__name__}: {exc}", "fail")
        tag = ("ok" if ok_count == len(RESOLVERS)
               else ("warn" if ok_count else "fail"))
        self._diag_result("DNS summary", f"{ok_count}/{len(RESOLVERS)} reachable", "", tag)

    def _diag_tunnel(self):
        self._diag_section("End-to-end tunnel through HookIP")
        if not (self.running and self.proxy):
            self._diag_result("Tunnel test", "skipped", "start the proxy first", "info")
            return
        ok_count = 0
        sites = ("github.com", "wikipedia.org")
        for site in sites:
            t0 = time.time()
            try:
                result = self._tunnel_test(site, 443)
                if result:
                    ok_count += 1
                    self._diag_result(f"{site}:443", "OK",
                                      f"{time.time()-t0:.2f}s · {result}", "ok")
                else:
                    self._diag_result(f"{site}:443", "FAIL", "no HTTP response", "fail")
            except Exception as exc:  # noqa: BLE001
                self._diag_result(f"{site}:443", "FAIL",
                                  f"{time.time()-t0:.2f}s · {exc}", "fail")
        self._diag_result("Tunnel summary", f"{ok_count}/{len(sites)} reachable", "",
                          "ok" if ok_count == len(sites) else ("warn" if ok_count else "fail"))

    def _copy_diag_report(self):
        lines = [f"HookIP {__version__} diagnostic report — {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        for section, check, result, details in self._diag_results:
            if section and not check:
                lines.append(f"\n== {section} ==")
            elif check:
                lines.append(f"  {check:<24} {result:<8} {details}")
        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log.info("Diagnostic report copied to clipboard.")

    def _tunnel_test(self, host, port):
        """Drive a real CONNECT + TLS handshake through our own proxy."""
        local_port = self.cfg.port if self.running else int(self.port_var.get())
        with socket.create_connection(("127.0.0.1", local_port), timeout=10) as s:
            s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                part = s.recv(4096)
                if not part:
                    raise OSError("proxy closed")
                resp += part
            if b" 200 " not in resp.split(b"\r\n", 1)[0]:
                raise OSError(resp.split(b"\r\n", 1)[0].decode(errors="replace"))
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname=host)
            try:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                            b"\r\nConnection: close\r\n\r\n")
                data = tls.recv(512)
                return data.split(b"\r\n", 1)[0].decode(errors="replace")
            finally:
                tls.close()

    def _on_close_request(self):
        """X button: hide to tray when tray mode is on — the proxy keeps
        running and the tray icon is the way back. Real exit lives in the
        tray menu (or on the X when tray is disabled)."""
        try:
            if self.tray.available and self.tray_var.get():
                self.root.withdraw()
                self.log.info("Hidden to tray — right-click the tray icon "
                              "to restore, start/stop the proxy, or exit.")
                return
        except (tk.TclError, RuntimeError):
            pass
        self.on_close()

    def on_close(self):
        try:
            self._closing.set()
            if self.running:
                self.stop_proxy(tell_user=False)   # no toast during exit
            self.cfg.minimize_to_tray = self.tray_var.get()
            if self.cfg.remember:
                self.cfg.save()
            self.log.session_end()
            self.log.close_file()
            try:
                self.tray.stop()
            except Exception:
                pass
        finally:
            self.root.destroy()


def run():
    # Single instance: if another HookIP is running, activate it and exit.
    mutex = winproxy.acquire_single_instance()
    if mutex is None:
        root = tk.Tk()
        root.withdraw()
        if winproxy.notify_running_instance():
            tk.messagebox.showinfo(
                APP_NAME,
                f"{APP_NAME} is already running —\nit was brought to the front instead.")
        else:
            tk.messagebox.showwarning(
                APP_NAME,
                f"{APP_NAME} is already running.\n"
                f"Close the other instance before starting a new one.")
        root.destroy()
        return
    root = tk.Tk()
    app = App(root)
    root.mainloop()
    try:
        import ctypes
        ctypes.windll.kernel32.CloseHandle(mutex)
    except Exception:
        pass

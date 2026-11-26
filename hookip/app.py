"""HookIP desktop app (tkinter, dark theme)."""
import os
import queue
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
from .config import Config, SETTINGS_PATH
from .logutil import Log
from .proxy import ProxyServer, Stats
from . import winproxy
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
        self.pac_token = secrets.token_hex(8)
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
        self._recover_stale_proxy()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_request)
        # system tray (optional, hides when minimized)
        self.tray = TrayIcon(f"{APP_NAME} — stopped")
        self.tray.start()
        if self.tray.available:
            self.root.bind("<Unmap>", self._on_unmap)
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
                while True:
                    if winproxy._k32.WaitForSingleObject(ev, 1000) == 0:
                        try:
                            self.root.after(0, self._show_self)
                        except (RuntimeError, tk.TclError):
                            return
                    if not self.root.winfo_exists():
                        return

            threading.Thread(target=watcher, daemon=True).start()
        except Exception:
            pass

    def _on_unmap(self, event):
        """Minimize → hide to tray (when enabled). The tray icon is the way
        back; the second-instance activation also restores it."""
        if event.widget is not self.root:
            return
        try:
            if self.root.state() == "iconic" and self.tray_var.get():
                self.root.after(10, self.root.withdraw)   # after the iconic animation
        except (tk.TclError, RuntimeError):
            pass

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
        except (tk.TclError, RuntimeError):
            return
        self.root.after(120, self._pump_tray)

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

    def check_updates(self):
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
        self.root.after(0, lambda: self._update_result(latest, url))

    @staticmethod
    def _ver_tuple(s):
        try:
            return tuple(int(p) for p in s.lstrip("v").split(".")[:3])
        except ValueError:
            return (0,)

    def _update_result(self, latest, url):
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
            self.root.lift()
            self.root.focus_force()
        except (tk.TclError, RuntimeError):
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
        self.port_badge = tk.Label(head, text=f"127.0.0.1:{self.cfg.port}",
                                   font=("Consolas", 10), bg="#202634", fg=MUTED,
                                   padx=10, pady=3)
        self.port_badge.pack(side="left")
        self.start_btn = tk.Button(head, text="▶  Start", command=self.toggle,
                                   font=("Segoe UI Semibold", 12), bd=0, cursor="hand2",
                                   bg=OK, fg="white", activebackground="#46c06a",
                                   activeforeground="white", padx=26, pady=8)
        self.start_btn.pack(side="right")
        self.restore_btn = tk.Button(head, text="↺  Restore internet",
                                     command=self._manual_restore,
                                     font=("Segoe UI", 10), bd=0, cursor="hand2",
                                     bg="#202634", fg=FG, activebackground="#2a3244",
                                     activeforeground=FG, padx=14, pady=8)
        self.restore_btn.pack(side="right", padx=(0, 10))
        self.update_pill = tk.Label(head, text="", font=("Segoe UI", 10),
                                    bg=BG, fg=MUTED, cursor="hand2", padx=6)
        self.update_pill.pack(side="right", padx=(0, 4))
        self.update_pill.bind("<Button-1>", self._update_pill_click)
        # flat-button hover feedback (header buttons)
        for btn, hot, cold in ((self.restore_btn, "#2a3244", "#202634"),):
            btn.bind("<Enter>", lambda e, b=btn, c=hot: b.configure(bg=c))
            btn.bind("<Leave>", lambda e, b=btn, c=cold: b.configure(bg=c))

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
        tk.Label(dash, text="Top domains this session", bg=PANEL, fg=MUTED).pack(anchor="w", pady=(14, 2))
        cols = ("domain", "conns", "up", "down")
        self.dom_tree = ttk.Treeview(dash, columns=cols, show="headings", height=7)
        for cid, text, w in (("domain", "Domain", 320), ("conns", "Conns", 70),
                             ("up", "Sent", 90), ("down", "Received", 100)):
            self.dom_tree.heading(cid, text=text)
            self.dom_tree.column(cid, width=w, anchor="w")
        self.dom_tree.pack(fill="both", expand=True)

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
        self.log_filter.bind("<<ComboboxSelected>>", lambda _e: self._apply_log_filter())
        tk.Button(bar, text="Save log…", command=self._export_log,
                  bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="right")
        tk.Button(bar, text="Copy all", command=self._copy_log,
                  bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="right", padx=(0, 6))
        tk.Label(bar, text=f"Session file: {self._log_file}", bg=PANEL,
                 fg=MUTED, font=("Segoe UI", 8)).pack(side="right", padx=8)
        self.log_text = tk.Text(logf, bg="#0d1017", fg=FG, insertbackground=FG,
                                font=("Consolas", 9), state="disabled", wrap="none",
                                height=10)
        self.log_text.pack(fill="both", expand=True)
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
        port_e = ttk.Entry(grid, textvariable=self.port_var, width=10)
        add_row("Local port", port_e, 0)

        self.frag_var = tk.StringVar(value=str(self.cfg.fragment_size))
        frag_e = ttk.Entry(grid, textvariable=self.frag_var, width=10)
        add_row("Fragment size (bytes)", frag_e, 1)

        self.strategy_var = tk.StringVar(value=self.cfg.strategy)
        strat_c = ttk.Combobox(grid, textvariable=self.strategy_var, width=12,
                               state="readonly",
                               values=["smart", "chunk", "random"])
        add_row("Strategy", strat_c, 2)

        self.mode_var = tk.StringVar(value=self.cfg.proxy_mode)
        mode_c = ttk.Combobox(grid, textvariable=self.mode_var, width=12,
                              state="readonly", values=["manual", "pac"])
        add_row("System proxy mode", mode_c, 3)

        self.doh_var = tk.BooleanVar(value=self.cfg.doh_enabled)
        doh_c = ttk.Checkbutton(grid, text="Use DNS-over-HTTPS (recommended)",
                                variable=self.doh_var)
        add_row("Secure DNS", doh_c, 4)

        self.verbose_var = tk.BooleanVar(value=self.cfg.verbose)
        verb_c = ttk.Checkbutton(grid, text="Verbose log", variable=self.verbose_var,
                                 command=lambda: setattr(self.log, "verbose",
                                                         self.verbose_var.get()))
        add_row("Logging", verb_c, 5)

        self.remember_var = tk.BooleanVar(value=self.cfg.remember)
        rem_c = ttk.Checkbutton(grid, text="Remember settings for next launch",
                                variable=self.remember_var)
        add_row("Persistence", rem_c, 6)

        self.tray_var = tk.BooleanVar(value=self.cfg.minimize_to_tray)
        tray_c = ttk.Checkbutton(grid, text="Minimize to system tray",
                                 variable=self.tray_var)
        add_row("Window", tray_c, 7)

        upd = tk.Frame(grid, bg=PANEL)
        tk.Button(upd, text="Check for updates", command=self.check_updates,
                  bg="#202634", fg=FG, bd=0, padx=10, pady=4,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="left")
        self.update_label = tk.Label(upd, text="", bg=PANEL, fg=MUTED,
                                     font=("Segoe UI", 9))
        self.update_label.pack(side="left", padx=10)
        add_row("Updates", upd, 8)

        tk.Label(setf, text="Excluded domains (one per line, wildcards allowed).\n"
                            "These sites connect without fragmentation — useful for\n"
                            "banking apps or anything that dislikes modified handshakes.",
                 bg=PANEL, fg=MUTED, justify="left").pack(anchor="w", pady=(10, 2))
        self.excl_text = tk.Text(setf, bg="#0d1017", fg=FG, insertbackground=FG,
                                 font=("Consolas", 9), height=5)
        self.excl_text.insert("1.0", "\n".join(self.cfg.excluded))
        self.excl_text.pack(fill="x")
        self.set_widgets.append(self.excl_text)
        tk.Label(setf, text=f"Settings file: {SETTINGS_PATH}",
                 bg=PANEL, fg=MUTED).pack(anchor="w", pady=(8, 0))

        # diagnostics ------------------------------------------------------------
        diagf = ttk.Frame(nb, style="Card.TFrame", padding=14)
        nb.add(diagf, text=" Diagnostics ")
        btns = tk.Frame(diagf, bg=PANEL)
        btns.pack(fill="x")
        for text, cmd in (("Run full check", lambda: self.run_diagnostics("all")),
                          ("DNS only", lambda: self.run_diagnostics("dns")),
                          ("Tunnel only", lambda: self.run_diagnostics("tunnel")),
                          ("System only", lambda: self.run_diagnostics("system"))):
            tk.Button(btns, text=text, command=cmd,
                      bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                      activebackground="#2a3244", activeforeground=FG,
                      cursor="hand2").pack(side="left")
        tk.Button(btns, text="Clear DNS cache", command=self._clear_cache,
                  bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="left", padx=8)
        tk.Button(btns, text="Copy report", command=self._copy_diag_report,
                  bg="#202634", fg=FG, bd=0, padx=12, pady=6,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="right")
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
        except (tk.TclError, RuntimeError):
            return   # window closing

    def _stat_card(self, parent, key, label, initial):
        card = tk.Frame(parent, bg="#1b2130", padx=14, pady=10)
        card.pack(side="left", padx=(0, 10))
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
            self.stop_proxy()   # stopping already restores from backup
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
            elif winproxy._is_ours(cur):
                winproxy.remove_proxy()
                self.log.ok("Internet restored: HookIP proxy settings cleared "
                            "(direct connection).")
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
                raise ValueError
            cfg.port = port
            frag = max(1, int(self.frag_var.get()))
            cfg.fragment_size = frag
            cfg.strategy = self.strategy_var.get()
            if cfg.strategy not in ("smart", "chunk", "random"):
                cfg.strategy = "smart"
            cfg.proxy_mode = self.mode_var.get()
            cfg.doh_enabled = self.doh_var.get()
            cfg.verbose = self.verbose_var.get()
            cfg.remember = self.remember_var.get()
            cfg.minimize_to_tray = self.tray_var.get()
            cfg.excluded = [ln.strip() for ln in self.excl_text.get("1.0", "end").splitlines()
                            if ln.strip()]
            self.log.verbose = cfg.verbose
        except ValueError:
            self.log.error("Invalid port or fragment size.")
            return

        self.log.info(f"Starting proxy on 127.0.0.1:{cfg.port} …")
        try:
            self.proxy = ProxyServer(cfg, self.log, self.stats, self.pac_token)
            self.proxy.start()
        except OSError as exc:
            self.log.error(f"Cannot bind port {cfg.port}: {exc}")
            self.proxy = None
            return

        # system proxy + crash safety
        try:
            self.log.info("Current system proxy: " + winproxy.describe(winproxy.read_current()))
            if cfg.proxy_mode == "manual":
                winproxy.apply_manual(cfg.port)
            else:
                winproxy.apply_pac(cfg.port, self.pac_token)
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

    def stop_proxy(self):
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

    def _set_running_ui(self, running):
        self.start_btn.configure(
            text="⏹  Stop" if running else "▶  Start",
            bg=ERR if running else OK,
            activebackground="#ff6b6b" if running else "#46c06a")
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
        except (tk.TclError, RuntimeError):
            return   # window closing

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
            port_txt = f"127.0.0.1:{self.cfg.port}"
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
        except (tk.TclError, RuntimeError):
            return   # window closing
        self.root.after(500, self._refresh_dashboard)

    def _draw_spark(self):
        self.spark.delete("all")
        w = max(50, self.spark.winfo_width() - 8)
        h = self.spark.winfo_height() - 8
        samples = list(self.stats.samples)[-180:]
        if len(samples) < 2:
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
        self.spark.create_text(10, 12, anchor="w", text=f"peak {self._fmt_bytes(peak)}/s",
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
        if self.proxy:
            self.proxy.resolver.clear_cache()
            self.log.info("DNS cache cleared.")

    def run_diagnostics(self, sections="all"):
        """sections: 'all' | 'dns' | 'tunnel' | 'system'"""
        if self._diag_running:
            return
        self._diag_running = True
        for iid in self.diag_tree.get_children():
            self.diag_tree.delete(iid)
        self._diag_results = []

        def work():
            try:
                if sections in ("all", "system"):
                    self._diag_system()
                if sections in ("all", "dns"):
                    self._diag_dns()
                if sections in ("all", "tunnel"):
                    self._diag_tunnel()
                self._diag_result("Summary", "done", "", "info")
            except Exception as exc:  # noqa: BLE001
                self._diag_result("Diagnostics", "error", str(exc), "fail")
            finally:
                self._diag_running = False

        threading.Thread(target=work, daemon=True).start()

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
        tag = "ok" if ok_count else ("warn" if ok_count == 0 else "fail")
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
            if self.running:
                self.stop_proxy()
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

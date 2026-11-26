"""HookIP desktop app (tkinter, dark theme)."""
import os
import secrets
import socket
import ssl
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

from . import __version__, APP_NAME
from . import dnsmsg
from .config import Config, SETTINGS_PATH
from .logutil import Log
from .proxy import ProxyServer, Stats
from . import winproxy
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
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._log_pos = 0  # kept for compatibility; pump now uses drain()
        self.root.after(250, self._pump_log)
        self.root.after(500, self._refresh_dashboard)
        self.root.after(100, self._startup_restore_check)
        self.log.info(f"{APP_NAME} {__version__} ready. Press Start to turn the proxy on.")

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
        self.log_text = tk.Text(logf, bg="#0d1017", fg=FG, insertbackground=FG,
                                font=("Consolas", 9), state="disabled", wrap="none",
                                height=10)
        self.log_text.pack(fill="both", expand=True)
        for tag, color in (("info", FG), ("ok", OK), ("warn", WARN),
                           ("error", ERR), ("debug", MUTED)):
            self.log_text.tag_configure(tag, foreground=color)

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
        tk.Button(btns, text="Run full check", command=self.run_diagnostics,
                  bg="#202634", fg=FG, bd=0, padx=14, pady=6,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="left")
        tk.Button(btns, text="Clear DNS cache", command=self._clear_cache,
                  bg="#202634", fg=FG, bd=0, padx=14, pady=6,
                  activebackground="#2a3244", activeforeground=FG,
                  cursor="hand2").pack(side="left", padx=8)
        self.diag_text = tk.Text(diagf, bg="#0d1017", fg=FG, insertbackground=FG,
                                 font=("Consolas", 9), height=14)
        self.diag_text.pack(fill="both", expand=True, pady=(10, 0))
        self._diag_queue = []
        self._diag_lock = threading.Lock()
        self.root.after(200, self._pump_diag)

    def _pump_diag(self):
        try:
            with self._diag_lock:
                msgs = list(self._diag_queue)
                self._diag_queue.clear()
            if msgs:
                for m in msgs:
                    self.diag_text.insert("end", m + "\n")
                self.diag_text.see("end")
            self.root.after(200, self._pump_diag)
        except (tk.TclError, RuntimeError):
            return   # window closing

    def _stat_card(self, parent, key, label, initial):
        card = tk.Frame(parent, bg="#1b2130", padx=14, pady=10)
        card.pack(side="left", padx=(0, 10))
        val = tk.Label(card, text=str(initial), font=("Segoe UI Semibold", 15),
                       bg="#1b2130", fg=FG)
        val.pack()
        tk.Label(card, text=label, bg="#1b2130", fg=MUTED,
                 font=("Segoe UI", 9)).pack()
        self.dash_vars[key] = val

    # ------------------------------------------------------------------
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

    def _pump_log(self):
        try:
            new_entries = self.log.drain()
            if new_entries:
                self.log_text.configure(state="normal")
                for level, ts, msg in new_entries:
                    self.log_text.insert("end", f"[{ts}] {msg}\n", level)
                self.log_text.configure(state="disabled")
                self.log_text.see("end")
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > 2500:
                self.log_text.delete("1.0", f"{lines - 2000}.0")
            self.root.after(250, self._pump_log)
        except (tk.TclError, RuntimeError):
            return   # window closing

    def _refresh_dashboard(self):
        try:
            total, active, up, down, failed = self.stats.totals()
            self.dash_vars["connections"].configure(text=str(total))
            self.dash_vars["active"].configure(text=str(active))
            self.dash_vars["failed"].configure(text=str(failed))
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
    def _clear_cache(self):
        if self.proxy:
            self.proxy.resolver.clear_cache()
            self.log.info("DNS cache cleared.")
            self._diag("DNS cache cleared.")

    def _diag(self, msg):
        with self._diag_lock:
            self._diag_queue.append(msg)

    def run_diagnostics(self):
        self.diag_text.delete("1.0", "end")
        self._diag(f"HookIP {__version__} — diagnostics\n" + "-" * 50)

        def work():
            cfg = self.cfg
            try:
                frag = max(1, int(self.frag_var.get()))
            except (ValueError, tk.TclError, RuntimeError):
                frag = max(1, cfg.fragment_size)
            # 1. system proxy state
            cur = winproxy.read_current()
            self._diag(f"\n[system proxy] {winproxy.describe(cur)}")
            # 2. resolver checks
            self._diag("\n[DoH resolvers]")
            query = dnsmsg.encode_query("example.com")
            for name, host, ip in RESOLVERS:
                t0 = time.time()
                try:
                    conn = _DoHConn(ip, host, timeout=4, chunk=frag)
                    try:
                        resp = conn.request(host, query)
                        rcode, answers = dnsmsg.parse_response(resp)
                        ips = [v for (_n, t, _tl, v) in answers if t == 1]
                        self._diag(f"  {name:<12} OK  {time.time()-t0:5.2f}s  rcode={rcode}  {ips[:2]}")
                    finally:
                        conn.close()
                except Exception as exc:  # noqa: BLE001
                    self._diag(f"  {name:<12} FAIL {time.time()-t0:5.2f}s  {exc}")
            # 3. end-to-end tunnel test (only while running)
            if self.running and self.proxy:
                self._diag("\n[end-to-end tunnel through HookIP]")
                for site in ("github.com", "wikipedia.org"):
                    try:
                        result = self._tunnel_test(site, 443)
                        if result:
                            self._diag(f"  {site}:443 → OK ({result})")
                        else:
                            self._diag(f"  {site}:443 → FAILED (no HTTP response)")
                    except Exception as exc:  # noqa: BLE001
                        self._diag(f"  {site}:443 → FAILED ({exc})")
            else:
                self._diag("\n[end-to-end tunnel] start the proxy first to test it.")
            self._diag("\nDone.")

        threading.Thread(target=work, daemon=True).start()

    def _tunnel_test(self, host, port):
        """Drive a real CONNECT + TLS handshake through our own proxy."""
        port = self.cfg.port if self.running else int(self.port_var.get())
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
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

    # ------------------------------------------------------------------
    def _startup_restore_check(self):
        """Power-loss / crash leftovers: restore saved settings and inform.
        The backup file only exists if we ran before, so a leftover
        127.0.0.1 proxy is ours with near-certainty (could also be a stale
        port from an older version)."""
        if winproxy.has_backup():
            cur = winproxy.read_current()
            proxy_str = f"{cur.get('ProxyServer') or ''}{cur.get('AutoConfigURL') or ''}"
            if "127.0.0.1" in proxy_str:
                if winproxy.restore_from_file():
                    winproxy.clear_runonce()
                    self.log.ok("Recovered system-proxy settings from a previous session.")

    def on_close(self):
        try:
            if self.running:
                self.stop_proxy()
        finally:
            self.root.destroy()


def run():
    root = tk.Tk()
    App(root)
    root.mainloop()

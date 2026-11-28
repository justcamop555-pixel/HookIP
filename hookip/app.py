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

from . import __version__, __build_id__, APP_NAME
from . import dnsmsg
from . import logutil
from .config import Config, SETTINGS_PATH, DEFAULTS
from .logutil import Log
from .perf import profile
from .proxy import ProxyServer, Stats
from .tooltips import Tooltip, NotebookTips
from . import winproxy
from . import notify
from . import vpn as vpndetect
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


def _parse_sha_file(txt):
    """First token of a .sha256 release asset -> 64-hex lowercase, or None.
    An HTML error page (or any non-hex junk) is NOT a checksum."""
    parts = (txt or "").split()
    tok = parts[0].strip().lower() if parts else None
    if tok and re.fullmatch(r"[0-9a-f]{64}", tok):
        return tok
    return None


def _sha_from_notes(txt):
    """Fallback checksum source: the release notes text the API already
    returned (github.com server side, not the asset CDN). Used only when
    it is unambiguous — exactly one 64-hex token, or one sitting next to
    the exe's name. None when nothing usable is there."""
    txt = str(txt or "")
    if not txt:
        return None
    hexes = re.findall(r"\b[0-9a-fA-F]{64}\b", txt)
    if len(hexes) == 1:
        return hexes[0].lower()
    for h in hexes:
        i = txt.find(h)
        if "HookIP.exe" in txt[max(0, i - 80):i + 80]:
            return h.lower()
    return None


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        saved = Config.load()
        # "Remember settings" unchecked → start from defaults (settings were forgotten)
        self.cfg = saved if saved.remember else Config()
        # the load-state flags must survive the swap to defaults: the
        # quarantine/degraded notices below read them, and with 'Remember
        # settings' off they used to vanish (defaults had no idea a bad
        # file had just been moved aside)
        self.cfg.quarantine_path = getattr(saved, "quarantine_path", None)
        self.cfg.degraded = getattr(saved, "degraded", False)
        self.cfg.quarantined = getattr(saved, "quarantined", False)
        self.log = Log()
        self.log.verbose = self.cfg.verbose
        # session log file (mirrors everything; helps bug reports)
        from .config import APP_DIR
        self._log_dir = os.path.join(APP_DIR, "logs")
        # keep=60 is a hard SAFETY cap (runaway count of files), not the
        # privacy control — that is retention by AGE
        # (Config.log_retention_days, default 14 days)
        Log.prune_session_files(self._log_dir, keep=60)
        # data-theft guard: encrypt legacy plaintext logs from older
        # versions (synchronously — migration must finish before the
        # logger opens any .hlog file, or lines appended in between
        # would be lost), then harden the folder's ACLs in the
        # background (best-effort)
        try:
            from . import dataguard as _dg
            _conv, _tot = _dg.migrate_plaintext_logs(self._log_dir)
            if _conv:
                self.log.ok(f"Data guard: encrypted {_conv} older plaintext "
                            f"log file(s) — browsing history is now stored "
                            f"encrypted.")
            del _conv, _tot
            # one-time: re-encrypt lines still written with the legacy
            # static entropy (public in the old source) under the
            # per-install key — must also finish before the logger opens
            _u_files, _u_lines = _dg.upgrade_entropy(self._log_dir)
            if _u_files:
                self.log.ok(f"Data guard: re-encrypted {_u_lines} log line(s) "
                            f"in {_u_files} file(s) with the per-install key "
                            "— old generically-decryptable data is gone.")
            del _u_files, _u_lines
            # settings still on the legacy static entropy? one save fixes it.
            # SYNCHRONOUS here (beside the log upgrade, before any other
            # thread can save) instead of from the background bootstrap —
            # a settings save collides with the main thread's own saves.
            try:
                if (self.cfg.remember
                        and _dg.settings_needs_entropy_upgrade(SETTINGS_PATH)):
                    if self._cfg_save("entropy upgrade"):
                        self.log.ok("Data guard: settings re-encrypted with "
                                    "the per-install key.")
            except OSError:
                pass
        except Exception:
            pass
        self._log_file = os.path.join(self._log_dir, time.strftime("hookip_%Y%m%d_%H%M%S.hlog"))
        self.log.attach_file(self._log_file)
        # start the guard AFTER _log_file exists: the retention purge uses
        # it as the never-delete name — a race here would make keep="" for
        # a moment (harmless today: a fresh session log always has a fresh
        # mtime, but the dependency should not be implicit)
        try:
            import threading as _th
            _th.Thread(target=self._startup_dataguard, daemon=True).start()
        except Exception:
            pass
        if getattr(self.log, "file_error", None):
            self.log.warn("Session log file could NOT be created — this "
                          "session is memory-only. Check disk space and "
                          "permissions for %LOCALAPPDATA%\\HookIP\\logs.")
        self.log.ok(f"HookIP v{__version__} started — session log: "
                    f"{os.path.basename(self._log_file)}")
        try:
            marker = os.path.join(APP_DIR, "last_crash.txt")
            if os.path.isfile(marker):
                with open(marker, encoding="utf-8") as fh:
                    raw = fh.read()
                # current format: encrypted (HKCFG1); a legacy plaintext
                # marker (pre-hardening) is honored once
                if raw.startswith("HKCFG1:"):
                    from . import dataguard
                    plain = dataguard.decrypt_bytes(raw)
                    raw = plain.decode("utf-8") if plain is not None else ""
                reason, ts = (raw.strip().split("\t", 1) + [""])[0:2]
                try:
                    os.remove(marker)
                except OSError:
                    pass
                if reason or ts:
                    self.log.warn(f"Last session ended unexpectedly "
                                  f"({reason or 'crash'}) at {ts} — crash "
                                  "protection restored your internet. This "
                                  "session is a fresh start.")
        except OSError:
            pass
        self._hook_exception_logging()
        self.stats = Stats()
        self.pac_token = self.cfg.pac_token or secrets.token_hex(8)
        if self.cfg.pac_token != self.pac_token:
            self.cfg.pac_token = self.pac_token
            # persist the token only when the user wants settings kept —
            # with 'Remember' off the file is deleted at Start anyway, and
            # writing it here recreated data the user asked not to keep
            if self.cfg.remember:
                self._cfg_save("PAC token bootstrap")
        if getattr(self.cfg, "degraded", False):
            # transient registry failure: this session cannot read the
            # per-install key — settings were left untouched and saves
            # are refused. Say it ONCE, loudly.
            self.log.warn(
                "The settings encryption key could not be read this "
                "session (the registry was temporarily unavailable) — "
                "your settings were left untouched and saving is paused "
                "for this session. A restart is recommended.")
        if getattr(self.cfg, "quarantined", False):
            # the encrypted settings could not be decrypted (corrupt blob,
            # another Windows account, or a lost per-install key): defaults
            # are active and the ORIGINALS are safe at settings.json.bad —
            # say so instead of silently showing an empty site list
            self.log.warn(
                "Settings file could not be decrypted — starting with "
                "defaults. Your previous settings are kept untouched at "
                f"{SETTINGS_PATH}.bad and can be recovered after fixing "
                "the cause (e.g. restore the file from the same Windows "
                "account that created it).")
            try:
                notify.notify(
                    "HookIP — settings need attention",
                    "settings.json could not be decrypted; defaults are "
                    "active. The original file was kept as "
                    "settings.json.bad.", timeout_s=30)
            except Exception:
                pass
        self.proxy = None
        self._live_port = None          # the port the proxy actually bound
        self.running = False
        self.watchdog = winproxy.Watchdog()

        root.title(f"{APP_NAME} v{__version__}"
                   + (f" · build {__build_id__}" if __build_id__ else ""))
        root.geometry("880x640")
        root.minsize(760, 560)
        root.configure(bg=BG)
        try:
            root.iconbitmap(resource_path(os.path.join("assets", "hookip.ico")))
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
        try:
            from .perf import profile as _p
            self.root.after(_p().dash_interval_ms, self._refresh_dashboard)
        except Exception:
            self.root.after(500, self._refresh_dashboard)
        self._watch_activation()
        self.log.info(f"{APP_NAME} {__version__} ready. Press Start to turn the proxy on.")
        try:
            from .perf import profile
            self.log.debug(f"Performance profile: {profile().describe()}")
        except Exception:
            pass

    def _startup_dataguard(self):
        """Background half of the data-theft guard bootstrap.

        Log-file MIGRATION already ran synchronously in __init__ (it
        must finish before the logger opens any .hlog file). This
        thread only strips inherited ACLs from the data folder so only
        the current user + SYSTEM can read it. Results are surfaced in
        Diagnostics → System.
        """
        from .config import APP_DIR
        try:
            from . import dataguard
            self._dg_acl_ok = dataguard.harden_dir(APP_DIR)
            if not self._dg_acl_ok:
                self.log.debug("Data guard: folder ACL hardening unavailable "
                               "(OneDrive/AV lock?) — file encryption still active.")
            else:
                self.log.debug("Data guard: folder ACL hardened (current user + "
                               "SYSTEM only).")
            # plaintext-hygiene sweep: delete known legacy leftovers the
            # current code never reads (winhttp_backup.txt from the old
            # version, stale settings tmp files, old toast scripts)
            swept = dataguard.sweep_plaintext(APP_DIR)
            if swept:
                self.log.ok("Data guard: removed " + ", ".join(swept))
            # retention: old session logs are a years-deep browsing history
            # — keep the default window only (config: log_retention_days)
            days = int(getattr(self.cfg, "log_retention_days", 14) or 0)
            if days:
                gone = logutil.purge_old_logs(
                    os.path.join(APP_DIR, "logs"), days,
                    keep=os.path.basename(getattr(self, "_log_file", "") or ""))
                if gone:
                    self.log.ok(f"Log retention: removed {len(gone)} session "
                                f"log(s) older than {days} days")
        except Exception as exc:  # noqa: BLE001 — the guard must never block startup
            self.log.debug(f"Data guard bootstrap skipped: {type(exc).__name__}: {exc}")

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
                elif kind == "emergency_done":
                    self._set_running_ui(False)
                elif kind == "reapply":
                    self._reapply_system_proxy()
                elif kind == "vpn":
                    self._apply_vpn_state(args[0] if args else None)
                elif kind == "upstream_ui":
                    try:
                        self.upstream_var.set(str(args[0]) if args else "")
                    except (tk.TclError, RuntimeError, AttributeError):
                        pass
                elif kind == "dl_progress":
                    mb, note = (args + ("",))[:2]
                    try:
                        self._dl_btn.configure(
                            text=f"downloading… {mb:.1f} MB{(' ' + note) if note else ''}")
                    except tk.TclError:
                        pass
                elif kind == "dl_done":
                    self._handle_dl_done(bool(args and args[0]))
                elif kind == "auto_install":
                    self._install_downloaded(auto=True)

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

    def _handle_dl_done(self, ok):
        """A download finished: on a verified download the app now updates
        ITSELF — no manual step, no second app. The running exe is renamed
        to .old, the new one takes the SAME NAME, HookIP closes fully and
        a waiter relaunches it (auto-install on a frozen build; the dev
        python build keeps the manual 'Install now' button)."""
        self._downloading = False
        dest = getattr(self, "_downloaded_path", None)
        try:
            if ok and dest and os.path.isfile(dest):
                if getattr(sys, "frozen", False):
                    self._dl_btn.configure(state="disabled",
                                           text="installing…")
                    self._ui_queue.put(("auto_install", ()))
                else:
                    self._dl_btn.configure(state="normal",
                                           text="▶ Install now",
                                           command=self._install_downloaded)
            else:
                self._dl_btn.configure(
                    state="normal",
                    text=(f"⬇ Download {self._pending_ver}"
                          if getattr(self, "_pending_ver", None)
                          else "⬇ Download"),
                    command=self._download_update)
        except tk.TclError:
            pass


    def _pump_tray(self):
        try:
            while True:
                ev = self.tray.events.get_nowait()
                kind = ev[0]
                if kind == "show":
                    self._show_self()
                elif kind == "toggle":
                    self.toggle()
                elif kind == "menu":
                    # legacy Win32-menu event from an older tray build —
                    # kept so a hot-swapped tray module never strands an
                    # unhandled event
                    self._show_self()
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


    # -- update check ----------------------------------------------------
    UPDATE_REPO = "justcamop555-pixel/HookIP"
    # NO third-party mirrors: the update bytes and the checksum both come
    # from GitHub only — a mirror serving a swapped exe would defeat the
    # whole fail-closed design. Unreachable CDN ⇒ download fails visibly,
    # it does not fall back to untrusted infrastructure.

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
            # so what it says here is exactly what Start will see.
            # While the proxy is RUNNING the probe still works for a NEW
            # port (our listener holds a different one) — with a hint that
            # the change needs Stop → Start; typing the running port gets
            # the 'HookIP itself' answer instead of a scary 'in use'.
            avail_txt, avail_fg = "", MUTED
            if ok_p:
                p_num = int(self.port_var.get())
                if self.running and p_num == self.cfg.port:
                    avail_txt, avail_fg = "in use by HookIP (running)", OK
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        s.bind(("127.0.0.1", p_num))
                        if self.running:
                            avail_txt, avail_fg = ("free — press ⏹ Stop, then "
                                                   "▶ Start to switch"), WARN
                        elif p_num <= 1023:
                            avail_txt, avail_fg = "well-known port — may clash", WARN
                        else:
                            avail_txt, avail_fg = "free", OK
                    except OSError as exc:
                        if getattr(exc, "winerror", None) == 10013:
                            avail_txt, avail_fg = ("blocked by Windows "
                                                   "(reserved range) — pick "
                                                   "another"), ERR
                        else:
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

    def check_updates(self, manual=False):
        if getattr(self, "_update_running", False):
            self.log.info("Update check already running.")
            return
        self._update_running = True
        self._update_manual = manual
        self.update_label.configure(text="checking…", fg=MUTED)
        threading.Thread(target=self._update_worker, daemon=True).start()

    def _schedule_update_recheck(self, delay_ms):
        """(Re)schedule the next automatic update check, cancelling any
        pending one first. Both the 12 h cadence and the 30 min offline
        retry used to stack a NEW timer on every result — repeated manual
        checks and offline periods multiplied them permanently."""
        try:
            old = getattr(self, "_update_after", None)
            if old:
                self.root.after_cancel(old)
        except (tk.TclError, RuntimeError, ValueError):
            pass
        try:
            self._update_after = self.root.after(delay_ms, self.check_updates)
        except (tk.TclError, RuntimeError):
            pass

    def _update_worker(self):
        import json as _json
        import urllib.request
        import urllib.error
        latest, url, offline, asset, sha_asset, prerelease = (None, None, False,
                                                              None, None, False)
        body = None
        http_error = None          # HTTP status / 0 for a bad body — never
                                   # an 'offline' verdict (the network was
                                   # reachable enough to answer)

        def fetch(req, timeout=10):
            # The system proxy may point at HookIP itself; if the request
            # fails mid-transition, retry DIRECT (no system proxy) so a
            # starting/stopping tunnel never fakes an 'offline' verdict.
            try:
                return urllib.request.urlopen(req, timeout=timeout)
            except OSError:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}))
                return opener.open(req, timeout=timeout)

        def redirect_fallback():
            """Some users cannot reach api.github.com at all (DNS/TLS
            filtering or the unauthenticated 60 req/h rate limit eaten by
            a shared NAT). github.com's releases/latest redirect is
            separate infrastructure and usually still reachable."""
            try:
                req2 = urllib.request.Request(
                    f"https://github.com/{self.UPDATE_REPO}/releases/latest",
                    headers={"User-Agent": "HookIP-updater"})
                with fetch(req2) as r2:
                    tag = r2.geturl().rsplit("/tag/", 1)[-1]
                    if tag and tag != "latest":
                        return tag
            except (OSError, ValueError):
                pass
            return None

        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{self.UPDATE_REPO}/releases/latest",
                headers={"User-Agent": "HookIP-updater", "Accept": "application/vnd.github+json"})
            with fetch(req) as r:
                data = _json.loads(r.read().decode("utf-8"))
                latest = data.get("tag_name", "")
                url = data.get("html_url") or \
                    f"https://github.com/{self.UPDATE_REPO}/releases"
                prerelease = bool(data.get("prerelease"))
                body = data.get("body") or None
                for a in data.get("assets") or []:
                    nm = str(a.get("name", "")).lower()
                    if nm.endswith(".exe") and not asset:
                        asset = a.get("browser_download_url")
                    elif nm.endswith(".sha256") and not sha_asset:
                        sha_asset = a.get("browser_download_url")
        except urllib.error.HTTPError as exc:
            offline = exc.code in (403, 429, 500, 502, 503)
            http_error = exc.code   # NOT 'offline': the network answered
            # 404: private repo — try the redirect form (works once public)
            if latest is None:
                tag = redirect_fallback()
                if tag:
                    # the redirect fallback succeeded — we are NOT offline
                    latest, url, offline = (tag,
                        f"https://github.com/{self.UPDATE_REPO}/releases/tag/{tag}",
                        False)
                    prerelease = "-" in tag
        except OSError:
            # api.github.com unreachable for this user (DNS/TLS filtering,
            # timeouts): the redirect form lives on other infrastructure —
            # try it before declaring offline (it used to give up here,
            # leaving users 'offline' forever on api-blocked networks)
            tag = redirect_fallback()
            if tag:
                latest, url, offline = (tag,
                    f"https://github.com/{self.UPDATE_REPO}/releases/tag/{tag}",
                    False)
                prerelease = "-" in tag
            else:
                offline = True
        except ValueError:
            # malformed API response must not kill the worker (it used to
            # leave the update check permanently stuck on 'already running')
            offline = True
            http_error = 0          # bad response, not offline
        self._ui_queue.put(("update", (latest, url, offline, asset,
                                       sha_asset, prerelease, body, http_error)))

    @staticmethod
    def _ver_tuple(s):
        """Numeric compare that tolerates pre-release AND build-ID suffixes:
        'v1.2.0-beta' and '1.2.0+build.42' both compare as (1, 2, 0).
        (The old parser crashed on '+' and returned (0,), which made any
        build-ID build look OLDER than the release and offered a
        downgrade.) Unparseable -> (0,) so it never claims newer."""
        try:
            core = str(s).strip().lstrip("vV").split("+", 1)[0].split("-", 1)[0]
            parts = [int(p) for p in core.split(".")[:3] if p.strip().isdigit()]
            if not parts:
                return (0,)
            return tuple(parts + [0] * (3 - len(parts)))
        except ValueError:
            return (0,)

    def _update_result(self, latest, url, offline=False, asset=None,
                       sha_asset=None, prerelease=False, body=None,
                       http_error=None):
        self._update_running = False
        # a running download OWNS the download button: a concurrent
        # 'Check for updates' used to rebind it to '⬇ Download' (or hide
        # it) mid-download — and a second download then corrupted the
        # first through the same .part file
        dl_locked = bool(getattr(self, "_downloading", False))
        try:
            if not latest:
                stamp = time.strftime(" · checked %H:%M")
                if offline and http_error is not None:
                    # FALSE-POSITIVE FIX: an HTTP answer means the network
                    # is UP — 403/429/5xx and malformed bodies are not
                    # 'offline'. Say what actually happened.
                    why = (f"HTTP {http_error}" if http_error
                           else "bad response")
                    self.update_label.configure(
                        text=f"update check failed ({why}) — will retry" + stamp,
                        fg=MUTED)
                    self.log.debug(f"Update check failed ({why}); "
                                   "will re-check in 30 min.")
                elif offline:
                    self.update_label.configure(
                        text="offline — will re-check later" + stamp, fg=MUTED)
                    self.log.debug("Update check: no reachable release info "
                                   "(offline).")
                else:
                    self.update_label.configure(
                        text="private repo — works once public" + stamp, fg=MUTED)
                    self.log.debug("Update check: no reachable release info "
                                   "(private repo).")
                self.update_pill.configure(text="", fg=MUTED)
                if not dl_locked:
                    self._dl_btn.pack_forget()
                # offline is usually transient (or our own tunnel mid-restart)
                # — re-check in 30 min instead of waiting 12 h (cancels any
                # pending timer first; this path used to stack timers)
                self._schedule_update_recheck(30 * 60 * 1000)
                return
            self._update_url = url
            remote = self._ver_tuple(latest)
            local = self._ver_tuple(__version__)
            newer = remote > local
            if remote < local:
                # this build is NEWER than anything published — a local
                # build ID not uploaded to GitHub yet. Never offer a
                # downgrade; say so plainly and stay quiet until the
                # release catches up.
                self.update_label.configure(
                    text=f"build ahead of GitHub (v{__version__} > {latest})",
                    fg=MUTED)
                self.update_pill.configure(
                    text=f"✓ v{__version__} — not published yet", fg=MUTED)
                if not dl_locked:
                    self._dl_btn.pack_forget()
                self.log.ok(
                    f"Update check: this build (v{__version__}"
                    + (f" build {__build_id__}" if __build_id__ else "")
                    + f") is newer than the latest GitHub release ({latest}) "
                    "— nothing to update until it is published.")
            elif newer and prerelease and not getattr(self, "_update_manual", False):
                # pre-release builds (v1.2.0-beta) are opt-in: automatic
                # checks stay on the stable channel and only mention them;
                # a MANUAL check offers the download. A pre-release whose
                # version EQUALS the installed one falls through to
                # 'up to date' below instead of claiming a release exists.
                self.update_label.configure(
                    text=f"pre-release {latest} exists — stable stays installed",
                    fg=MUTED)
                self.update_pill.configure(text=f"✓ v{__version__}", fg=MUTED)
                if not dl_locked:
                    self._dl_btn.pack_forget()
            elif newer:
                self.update_label.configure(text=f"update available: {latest}", fg=WARN)
                self.update_pill.configure(text=f"⬆ {latest} — click to update", fg=WARN)
                self.log.ok(f"Update available: {latest} — you are on v{__version__}.")
                notify.notify("HookIP update available",
                              f"{latest} is out (you have v{__version__}). "
                              "Click the banner in the app to get it.",
                              timeout_s=12)
                # one-click download straight from the release (public repo)
                if asset:
                    self._update_asset_url = asset
                    self._update_sha_url = sha_asset
                    self._update_body = body
                    self._pending_ver = latest
                    if not dl_locked:
                        self._dl_btn.configure(text=f"⬇ Download {latest}", state="normal")
                    if not dl_locked:
                        self._dl_btn.pack(side="left", padx=(10, 0))
                    self.log.info("A one-click download is available in "
                                  "Settings → Updates.")
                if getattr(self, "_update_manual", False):
                    pr = "\n(This is a pre-release build.)" if prerelease else ""
                    if messagebox.askyesno(
                            APP_NAME,
                            f"HookIP {latest} is available\n(you have "
                            f"v{__version__}).{pr}\n\nOpen the Releases page?"):
                        import webbrowser
                        webbrowser.open(url or
                                        f"https://github.com/{self.UPDATE_REPO}/releases")
            else:
                self.update_label.configure(text=f"up to date (v{__version__})", fg=OK)
                self.update_pill.configure(text=f"✓ v{__version__}", fg=MUTED)
                if not dl_locked:
                    self._dl_btn.pack_forget()
        except (tk.TclError, RuntimeError):
            pass
        # re-check every 12 h so a published update is noticed without a
        # restart — cancels any pending timer first (no stacking)
        self._schedule_update_recheck(12 * 3600 * 1000)

    def _download_update(self):
        url = getattr(self, "_update_asset_url", None)
        if not url:
            return
        if getattr(self, "_downloading", False):
            self.log.info("A download is already running — it owns the "
                          "button until it finishes.")
            return
        self._downloading = True
        try:
            self._dl_btn.configure(state="disabled", text="downloading… 0.0 MB")
        except tk.TclError:
            pass
        threading.Thread(target=self._download_worker, args=(url,), daemon=True).start()

    def _dl_progress(self, mb, note=""):
        """Worker-thread safe: route through the UI queue."""
        self._ui_queue.put(("dl_progress", (mb, note)))

    def _download_worker(self, url):
        import hashlib
        import urllib.request
        import urllib.error

        def fetch(u, timeout=30, deadline=None, what="asset"):
            # GITHUB ONLY: via the system proxy (our own tunnel), then
            # direct. No third-party mirrors — every byte of the update
            # and of the checksum must come from the same trusted host.
            last = None
            if deadline and time.monotonic() > deadline:
                raise OSError(f"download budget exhausted before {what}")
            for attempt in (0, 1):         # 0 = via system proxy, 1 = direct
                try:
                    if attempt == 1:
                        opener = urllib.request.build_opener(
                            urllib.request.ProxyHandler({}))
                        return opener.open(
                            urllib.request.Request(
                                u, headers={"User-Agent": "HookIP-updater"}),
                            timeout=timeout)
                    return urllib.request.urlopen(
                        urllib.request.Request(
                            u, headers={"User-Agent": "HookIP-updater"}),
                        timeout=timeout)
                except (OSError, urllib.error.URLError) as exc:
                    last = exc
            raise OSError(f"GitHub unreachable for {what} ({last})")

        body_sha256 = lambda: _sha_from_notes(
            getattr(self, "_update_body", ""))

        # Destination: the exe's OWN directory when frozen — the install
        # step then renames the RUNNING exe to .old and takes its exact
        # name, so the updated app is the SAME FILE the user knows, with
        # no manual run of a differently named file. (Downloading into
        # %TEMP%-style dirs or Downloads left a second HookIP install.)
        frozen = bool(getattr(sys, "frozen", False))
        dest_dir = (os.path.dirname(os.path.abspath(sys.executable))
                    if frozen else os.path.join(os.path.expanduser("~"), "Downloads"))
        dest_name = ("HookIP.exe.new" if frozen else
                     f"HookIP_{getattr(self, '_pending_ver', 'update').lstrip('v')}.exe")
        tmp = dest = None
        try:
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, dest_name)
            # UNIQUE per download: two concurrent downloads used to write
            # the SAME .part file and corrupt each other
            tmp = dest + f".part{threading.get_ident()}"
            data = b""
            deadline = time.monotonic() + 15 * 60   # overall download budget
            last_progress = 0.0
            with fetch(url, timeout=30, deadline=deadline) as r:
                # read INSIDE the chosen connection with a no-data watchdog:
                # the socket timeout (30 s) covers a fully stalled read, and
                # the wall-clock deadline covers a TRICKLING stream that
                # never EOFs (VM NAT networks do this) — the old loop lived
                # OUTSIDE the mirror selection, so a bad connection was
                # stuck forever with no failover and no progress display
                last_data = time.monotonic()
                while True:
                    if time.monotonic() > deadline:
                        raise OSError("download exceeded the 15-minute budget")
                    if time.monotonic() - last_data > 45:
                        raise OSError("no data for 45 s — connection stalled")
                    try:
                        chunk = r.read(65536)
                    except (socket.timeout, TimeoutError) as exc:
                        raise OSError(f"read timed out (stalled): {exc}") from exc
                    if not chunk:
                        break
                    data += chunk
                    last_data = time.monotonic()
                    if len(data) - last_progress >= 1_000_000:
                        last_progress = len(data)
                        self._dl_progress(len(data) / 1_000_000)
            self._dl_progress(len(data) / 1_000_000, "verifying…")
            # verify against a GitHub-published checksum — a corrupted
            # download is deleted, not left behind to be run by mistake.
            # FAIL CLOSED once a checksum is published: if no source can
            # produce one, the download is refused rather than saved
            # unverified. Sources in order of trust: the .sha256 release
            # asset (via GitHub, then via the same mirrors), then the
            # sha256 printed in the release notes (github.com server side,
            # immune to asset-CDN blocks).
            expected = None
            sha_url = getattr(self, "_update_sha_url", None)
            if sha_url:
                try:
                    with fetch(sha_url, timeout=15, what="checksum") as sr:
                        txt = sr.read(512).decode("utf-8", "replace")
                    # STRICT hex validation INSIDE the parser: an HTML
                    # error page must never become the 'expected' hash
                    # (that would fail every genuine download with a
                    # nonsense mismatch)
                    expected = _parse_sha_file(txt)
                except (OSError, urllib.error.URLError):
                    expected = None
            if expected is None:
                expected = body_sha256()
                if expected:
                    self.log.info("Update checksum taken from the release "
                                  "notes (asset CDN unreachable).")
            if expected is None:
                self.log.error(
                    "Update download REFUSED: no checksum could be "
                    "obtained for this release (checksum asset and "
                    "release notes both unavailable) — install manually "
                    "from the Releases page.")
                notify.notify(
                    "HookIP — update download failed",
                    "No checksum could be obtained for this release, so "
                    "the download was refused. Install manually from the "
                    "Releases page.", timeout_s=12)
                self._ui_queue.put(("dl_done", (False,)))
                return
            if expected:
                actual = hashlib.sha256(data).hexdigest()
                if actual != expected:
                    self.log.error(
                        f"Update download FAILED the checksum check "
                        f"({actual[:16]}… ≠ {expected[:16]}…) — the file was "
                        "deleted. Try again or download from the Releases page.")
                    notify.notify("HookIP — update download failed",
                                  "The downloaded file did not match its "
                                  "checksum and was deleted. Try again.",
                                  timeout_s=12)
                    # re-enable the button too — the mismatch path used to
                    # leave it stuck on 'downloading…' forever
                    self._ui_queue.put(("dl_done", (False,)))
                    return
                self.log.ok("Downloaded update verified against the release checksum.")
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, dest)   # atomic: the exe appears only when complete
            tmp = None              # moved — nothing to clean up
            self._downloaded_path = dest
            self._downloaded_ok = True
            self.log.ok(f"Update downloaded and verified: {dest}")
            self._ui_queue.put(("dl_done", (True,)))
        except OSError as exc:
            if tmp:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            self.log.error(f"Update download failed: {exc} — use 'click to "
                           "update' to get it from the Releases page.")
            notify.notify("HookIP — update download failed",
                          str(exc)[:140], timeout_s=12)
            self._ui_queue.put(("dl_done", (False,)))
        except Exception as exc:  # noqa: BLE001 — a download must never
                                  # die silently (the button stayed on
                                  # 'downloading…' forever if it did)
            if tmp:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            self.log.error(f"Update download crashed: "
                           f"{type(exc).__name__}: {exc}")
            self._ui_queue.put(("dl_done", (False,)))

    def _update_pill_click(self, _event=None):
        if getattr(self, "_update_url", None) and "⬆" in self.update_pill.cget("text"):
            import webbrowser
            webbrowser.open(self._update_url)
        else:
            self.check_updates(manual=True)

    def _install_downloaded(self, auto=False):
        """Install a verified download.

        Frozen build: the RUNNING HookIP.exe is renamed to HookIP.exe.old
        (allowed while running), the verified download takes the SAME
        NAME, and a detached waiter relaunches HookIP.exe as soon as this
        process has fully exited (Wait-Process on our real PID — the old
        fixed `timeout /t 2` raced the single-instance mutex and could
        bounce the user to 'already running').

        Dev (python) build: the download is its own exe; starting it is
        the manual path (no renaming of python.exe)."""
        dest = getattr(self, "_downloaded_path", None)
        if not dest or not os.path.isfile(dest):
            if not auto:
                messagebox.showerror(
                    APP_NAME,
                    "The downloaded update file is gone —\n"
                    "download it again from Settings → Updates.")
            try:
                self._dl_btn.configure(
                    text=f"⬇ Download {self._pending_ver}"
                    if getattr(self, "_pending_ver", None) else "⬇ Download",
                    command=self._download_update)
            except tk.TclError:
                pass
            return
        if getattr(self, "_installing", False):
            return
        if not auto and not messagebox.askyesno(
                APP_NAME,
                f"Install the downloaded update now?\n\n{dest}\n\n"
                "HookIP will close, your internet settings will be "
                "restored, and the new version will start."):
            return
        self._installing = True
        try:
            self._dl_btn.configure(state="disabled", text="installing…")
        except tk.TclError:
            pass

        frozen = bool(getattr(sys, "frozen", False))
        if frozen:
            # SAME-NAME replace: rename the running exe (Windows allows
            # renaming a running image), then move the verified download
            # into its exact name. The user's shortcut, Start-menu pin and
            # taskbar icon all keep working — nothing else to run.
            exe = os.path.abspath(sys.executable)
            old = exe + ".old"
            try:
                try:
                    if os.path.exists(old):
                        os.remove(old)      # a previous update's leftover
                except OSError:
                    pass                    # locked — replace() still works
                os.replace(exe, old)
                os.replace(dest, exe)
            except OSError as exc:
                self._installing = False
                # put the RUNNING exe back before giving up — otherwise
                # HookIP.exe is renamed away and the shortcut breaks
                try:
                    if not os.path.exists(exe) and os.path.exists(old):
                        os.replace(old, exe)
                except OSError:
                    pass
                msg = (f"The update could not be swapped in:\n{exc}\n\n"
                       "The downloaded file is kept — install it manually "
                       "from the Releases page.")
                if auto:
                    self.log.error(msg.replace("\n", " "))
                    notify.notify("HookIP — update install failed",
                                  str(exc)[:140], timeout_s=15)
                else:
                    messagebox.showerror(APP_NAME, msg)
                return
            exe_dir = os.path.dirname(exe)
        else:
            exe_dir = os.path.dirname(dest)

        # detached waiter: waits for THIS process to fully exit (not a
        # fixed timeout that raced the single-instance mutex), then starts
        # HookIP.exe from its own directory
        ps = ("Wait-Process -Id %d -ErrorAction SilentlyContinue; "
              "Start-Sleep -Milliseconds 500; "
              "Start-Process -FilePath '%s' -WorkingDirectory '%s'"
              % (os.getpid(),
                 (os.path.join(exe_dir, "HookIP.exe") if frozen else dest),
                 exe_dir))
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-STA", "-WindowStyle", "Hidden",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                creationflags=0x08000000)   # CREATE_NO_WINDOW
        except OSError as exc:
            self._installing = False
            if auto:
                self.log.error(f"Could not start the update waiter: {exc}")
            else:
                messagebox.showerror(APP_NAME,
                                     f"Could not start the installer:\n{exc}")
            return
        self.log.ok(f"Installing {os.path.basename(dest)} — HookIP is closing "
                    "and your internet settings are being restored; the new "
                    "version starts automatically under the same name.")
        notify.notify("HookIP — updating",
                      "Closing and restarting with the new version "
                      "(same name, same place). Your internet settings "
                      "are restored first.", timeout_s=10)
        try:
            self.root.after(300, self.on_close)
        except (tk.TclError, RuntimeError):
            self.on_close()

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
        # Brand: the real HookIP logo image next to the title. The old
        # '⚓' text symbol rendered as an empty box (tofu) on font stacks
        # without the glyph — a bundled PNG cannot fail to exist.
        self._brand_img = None
        try:
            self._brand_img = tk.PhotoImage(
                file=resource_path(os.path.join("assets", "hookip_32.png")))
            tk.Label(head, image=self._brand_img, bg=BG).pack(side="left")
            tk.Label(head, text="HookIP", font=("Segoe UI Semibold", 18),
                     bg=BG, fg=FG).pack(side="left", padx=(6, 0))
        except (tk.TclError, OSError):
            tk.Label(head, text="⚓ HookIP", font=("Segoe UI Semibold", 18),
                     bg=BG, fg=FG).pack(side="left")   # fallback keeps the old look
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
        # VPN pill: hidden until a VPN is detected (best-effort, cached in
        # hookip.vpn). Honest WHY: with a full-tunnel VPN up, HookIP's
        # fragmentation/DoH are redundant — the user should know that.
        self.vpn_pill = tk.Label(head, text="", font=("Segoe UI", 10),
                                 bg="#202634", fg=MUTED, padx=8, pady=3)
        self.vpn_tip = None
        self._vpn_refresh_scheduled = False
        # after the window paints — on a WORKER thread: detect() spawns
        # subprocesses (tasklist, warp-cli) and must never run on the UI
        # thread, where a hung probe could freeze the window
        self.root.after(1500, lambda: threading.Thread(
            target=self._refresh_vpn_pill, daemon=True).start())
        # flat-button hover feedback (header buttons)
        for btn, hot, cold in ((self.restore_btn, "#2a3244", "#202634"),):
            btn.bind("<Enter>", lambda e, b=btn, c=hot: b.configure(bg=c), add="+")
            btn.bind("<Leave>", lambda e, b=btn, c=cold: b.configure(bg=c), add="+")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        self.nb = nb
        # Notebook tab headers: plain Tooltips can't target a tab — this
        # helper shows a description when the cursor hovers a tab
        try:
            NotebookTips(nb, [
                "Dashboard — connection totals, live throughput graph and "
                "the list of sites HookIP resolved today.",
                "Log — everything HookIP did, color-coded. 'Save log…' "
                "exports the complete decrypted file for bug reports.",
                "Settings — port, fragmentation strategy, system proxy mode, "
                "secure DNS, upstream proxy, excluded domains.",
                "Diagnostics — one-click checks: DNS resolvers, real tunnel "
                "test, system/antivirus state, plus a copyable report.",
            ])
        except Exception:
            pass

        # dashboard --------------------------------------------------------
        dash = ttk.Frame(nb, style="Card.TFrame", padding=14)
        nb.add(dash, text=" Dashboard ")
        self.dash_vars = {}
        self._dash_colors = {}   # dashboard key -> (lit, normal) colors
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
                "'Everything' also reveals per-connection detail; the "
                "log file on disk (.hlog, encrypted) always keeps it all.")
        self.log_filter.bind("<<ComboboxSelected>>", lambda _e: self._apply_log_filter())
        # text search on top of the level filter — live substring match
        self._log_query = ""
        tk.Label(bar, text="🔍 Find:", bg=PANEL, fg=MUTED).pack(side="left", padx=(10, 4))
        self.log_search = tk.Entry(bar, bg="#171c26", fg=FG, bd=0,
                                   insertbackground=FG, width=18)
        self.log_search.pack(side="left")
        Tooltip(self.log_search,
                "Show only lines containing this text (e.g. a hostname "
                "or an error word). Leave empty to see everything; "
                "combines with the 'Show' level filter.")
        self.log_search.bind("<KeyRelease>", lambda _e: self._apply_log_filter())
        save_btn = tk.Button(bar, text="Save log…", command=self._export_log,
                             bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                             activebackground="#2a3244", activeforeground=FG,
                             cursor="hand2")
        save_btn.pack(side="right")
        Tooltip(save_btn,
                "Save the complete log (every detail, no filter) to a file "
                "— this is a DECRYPTED copy of your browsing history, so "
                "share it only intentionally (e.g. a bug report). The log "
                "is also always written to disk encrypted: "
                "%LOCALAPPDATA%\\HookIP\\logs.")
        copy_btn = tk.Button(bar, text="Copy all", command=self._copy_log,
                             bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                             activebackground="#2a3244", activeforeground=FG,
                             cursor="hand2")
        copy_btn.pack(side="right", padx=(0, 6))
        Tooltip(copy_btn, "Copy the complete log to the clipboard.")
        folder_btn = tk.Button(bar, text="Logs folder", command=self._open_log_folder,
                               bg="#202634", fg=FG, bd=0, padx=10, pady=3,
                               activebackground="#2a3244", activeforeground=FG,
                               cursor="hand2")
        folder_btn.pack(side="right", padx=(0, 6))
        Tooltip(folder_btn,
                "Open the folder with the encrypted session logs "
                "(%LOCALAPPDATA%\\HookIP\\logs) in Explorer.")
        # 'jump to latest' appears only when the reader scrolled up while
        # new lines kept arriving (the view no longer follows silently)
        self.jump_latest = tk.Button(bar, text="↓ latest", fg="#8ab4f8",
                                     bg="#202634", bd=0, padx=8, pady=2,
                                     activebackground="#2a3244",
                                     activeforeground="#8ab4f8", cursor="hand2",
                                     command=self._jump_to_latest)
        self.jump_latest.pack(side="right", padx=(0, 6))
        self.jump_latest.pack_forget()
        Tooltip(self.jump_latest,
                "You scrolled up while new lines arrived — click to jump "
                "back to the live tail (it follows again automatically).")
        # basename only: the full path made the toolbar so wide it was
        # clipped by the Find box (the full path lives in the tooltip)
        sf_lbl = tk.Label(bar, text=f"Session: {os.path.basename(self._log_file)}",
                          bg=PANEL, fg=MUTED, font=("Segoe UI", 8))
        sf_lbl.pack(side="right", padx=8)
        Tooltip(sf_lbl,
                f"This session's encrypted log file (.hlog): {self._log_file}\n\n"
                "Each line is DPAPI-encrypted with a per-install key "
                "before it touches disk — a copied file shows no browsing "
                "history. Logs are kept in %LOCALAPPDATA%\\HookIP\\logs "
                "and pruned by age (default: 14 days).")
        logwrap = tk.Frame(logf, bg=PANEL)
        logwrap.pack(fill="both", expand=True)
        # The Text MUST be a CHILD of logwrap. The first version packed it
        # 'in_=logwrap' while its master was still logf — the packer left
        # logwrap ABOVE it in logf's stacking order, and logwrap's opaque
        # background painted over the ENTIRE log: the widget held every
        # entry, the scrollbar worked, and the user saw a perfectly blank
        # pane (the bug in the wild).
        self.log_text = tk.Text(logwrap, bg="#0d1017", fg=FG, insertbackground=FG,
                                font=("Consolas", 9), state="disabled", wrap="none",
                                height=10)
        sb_x = tk.Scrollbar(logwrap, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(xscrollcommand=sb_x.set)
        # wrap='none' with NO horizontal scrollbar used to clip long lines
        # (hostnames, error text) — you could see they existed, never read them
        self.log_text.pack(side="top", fill="both", expand=True)
        sb_x.pack(side="bottom", fill="x")
        Tooltip(self.log_text,
                "Live log view — filtered by the 'Show' selector above. "
                "Use 'Save log…' for the complete unfiltered (decrypted) "
                "file; colors: blue = DNS, teal = resolves, dim = "
                "per-connection detail.")
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

        # Upstream proxy: chain HookIP through another proxy. Empty =
        # direct. Fills the gap for WARP-in-proxy-mode (127.0.0.1:40000),
        # corporate upstreams and local chains — the config key existed
        # (network detection wrote it) but users had no manual control.
        up_row = tk.Frame(grid, bg=PANEL)
        self.upstream_var = tk.StringVar(value=str(getattr(self.cfg, "upstream_proxy", "") or ""))
        up_e = ttk.Entry(up_row, textvariable=self.upstream_var, width=28)
        up_e.pack(side="left")
        self.upstream_e = up_e
        add_row("Upstream proxy", up_row, 4)   # row 4; later rows shift down
        Tooltip(up_e,
                "Chain HookIP through another proxy before the internet "
                "(empty = direct). Accepts host:port or "
                "http://user:pass@host:port.\n"
                "Typical use: a VPN running in PROXY mode — e.g. Cloudflare "
                "WARP proxy mode listens on 127.0.0.1:40000 — or the "
                "network's own mandatory proxy on restricted Wi-Fi.\n"
                "With a full-tunnel VPN (normal WARP mode) leave this EMPTY: "
                "HookIP's traffic already rides through the tunnel.")
        self.doh_var = tk.BooleanVar(value=self.cfg.doh_enabled)
        doh_c = ttk.Checkbutton(grid, text="Use DNS-over-HTTPS (recommended)",
                                variable=self.doh_var)
        add_row("Secure DNS", doh_c, 5)
        Tooltip(doh_c,
                "DNS-over-HTTPS: resolves names over an encrypted, fragmented\n"
                "connection so DNS itself can't be blocked or tampered with.\n"
                "Keep this on unless a network requires plain DNS.")

        self.verbose_var = tk.BooleanVar(value=self.cfg.verbose)
        verb_c = ttk.Checkbutton(grid, text="Verbose log", variable=self.verbose_var,
                                 command=lambda: setattr(self.log, "verbose",
                                                         self.verbose_var.get()))
        add_row("Logging", verb_c, 6)
        Tooltip(verb_c,
                "Shows per-connection detail on screen (DNS timings, ports,\n"
                "fragment counts). The log FILE always keeps this detail\n"
                "regardless of this switch.")

        self.remember_var = tk.BooleanVar(value=self.cfg.remember)
        rem_c = ttk.Checkbutton(grid, text="Remember settings for next launch",
                                variable=self.remember_var)
        add_row("Persistence", rem_c, 7)
        Tooltip(rem_c,
                "Save port, fragment size, strategy, mode and the excluded\n"
                "list to %LOCALAPPDATA%\\HookIP\\settings.json.\n"
                "Off = forget everything when HookIP closes.")

        self.tray_var = tk.BooleanVar(value=self.cfg.minimize_to_tray)
        tray_c = ttk.Checkbutton(grid, text="Hide to tray when the window is closed (X)",
                                 variable=self.tray_var)
        add_row("Window", tray_c, 8)
        Tooltip(tray_c,
                "On: the X button hides HookIP to the system tray and the "
                "proxy keeps running — the tray icon restores it.\n"
                "Off: the X button really exits (stopping the proxy).\n"
                "Minimize is always a normal minimize.")

        upd = tk.Frame(grid, bg=PANEL)
        upd_btn = tk.Button(upd, text="Check for updates", command=lambda: self.check_updates(manual=True),
                            bg="#202634", fg=FG, bd=0, padx=10, pady=4,
                            activebackground="#2a3244", activeforeground=FG,
                            cursor="hand2")
        upd_btn.pack(side="left")
        Tooltip(upd_btn,
                "Checks GitHub Releases for a newer HookIP version.\n"
                "Also runs automatically ~15 s after launch and every 12 h.\n"
                "When an update is out, a one-click download button "
                "appears here.")
        self.update_label = tk.Label(upd, text="", bg=PANEL, fg=MUTED,
                                     font=("Segoe UI", 9))
        self.update_label.pack(side="left", padx=10)
        self._dl_btn = tk.Button(upd, text="⬇ Download", state="disabled",
                                 command=self._download_update,
                                 bg="#202634", fg=FG, bd=0, padx=10, pady=4,
                                 activebackground="#2a3244", activeforeground=FG,
                                 cursor="hand2")
        Tooltip(self._dl_btn,
                "Downloads the new HookIP.exe straight from the release "
                "(checksum-verified), then HookIP closes, your internet "
                "settings are restored, and the new version starts "
                "automatically under the same name. Settings are kept.\n"
                "The button is grey until an update is actually found.",
                disabled_text=
                    "No update is available right now (or a check is still "
                    "running) — the button lights up as soon as a newer "
                    "release is detected. It also runs automatically ~15 s "
                    "after launch and every 12 h.")
        add_row("Updates", upd, 9)

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
        # keep the colors OFF the widget object: a Label subclass would be
        # one more widget class to carry around, and monkey-patching Tk
        # widget attributes confuses static analysis for no benefit
        self._dash_colors[key] = (lit, normal)
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
        # STALE-SESSION recognition: after a crash with 'Remember settings'
        # off, THIS session's port/token differ from the crashed one — an
        # exact _is_ours(cur, port, token) missed the stale entry and the
        # caller then discarded the only backup. is_stale_hookip matches
        # EITHER the current session or the session that wrote the backup.
        if self.running or not winproxy.is_stale_hookip(cur, self.cfg.port,
                                                        self.pac_token):
            return
        if winproxy.has_backup():
            # backup exists only when the last activation never stopped
            # cleanly (clean stop deletes it) — restore the original settings
            restored = winproxy.restore_from_file()
            if not restored and winproxy.has_backup():
                # encrypted backup unreadable this session (degraded key):
                # the plaintext recovery script is the second chance
                restored = winproxy.restore_from_cmd()
                if restored:
                    self.log.ok("Recovered from a crash via the recovery "
                                "script (the encrypted backup could not be "
                                "decrypted this session).")
            if restored:
                winproxy.clear_runonce()   # stale crash-cleanup entry
                self.log.ok("Recovered from a crash: system proxy restored to "
                            "your previous settings — internet should work again.")
                notify.notify("HookIP — internet restored",
                              "The app crashed earlier and Windows was still "
                              "pointed at it. Your original connection is back.",
                              timeout_s=12)
                return
        # no (usable) backup, but the registry still points at our own port —
        # exact match for this session, or the SELF-IDENTIFYING PAC URL of a
        # crashed older session (different port/token, no backup left)
        port_s = f"127.0.0.1:{self.cfg.port}"
        if port_s in str(cur.get("ProxyServer") or "") or \
                port_s in str(cur.get("AutoConfigURL") or "") or \
                winproxy.looks_like_ours(cur):
            winproxy.remove_proxy()
            winproxy.clear_runonce()
            self.log.ok("Recovered from a crash: stale HookIP proxy settings "
                        "cleared — internet set to direct connection.")

    def _manual_restore(self):
        """'Restore internet' button: fix a system proxy left pointing at a
        dead HookIP port (crash, watchdog failure, power loss)."""
        if self.running:
            self.stop_proxy()   # stopping already restores from backup (+ toast)
            # stop_proxy logs the SPECIFIC outcome (backup restore vs
            # direct-fallback) — a generic 'internet restored' here would
            # be a false success when it actually fell back to direct
            self.log.ok("Proxy stopped.")
            return
        try:
            cur = winproxy.read_current()
        except OSError as exc:
            self.log.error(f"Cannot read proxy settings: {exc}")
            return
        try:
            if winproxy.has_backup():
                if winproxy.is_stale_hookip(cur, self.cfg.port, self.pac_token):
                    # the system still points at HOOKIP — this session's or
                    # the crashed one's port/token (the crashed session's
                    # entries used to be missed here, and the stale backup
                    # — the only one — was then discarded below): the
                    # backup is the real fix
                    restored = winproxy.restore_from_file()
                    if not restored and winproxy.has_backup():
                        # unreadable ENCRYPTED backup (degraded key
                        # session): the plaintext recovery script written
                        # next to it holds the same original values
                        restored = winproxy.restore_from_cmd()
                        if restored:
                            self.log.ok("Restored from the recovery script — "
                                        "the encrypted backup could not be "
                                        "decrypted this session. If your "
                                        "upstream proxy needed a password, "
                                        "enter it again.")
                    if restored:
                        # also drop the crash-cleanup RunOnce entry: after
                        # a manual restore it used to survive and re-apply
                        # the crash-era settings at the NEXT REBOOT
                        winproxy.clear_runonce()
                        self.log.ok("Internet restored: system proxy set back "
                                    "to your previous settings.")
                        notify.notify("HookIP — internet restored",
                                      "Windows points at your original "
                                      "connection again.")
                    else:
                        self.log.error(
                            "Restore failed — neither the encrypted backup "
                            "nor the recovery script could be applied "
                            f"({winproxy.RESTORE_CMD}). "
                            "A restart of HookIP usually fixes the key "
                            "problem; try again after restarting.")
                else:
                    # FALSE-POSITIVE GUARD: a backup exists but the system
                    # proxy no longer points at HookIP — the user (or
                    # another tool) already fixed it manually. Restoring
                    # the stale backup would CLOBBER their config. Drop
                    # the backup, touch nothing else.
                    winproxy.discard_backup()
                    winproxy.clear_runonce()
                    self.log.ok("Stale proxy backup discarded — the system "
                                "proxy no longer points at HookIP, so there "
                                "is nothing to restore. Your current "
                                "settings were left untouched.")
            elif winproxy._is_ours(cur, self.cfg.port, self.pac_token) or \
                    winproxy.looks_like_ours(cur):
                winproxy.remove_proxy()
                self.log.ok("Internet restored: HookIP proxy settings cleared "
                            "(direct connection).")
                winproxy.clear_runonce()
                notify.notify("HookIP — internet restored",
                              "Stale HookIP proxy settings cleared — direct "
                              "connection is back.")
            else:
                self.log.info("Nothing to restore — system proxy is already "
                              + winproxy.describe(cur, self.pac_token))
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
            # upstream proxy: empty = direct; strip spaces and a possible
            # scheme-less 'http://' is allowed by proxy._via_upstream —
            # store the user's string verbatim minus surrounding blanks
            cfg.upstream_proxy = self.upstream_var.get().strip()
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

        prev_port = getattr(self, "_live_port", None)
        self.log.info(f"Starting proxy on 127.0.0.1:{cfg.port} …")
        if prev_port and prev_port != cfg.port:
            self.log.info(f"Proxy port switched: {prev_port} → {cfg.port} "
                          "— change noted for diagnostics.")
        # restricted-network support: if Windows already points at the
        # network's own proxy (WPAD/PAC or manual), HookIP must tunnel
        # THROUGH it — direct connects are blocked on such Wi-Fi
        try:
            prev = winproxy.read_current()
        except OSError:
            prev = {}
        # detection runs on a WORKER: the PAC fetch alone can take up to
        # 4 s and used to freeze the window on every Start (and a
        # malformed AutoConfigURL raising ValueError used to abort Start
        # outright). _via_upstream reads cfg.upstream_proxy per-connection,
        # so the result can be applied when it arrives.
        net_proxy = ""
        try:
            # registry-form only on the UI thread (instant); the PAC fetch
            # (up to 4 s) belongs to the worker below
            net_proxy = winproxy.detect_network_proxy(prev, pac=False)
        except Exception as exc:  # noqa: BLE001 — never abort Start
            self.log.debug(f"network-proxy detection failed: "
                           f"{type(exc).__name__}: {exc}")
        cfg.upstream_proxy = net_proxy
        if net_proxy:
            self._announce_upstream(net_proxy)
        else:
            def _late_detect(prev_vals=prev):
                try:
                    found = winproxy.detect_network_proxy(prev_vals)
                except Exception:
                    return
                # the race: running is only set AFTER apply_*/watchdog.start,
                # so a fast LAN PAC fetch arrived while running was still
                # False and was DROPPED — the bypass list was already
                # written with the excluded domains. self.proxy is set as
                # soon as the server is listening: gate on THAT instead.
                if found and self.proxy is not None and \
                        not getattr(self.cfg, "upstream_proxy", ""):
                    self.cfg.upstream_proxy = found
                    self._announce_upstream(found)
                    # re-apply the system proxy WITHOUT bypass entries
                    # (restricted network: DIRECT is blocked, user
                    # exclusions must not go direct) — main thread only
                    self._ui_queue.put(("reapply", ()))
            threading.Thread(target=_late_detect, daemon=True).start()
        try:
            self.proxy = ProxyServer(cfg, self.log, self.stats, self.pac_token)
            self.proxy.on_accept_death = self._on_accept_death
            self.proxy.start()
            self._live_port = cfg.port
        except OSError as exc:
            self.log.error(f"Cannot bind port {cfg.port}: {exc}")
            self.proxy = None
            return

        # system proxy + crash safety
        try:
            self.log.info("Current system proxy: " + winproxy.describe(winproxy.read_current(), self.pac_token))
            # on restricted networks DIRECT is blocked: keep excluded domains
            # OUT of the bypass lists or they would break (round-2 finding)
            bypass = None if net_proxy else cfg.excluded
            self._apply_proxy_settings(cfg, bypass)
            # RunOnce FIRST: from the moment the registry points at HookIP,
            # a crash needs a recovery path — the watchdog covers the
            # running window, RunOnce covers the sign-in after a power
            # loss, but between apply_* and watchdog.start there was NO
            # recovery at all (a crash in those milliseconds left the
            # system proxy pointing at a dead port with nothing to fix it).
            winproxy.set_runonce()
            self.watchdog.start(cfg.port)
            self.log.ok("System proxy configured.")
            # the watchdog can die at birth (AV heuristic, broken cwd) and
            # respawns once internally — 'crash protection active' used to
            # be logged even when zero children actually survived
            n_w = self.watchdog.watchers()
            (self.log.ok if n_w >= 2 else self.log.warn)(
                f"Crash protection: {n_w}/2 watchdog process(es) watching "
                "this session (heartbeat monitored).")
        except winproxy.BackupError as exc:
            # A FAILED BACKUP must not leave a half-started proxy: the
            # apply_* calls abort BEFORE any registry write, so nothing
            # was changed — stop the proxy and leave the user's settings
            # exactly as they were.
            self._handle_backup_error(exc)
            return
        except Exception as exc:  # noqa: BLE001 — nothing after the proxy is
            # up may kill the startup sequence: Windows already routes
            # through HookIP here, so the running flag and the UI MUST be
            # set regardless (a non-OSError used to leave the app looking
            # 'stopped' while the system proxy was live)
            self.log.warn(f"System proxy not fully configured: "
                          f"{type(exc).__name__}: {exc}")

        if cfg.remember:
            # save() reports failure with False (nothing raises); the
            # warning is emitted once per session by _cfg_save
            self._cfg_save("Start")
        else:
            # user chose not to remember — forget any previously stored settings
            try:
                if os.path.isfile(SETTINGS_PATH):
                    os.remove(SETTINGS_PATH)
            except OSError:
                pass
        self.running = True
        self._set_running_ui(True)
        # VPN awareness: say HONESTLY what HookIP does and does not add
        # while a full-tunnel VPN (e.g. Cloudflare WARP) is up — the user
        # asked 'do they conflict?' too often for this to stay invisible.
        # peek() = cache only: no subprocess on the Start path (the
        # pill's worker refresh keeps the cache warm; without a cached
        # answer we simply say nothing yet)
        try:
            vpn_state = vpndetect.peek()
        except Exception:
            vpn_state = None
        protect_msg = (f"Proxy running on 127.0.0.1:{cfg.port}.\n"
                       "Close (X) hides to the tray; Stop restores your "
                       "internet.")
        if vpn_state:
            self.log.info(
                f"VPN detected: {vpn_state.get('kind')} ({vpn_state.get('detail')}) — "
                + vpndetect.why_text(vpn_state))
            self._ui_queue.put(("vpn", (vpn_state,)))
            protect_msg += ("\nVPN active: "
                            + vpndetect.why_text(vpn_state).split(". ")[0] + ".")
        notify.notify("HookIP is protecting you", protect_msg)
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
            resp = b""
            s.settimeout(6)
            while b"\r\n\r\n" not in resp and len(resp) < 16384:
                try:
                    part = s.recv(4096)
                except socket.timeout:
                    break
                if not part:
                    break
                resp += part
            s.close()
            head, _, body = resp.partition(b"\r\n\r\n")
            location = ""
            for line in head.decode(errors="replace").split("\r\n")[1:]:
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
            if b"Microsoft Connect Test" in body and not location:
                self.log.debug("Restricted-network probe: direct unproxied "
                               "internet works.")
            else:
                first = resp.split(b"\r\n", 1)[0].decode(errors="replace").strip()
                portal = f" Portal login page: {location}" if location else ""
                self.log.warn(
                    "This network looks RESTRICTED or behind a captive "
                    "portal (probe answered: " + (first or "no data") + ")."
                    + portal +
                    " Log into the network's portal in a browser first — "
                    "until then app installs and Store downloads may "
                    "refuse to connect. Stopping HookIP also removes any "
                    "interference from our side.")
                if location:
                    notify.notify("HookIP — captive portal detected",
                                  "This Wi-Fi wants you to log in first. "
                                  "Open: " + location[:120], timeout_s=15)
        except OSError as exc:
            self.log.warn(
                "Direct unproxied internet probe failed (" + str(exc) + "). "
                "This network limits direct traffic — app installs (Store "
                "downloads, Windows services) do not go through HookIP and "
                "may refuse to connect here regardless of the proxy. Browsing "
                "through HookIP is unaffected.")
        except Exception as exc:  # noqa: BLE001 — a probe must never crash
            # its worker thread (an unexpected error here used to surface as
            # a dead thread with no explanation)
            self.log.debug(f"Restricted-network probe stopped: "
                           f"{type(exc).__name__}: {exc}")

    def _on_accept_death(self):
        """The listener died while Windows still points at it — without this
        hook the user's internet would be broken and the app would still say
        'Running'. Emergency: restore the original proxy settings NOW.
        BUGFIX: this runs on the proxy's accept thread — widget calls from a
        non-main thread can crash Tk (right when the proxy already died), so
        the UI refresh is marshalled through _ui_queue/_pump_ui."""
        try:
            self.log.error("Proxy listener died unexpectedly — restoring your "
                           "internet immediately.")
            notify.notify("HookIP — proxy crashed",
                          "The proxy stopped unexpectedly; your original "
                          "internet settings were restored.", timeout_s=12)
            self._emergency_restore()
            self._ui_queue.put(("emergency_done", ()))
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
        # UI refresh happens on the main thread via _pump_ui ("emergency_done")
        # — this hook runs on the accept thread and must not touch Tk directly

    def _refresh_vpn_pill(self):
        """Best-effort VPN detection for the header pill. Runs on a worker
        thread (tasklist + optional warp-cli are subprocesses); the UI is
        updated via the pump queue. Re-arms itself every 5 minutes."""
        if self._closing.is_set():
            return
        try:
            state = vpndetect.detect()
        except Exception:
            state = None
        self._ui_queue.put(("vpn", (state,)))
        if not self._vpn_refresh_scheduled:
            self._vpn_refresh_scheduled = True
            try:
                self.root.after(5 * 60 * 1000, self._vpn_refresh_loop)
            except (RuntimeError, tk.TclError):
                self._vpn_refresh_scheduled = False

    def _vpn_refresh_loop(self):
        # periodic re-check: WARP can connect/disconnect while HookIP runs
        try:
            self.root.after(5 * 60 * 1000, self._vpn_refresh_loop)
        except (RuntimeError, tk.TclError):
            return
        threading.Thread(target=self._refresh_vpn_pill, daemon=True).start()

    def _apply_vpn_state(self, state):
        """Main-thread: show/hide the VPN pill with the honest WHY."""
        try:
            if state:
                self.vpn_pill.configure(
                    text=f"⛓ VPN ({state.get('detail', 'active')})",
                    fg=MUTED)
                if not self.vpn_pill.winfo_manager():
                    self.vpn_pill.pack(side="left", padx=(0, 8))
                if self.vpn_tip:
                    self.vpn_tip.set_text(
                        f"VPN detected: {state.get('kind')} — "
                        + vpndetect.why_text(state))
                else:
                    self.vpn_tip = Tooltip(
                        self.vpn_pill,
                        f"VPN detected: {state.get('kind')} — "
                        + vpndetect.why_text(state))
            else:
                try:
                    self.vpn_pill.pack_forget()
                except tk.TclError:
                    pass
        except (tk.TclError, RuntimeError):
            pass

    def _apply_proxy_settings(self, cfg, bypass=None):
        """Write the system proxy per the configured mode. May raise
        winproxy.BackupError (nothing was written then) or OSError."""
        if cfg.proxy_mode == "manual":
            winproxy.apply_manual(cfg.port, bypass=bypass)
        elif cfg.proxy_mode == "pac":
            winproxy.apply_pac(cfg.port, self.pac_token)
        else:
            winproxy.apply_both(cfg.port, self.pac_token, bypass=bypass)

    def _handle_backup_error(self, exc):
        """A FAILED BACKUP must not leave a half-started proxy: the
        apply_* calls abort BEFORE any registry write, so nothing was
        changed — stop the proxy and leave the user's settings exactly
        as they were. running stays False."""
        self.log.error(
            "Could not save your original proxy settings, HookIP was "
            f"not started; nothing was changed ({exc})")
        notify.notify(
            "HookIP — not started",
            "Your proxy settings could not be backed up, so HookIP "
            "did not start. Nothing was changed — try freeing disk "
            "space or restarting.", timeout_s=15)
        try:
            if self.proxy:
                self.proxy.stop()
        except Exception:
            pass
        self.proxy = None

    def _reapply_system_proxy(self):
        """Late network-proxy detection: re-apply the system proxy WITHOUT
        bypass entries (restricted network: DIRECT is blocked, so user
        exclusions must not be served as DIRECT). Runs on the MAIN thread
        (via _pump_ui) — a background thread must never touch winreg/Tk;
        does nothing when the proxy was stopped meanwhile."""
        if not (self.running and self.proxy):
            return                      # stopped while detection ran
        try:
            self._apply_proxy_settings(self.cfg, bypass=None)
            self.log.ok("System proxy re-applied without bypass entries — "
                        "the network's own proxy arrived late.")
        except Exception as exc:  # noqa: BLE001 — re-apply is best-effort
            self.log.warn(f"Could not re-apply the system proxy: "
                          f"{type(exc).__name__}: {exc}")

    def _cfg_save(self, where=""):
        """cfg.save() with the once-per-session failure warning.
        save() returns True/False and never raises; repeated failures
        must not spam the log."""
        ok = True
        try:
            ok = self.cfg.save()
        except Exception as exc:  # noqa: BLE001 — defensive
            ok = False
            if not getattr(self.cfg, "last_save_error", None):
                self.cfg.last_save_error = f"{type(exc).__name__}: {exc}"
        if ok is False and not getattr(self, "_save_failed_warned", False):
            self._save_failed_warned = True
            reason = getattr(self.cfg, "last_save_error", "") or "unknown error"
            self.log.warn(f"Settings could not be saved ({where}): {reason}")
        return ok

    def _announce_upstream(self, net_proxy):
        """Log + toast a detected network proxy (credentials masked)."""
        shown = winproxy.mask_proxy(net_proxy)
        self.log.ok(f"This network requires its own proxy ({shown}) — "
                    "HookIP will tunnel through it automatically.")
        notify.notify("HookIP — restricted network detected",
                      f"Your Wi-Fi only allows traffic through its own "
                      f"proxy ({shown}). HookIP now chains through "
                      "it, so sites keep working.", timeout_s=12)
        # reflect the detected upstream in the Settings field (worker
        # thread must not touch Tk — route through the pump)
        self._ui_queue.put(("upstream_ui", (net_proxy,)))

    def stop_proxy(self, tell_user=True):
        if not self.running:
            return
        self.running = False
        proxy = self.proxy
        if proxy:
            proxy.stop()
            self.proxy = None
        try:
            # _live_port is deliberately KEPT across Stop: the next Start
            # can then log 'port switched: a → b' for the diagnostics
            self.watchdog.stop()
            winproxy.clear_runonce()
            restored = winproxy.restore_from_file()
            if not restored and winproxy.has_backup():
                # the backup EXISTS but could not be applied (degraded key
                # session): the plaintext recovery script written next to
                # it holds the same original values (credentials stripped)
                restored = winproxy.restore_from_cmd()
                if restored:
                    self.log.ok("System proxy restored from the recovery "
                                "script — the encrypted backup could not be "
                                "decrypted this session. If your upstream "
                                "proxy needed a password, enter it again.")
            if restored:
                self.log.ok("System proxy restored to previous settings.")
            else:
                # no (usable) backup (e.g. wiped while running) — clear our
                # own entries by EXACT match (or the self-identifying stale
                # PAC URL): the old '127.0.0.1 in …' heuristic wiped a local
                # Clash/Fiddler/V2Ray config that was never HookIP's
                cur = winproxy.read_current()
                if winproxy._is_ours(cur, self.cfg.port, self.pac_token) or \
                        winproxy.looks_like_ours(cur):
                    winproxy.remove_proxy()
                    self.log.ok("Proxy backup missing — cleared HookIP proxy settings (direct connection).")
                elif winproxy.has_backup():
                    self.log.error(
                        "Restore failed: the encrypted backup could not be "
                        "decrypted and the recovery script did not apply — "
                        "Windows may still point at HookIP. Restart HookIP "
                        "(usually fixes the key problem) and use 'Restore "
                        "internet', or run " + winproxy.RESTORE_CMD + " manually.")
                else:
                    self.log.warn("No proxy backup found and current proxy is not HookIP's; left untouched.")
        except OSError as exc:
            self.log.error(f"Restore failed: {exc}")
            restored = False
        # the app (not proxy.stop()) persists strategy memory AFTER the
        # system proxy is back — stop() itself must not do disk I/O
        try:
            if proxy:
                proxy.persist_strat_memory()
        except Exception:
            pass
        self._set_running_ui(False)
        if tell_user:
            # HONEST toast: say what actually happened (backup restore vs
            # direct fallback) instead of always claiming 'your normal
            # connection is back'
            notify.notify("HookIP — internet restored",
                          "Proxy stopped. Your normal connection is back."
                          if restored else
                          "Proxy stopped — Windows is set to a direct "
                          "connection (your previous proxy settings could "
                          "not be restored this session).")

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
        # the native tray menu rebuilds its Start/Stop label from this
        try:
            self.tray.set_menu_state(running)
        except Exception:
            pass
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

    def _log_entry_visible(self, level, msg):
        """One place decides what the on-screen log shows: the 'Show'
        importance filter AND the 🔍 Find box (live substring match)."""
        if logutil.LEVEL_RANK.get(level, 1) < self._log_min_rank:
            return False
        q = getattr(self, "_log_query", "")
        return not q or q in str(msg).lower()

    def _jump_to_latest(self):
        # vertical-only (see _pump_log): see("end") with wrap="none" also
        # scrolls horizontally and can land the viewport in blank space
        try:
            self.log_text.yview_moveto(1.0)
        except tk.TclError:
            pass
        self.jump_latest.pack_forget()

    def _open_log_folder(self):
        path = self._log_dir
        try:
            os.makedirs(path, exist_ok=True)
            subprocess.Popen(["explorer", os.fspath(path)])
            self.log.info(f"Opened the logs folder: {path}")
        except OSError as exc:
            self.log.error(f"Could not open the logs folder: {exc}")

    def _pump_log(self):
        try:
            entries = self.log.drain()
            if entries:
                self._log_all.extend(entries)
                buf_cap = profile().log_buffer      # tier-scaled, matches Log
                if len(self._log_all) > buf_cap:
                    self._log_all = self._log_all[-buf_cap:]
                new_entries = [e for e in entries if self._log_entry_visible(e[0], e[2])]
                if new_entries:
                    self.log_text.configure(state="normal")
                    # decide BEFORE inserting — insertion itself shifts the view
                    at_bottom = self.log_text.yview()[1] >= 0.98
                    for level, ts, msg, _date in new_entries:
                        extra = self._log_semantic_tag(msg)
                        tags = (level, extra) if extra else (level,)
                        self.log_text.insert("end", f"[{ts}] ", "ts")
                        self.log_text.insert("end", f"{msg}\n", tags)
                    self.log_text.configure(state="disabled")
                    # follow new lines only when the reader was already at the
                    # bottom — otherwise scrolling up gets yanked back down,
                    # and the ↓ latest button tells them what they are missing.
                    # VERTICAL-ONLY follow: Text.see("end") also scrolls
                    # HORIZONTALLY to the end of the last line — with
                    # wrap="none" and a long final line (most debug lines are
                    # long) the viewport was pushed right of where the short
                    # lines end, rendering the whole log BLANK. The empty
                    # activity log in the wild was this, not a dead pump.
                    if at_bottom:
                        self.log_text.yview_moveto(1.0)
                        try:
                            self.jump_latest.pack_forget()
                        except (tk.TclError, AttributeError):
                            pass
                    else:
                        try:
                            self.jump_latest.pack(side="right", padx=(0, 6))
                        except (tk.TclError, AttributeError):
                            pass
            keep = profile().log_screen_lines
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > keep:
                # the trim was silently IGNORED while the widget is
                # 'disabled' (Tk ignores delete on a disabled Text) — the
                # on-screen log grew without bound in long sessions
                self.log_text.configure(state="normal")
                self.log_text.delete("1.0", f"{lines - (keep - 500)}.0")
                self.log_text.configure(state="disabled")
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
        try:
            self._log_query = self.log_search.get().strip().lower()
        except (tk.TclError, AttributeError):
            self._log_query = ""
        # re-render the visible log from the in-app history
        try:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            for level, ts, msg, _date in self._log_all:
                if self._log_entry_visible(level, msg):
                    extra = self._log_semantic_tag(msg)
                    tags = (level, extra) if extra else (level,)
                    self.log_text.insert("end", f"[{ts}] ", "ts")
                    self.log_text.insert("end", f"{msg}\n", tags)
            self.log_text.configure(state="disabled")
            self.log_text.yview_moveto(1.0)
            self.jump_latest.pack_forget()
        except tk.TclError:
            pass

    def _log_report_text(self, min_rank=None):
        rank = self._log_min_rank if min_rank is None else min_rank
        today = time.strftime("%Y-%m-%d")
        lines = [f"HookIP {__version__} log — {today}"]
        for level, ts, msg, date in self._log_all:
            if logutil.LEVEL_RANK.get(level, 1) >= rank:
                # per-entry date: a session spanning midnight must not
                # export older lines under today's date
                lines.append(f"[{date} {ts}] [{level.upper():5}] {msg}")
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
            for key, count in (("active", active), ("failed", failed),
                               ("blocked", blocked)):
                lit, normal = self._dash_colors[key]
                self.dash_vars[key].configure(text=str(count),
                                              fg=lit if count else normal)
            self.dash_vars["down"].configure(text=self._fmt_bytes(down))
            self.dash_vars["up"].configure(text=self._fmt_bytes(up))
            # crash protection must never silently vanish: the watchdog is a
            # separate process and can die without anyone noticing. With v3
            # there are TWO children — re-arm the pair whenever one dies,
            # not just when the protection is fully gone.
            if self.running:
                if self.watchdog.watchers() < 2:
                    self._wd_restarts = getattr(self, "_wd_restarts", 0) + 1
                    if self._wd_restarts <= 3:
                        try:
                            self.watchdog.start(self.cfg.port)
                            self.log.warn(
                                "Watchdog child died — restarted "
                                f"automatically ({self.watchdog.watchers()} "
                                "of 2 protection processes were live).")
                        except OSError:
                            pass
                    elif not getattr(self, "_wd_cap_warned", False):
                        # the restart cap gave up — say it ONCE instead of
                        # leaving crash protection silently degraded/gone
                        self._wd_cap_warned = True
                        self.log.warn(
                            "Watchdog restart cap reached — crash "
                            "protection is degraded. The proxy still "
                            "works; restart HookIP to re-arm it.")
                        try:
                            notify.notify(
                                "HookIP — crash protection degraded",
                                "The watchdog kept dying and restarts "
                                "gave up. The proxy still works; restart "
                                "HookIP to re-arm crash protection.",
                                timeout_s=30)
                        except Exception:
                            pass
                else:
                    self._wd_restarts = 0
                    self._wd_cap_warned = False   # healthy again — re-arm
                # DESYNC WATCH (crash-safety mirror): while HookIP is
                # running, the system proxy MUST point at its port. A
                # watchdog-forced restore, another tool changing the
                # setting, or a group-policy refresh silently takes
                # HookIP OUT of the path — the UI keeps saying 'running'
                # while traffic flows direct. Poll the registry every dash
                # tick (a registry read is ~µs) and warn throttled.
                try:
                    cur = winproxy.read_current()
                except OSError:
                    cur = None
                if cur is not None and not winproxy._is_ours(
                        cur, self.cfg.port, self.pac_token):
                    now_ts = time.time()
                    if now_ts - getattr(self, "_desync_warn_at", 0) > 300:
                        self._desync_warn_at = now_ts
                        self.log.warn(
                            "System proxy no longer points at HookIP "
                            "(changed externally or restored by crash "
                            "protection) — traffic is bypassing HookIP. "
                            "Press ⏹ Stop, then ▶ Start to re-arm.")
            if self.root.state() == "normal":
                self._draw_spark()
            if self.root.state() != "normal":
                # minimized OR hidden to tray ('withdrawn' — the old
                # '!= iconic' check still redrew every tick while hidden)
                # skip the expensive top-domains redraw (stats keep
                # accumulating; the watchdog check above still ran)
                pass
            else:
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
            # hardware-scaled cadence: redraw less often on weak machines,
            # and drop to the idle cadence when nothing is flowing
            from .perf import profile
            p = profile()
            interval = p.dash_interval_ms if self.running else p.idle_dash_interval_ms
            self.root.after(interval, self._refresh_dashboard)
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

        # capture Tk variables on the MAIN thread — the work() thread below
        # must never touch Tk/Tk variables (cross-thread Tcl access is
        # undefined behaviour and has crashed interpreters)
        ui_port = int(self.port_var.get()) if self.port_var.get().isdigit() else self.cfg.port
        try:
            ui_frag = max(1, int(self.frag_var.get()))
        except (ValueError, tk.TclError, RuntimeError):
            ui_frag = max(1, self.cfg.fragment_size)

        def work():
            try:
                if sections in ("all", "system"):
                    self._diag_system()
                if sections == "all":
                    self._diag_settings(ui_port, ui_frag)
                if sections in ("all", "dns"):
                    self._diag_dns(ui_frag)
                if sections in ("all", "tunnel"):
                    self._diag_tunnel()
                self._diag_result("Summary", "done", "", "info")
            except Exception as exc:  # noqa: BLE001
                self._diag_result("Diagnostics", "error", str(exc), "fail")
            finally:
                self._diag_running = False
                self._ui_queue.put(("diag_done", ()))

        threading.Thread(target=work, daemon=True).start()

    def _diag_settings(self, ui_port=None, ui_frag=None):
        """Sanity of the numeric settings + port availability.
        ui_port/ui_frag are captured on the main thread before this runs
        (background threads must not read Tk variables)."""
        self._diag_section("Settings")
        try:
            port = ui_port if ui_port is not None else int(self.port_var.get())
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
                        note = (f" — differs from the running proxy on "
                                f"{self.cfg.port} (press ⏹ Stop, then ▶ Start "
                                "to switch)" if self.running else "")
                        self._diag_result("Port availability", "OK",
                                          f"{port} is free{note}", "ok")
                    except OSError as exc:
                        if getattr(exc, "winerror", None) == 10013:
                            self._diag_result(
                                "Port availability", "FAIL",
                                f"{port} is blocked by Windows (reserved port "
                                "range — Hyper-V/WSL/Docker reserve large "
                                "blocks); Start would refuse it", "fail")
                        else:
                            self._diag_result("Port availability", "WARN",
                                              f"{port} is already in use — Start "
                                              f"would refuse it ({exc})", "warn")
                    finally:
                        s.close()
        except (ValueError, tk.TclError):
            self._diag_result("Local port", "FAIL", "not a number (1–65535)", "fail")
        try:
            frag = ui_frag if ui_frag is not None else int(self.frag_var.get())
            ok = 1 <= frag <= 255
            self._diag_result("Fragment size", "OK" if ok else "FAIL",
                              f"{frag} bytes" if ok else f"{frag} is not in 1–255",
                              "ok" if ok else "fail")
        except (ValueError, tk.TclError):
            self._diag_result("Fragment size", "FAIL", "not a number (1–255)", "fail")
        pats = self._parse_excluded()
        self._diag_result("Excluded domains", "OK", f"{len(pats)} valid pattern(s)", "ok")
        try:
            from . import dataguard as _dg
            # READ-ONLY check — this used to call Config.save() from the
            # diagnostics worker thread, which recreated settings.json even
            # with 'Remember settings' off and raced the main thread's saves
            enc = _dg.is_encrypted_file(SETTINGS_PATH, _dg.CFG_MAGIC)
            if not os.path.exists(SETTINGS_PATH):
                self._diag_result("Settings file", "OK",
                                  "not saved yet ('Remember settings' is off)", "ok")
            elif enc:
                self._diag_result("Settings file", "OK",
                                  SETTINGS_PATH + " · encrypted at rest "
                                  "(per-install key)", "ok")
            else:
                self._diag_result("Settings file", "WARN",
                                  SETTINGS_PATH + " · settings stored as "
                                  "plaintext (re-encrypts on next save)", "warn")
        except OSError as exc:
            self._diag_result("Settings file", "WARN",
                              f"cannot read: {exc}", "warn")

    def _diag_system(self):
        self._diag_section("System")
        # VPN awareness in the report: the WHY belongs in diagnostics too
        try:
            vstate = vpndetect.detect()
        except Exception:
            vstate = None
        if vstate:
            self._diag_result(
                "VPN", "info",
                f"{vstate.get('kind')} ({vstate.get('detail')}) — "
                + vpndetect.why_text(vstate))
        else:
            self._diag_result(
                "VPN", "info",
                "no VPN detected — HookIP's SNI fragmentation and DoH are "
                "doing real work right now (with a VPN up they would be "
                "redundant, not broken)")
        import platform
        self._diag_result("Environment", "info",
                          f"HookIP {__version__}"
                          + (f" build {__build_id__}" if __build_id__ else "")
                          + f" · Python {sys.version.split()[0]} · "
                          f"{platform.system()} {platform.release()} ({platform.machine()})")
        try:
            from .perf import profile
            self._diag_result("Performance profile", "info", profile().describe())
        except Exception:
            pass
        try:
            from . import dataguard
            from .config import APP_DIR          # BUGFIX: referenced below but
                                                 # only ever imported inside
                                                 # __init__ — when hardening had
                                                 # failed, the NameError was
                                                 # swallowed and the whole 'Data
                                                 # protection' diagnostic row
                                                 # silently vanished
            log_files = [n for n in (os.listdir(self._log_dir)
                                     if os.path.isdir(self._log_dir) else [])
                         if n.startswith("hookip_") and (n.endswith(".hlog") or n.endswith(".log"))]
            n_enc = sum(1 for n in log_files if n.endswith(".hlog"))
            n_plain = len(log_files) - n_enc
            # leftover migration claims still hold PLAINTEXT on disk —
            # they used to be invisible in this count
            n_migrating = sum(1 for n in (os.listdir(self._log_dir)
                              if os.path.isdir(self._log_dir) else [])
                              if n.endswith(".log.migrating"))
            cfg_enc = (not os.path.exists(SETTINGS_PATH)) or dataguard.is_encrypted_file(
                SETTINGS_PATH, dataguard.CFG_MAGIC)
            acl_ok = getattr(self, "_dg_acl_ok", False) or dataguard.acl_is_hardened(APP_DIR)
            # the key MODE is part of the truth: a degraded session writes
            # with the LEGACY static entropy (public in the repo) — the
            # user must know that, not read a green 'protected' row
            try:
                key_mode = ("per-install key" if dataguard.using_per_install_key()
                            else "legacy entropy (registry unavailable)")
            except Exception:
                key_mode = "unknown"
            degraded = getattr(self.cfg, "degraded", False)
            if n_plain == 0 and cfg_enc and acl_ok and not n_migrating and not degraded:
                self._diag_result(
                    "Data protection", "OK",
                    f"logs encrypted {n_enc}/{len(log_files)} · settings "
                    f"encrypted ({key_mode}) · folder locked to your "
                    "account · limits: same-user software can still "
                    "reverse DPAPI; old plaintext may persist in free "
                    "disk space, OneDrive history and backups")
            else:
                missing = []
                if n_plain:
                    missing.append(f"{n_plain} plaintext log(s) pending encryption")
                if n_migrating:
                    missing.append(f"{n_migrating} migration claim file(s) "
                                   "still hold plaintext")
                if not cfg_enc:
                    missing.append("settings stored as plaintext")
                if not acl_ok:
                    missing.append("folder ACL default")
                if degraded or key_mode != "per-install key":
                    missing.append(f"encryption key: {key_mode}")
                self._diag_result("Data protection", "WARN",
                                  " · ".join(missing) + " — retry on next start", "warn")
        except Exception:
            pass
        cur = winproxy.read_current()
        self._diag_result("System proxy", "info", winproxy.describe(cur, self.pac_token))
        # stale-proxy detection: registry points at HookIP while we're off
        if not self.running and winproxy._is_ours(cur, self.cfg.port, self.pac_token):
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
                          (f"{self.watchdog.watchers()} watchdog process(es) · "
                           "heartbeat monitored") if self.watchdog.alive() else "",
                          "info")
        # runtime memory health: the bounded caches should show sane sizes
        if self.proxy:
            pos, neg = self.proxy.resolver.cache_stats()
            self._diag_result("Runtime state", "info",
                              f"DNS cache {pos}+{neg} entries · strategy memory "
                              f"{len(self.proxy._strat_pref)} hosts · "
                              f"{self.stats.totals()[1]} connections open")
        net_up = str(getattr(self.cfg, "upstream_proxy", "") or "")
        self._diag_result("Network proxy", "info",
                          f"tunneling through the network's own proxy ({net_up})"
                          if net_up else "none — direct connections allowed")
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

    def _diag_dns(self, ui_frag=None):
        self._diag_section("DNS resolvers (DNS-over-HTTPS)")
        try:
            frag = ui_frag if ui_frag is not None else max(1, int(self.frag_var.get()))
        except (ValueError, tk.TclError, RuntimeError):
            frag = max(1, self.cfg.fragment_size)
        query = dnsmsg.encode_query("example.com")
        ok_count = 0
        for name, host, ip in RESOLVERS:
            t0 = time.time()
            try:
                try:
                    conn = _DoHConn(ip, host, timeout=4, chunk=frag,
                                    validate_by_ip=True)
                except ssl.SSLCertVerificationError:
                    # the resolver's cert has no IP SAN — retry with the
                    # hostname SNI instead of reporting a flat FAIL (the
                    # direct construction had NO fallback at all)
                    conn = _DoHConn(ip, host, timeout=4, chunk=frag,
                                    validate_by_ip=False)
                try:
                    resp = conn.request(host, query)
                    rcode, answers = dnsmsg.parse_response(resp)
                    ips = dnsmsg.extract_ips(answers, 1)
                    dt = time.time() - t0
                    if rcode == 0 and ips:
                        ok_count += 1
                        # surface the SNI mode from the CONNECTION's own
                        # flag (the previous getattr(conn, ..., True)
                        # defaulted to 'SNI-less' even when the attribute
                        # was missing — it could lie)
                        sni = ("SNI-less" if getattr(conn, "validate_by_ip",
                                                    True) else "SNI sent")
                        self._diag_result(name, "OK",
                                          f"{dt:.2f}s · {sni} · A records: {', '.join(ips[:2])}",
                                          "ok")
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
        # snapshot BEFORE the checks: Stop during the test clears
        # self.proxy on the main thread — reaching back into it below
        # (locks/detail) could hit None mid-diagnostic
        proxy = self.proxy
        if not (self.running and proxy):
            self._diag_result("Tunnel test", "skipped", "start the proxy first", "info")
            return
        ok_count = 0
        sites = ("github.com", "wikipedia.org", "www.gnu.org")
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
        # Steam-style patterns that used to break apps:
        try:
            result = self._big_head_test()
            self._diag_result("Big-cookie request (Steam-style)", "OK",
                              f"{result} — huge cookie heads no longer "
                              "truncate", "ok")
            ok_count += 1
        except Exception as exc:  # noqa: BLE001
            self._diag_result("Big-cookie request (Steam-style)", "FAIL",
                              str(exc)[:120], "fail")
        try:
            result = self._ip_connect_test()
            self._diag_result("IP-literal CONNECT (Steam CDN-style)", "OK",
                              f"{result} — connecting by IP works", "ok")
            ok_count += 1
        except Exception as exc:  # noqa: BLE001
            self._diag_result("IP-literal CONNECT (Steam CDN-style)", "FAIL",
                              str(exc)[:120], "fail")
        n = len(sites) + 2
        self._diag_result("Tunnel summary", f"{ok_count}/{n} passed", "",
                          "ok" if ok_count == n else ("warn" if ok_count else "fail"))
        # last-tunnel detail straight from the running proxy
        with proxy._detail_lock:
            detail = dict(proxy._tunnel_detail)
            if detail:
                best = sorted(detail.items(), key=lambda kv: kv[1][4])[:3]
                self._diag_result("Last tunnels", "info",
                                  " · ".join(f"{h.split('.')[0]} {v[4]:.0f}ms via {v[0]} "
                                             f"(dns {v[1]:.0f}+conn {v[2]:.0f}ms, {v[3]} seg)"
                                             for h, v in best), "info")

    def _big_head_test(self):
        """Plain-HTTP request with a Steam-sized Cookie head (~40 KB).
        The old 32 KB read cap truncated this into a malformed upstream
        request — the 'Steam sometimes refuses' bug."""
        local_port = self.cfg.port   # only reached while running; cfg.port is
                             # authoritative and avoids a bg-thread Tk read
        cookie = "; ".join(f"session{i}=" + ("x" * 96) for i in range(500))
        req = (f"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
               f"Cookie: {cookie}\r\nConnection: close\r\n\r\n").encode()
        assert len(req) > 40000, "test header not big enough"
        with socket.create_connection(("127.0.0.1", local_port), timeout=15) as s:
            s.sendall(req)
            resp = b""
            while b"\r\n\r\n" not in resp:
                part = s.recv(4096)
                if not part:
                    break
                resp += part
            if not resp:
                raise OSError("proxy closed without a response")
            return resp.split(b"\r\n", 1)[0].decode(errors="replace")

    def _ip_connect_test(self):
        """Steam CDNs often CONNECT by literal IP with the SNI carrying the
        name. Mimic that end-to-end: resolve via the proxy's DoH, CONNECT to
        the IP, then TLS with the real hostname."""
        local_port = self.cfg.port   # only reached while running; cfg.port is
                             # authoritative and avoids a bg-thread Tk read
        host = "github.com"
        ips = self.proxy.resolver.resolve(host) if self.proxy else [socket.gethostbyname(host)]
        with socket.create_connection(("127.0.0.1", local_port), timeout=10) as s:
            s.sendall(f"CONNECT {ips[0]}:443 HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
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
                            b"\r\nUser-Agent: Mozilla/5.0 HookIP-diag\r\n"
                            b"Connection: close\r\n\r\n")
                return tls.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")
            finally:
                tls.close()

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
        """Drive a real CONNECT + TLS handshake through our own proxy.
        Returns the response line PLUS a timing breakdown (CONNECT / TLS /
        first byte) so a slow stage is visible in diagnostics."""
        local_port = self.cfg.port   # only reached while running; cfg.port is
                             # authoritative and avoids a bg-thread Tk read
        t_connect = t_tls = t_ttfb = 0.0
        t0 = time.time()
        with socket.create_connection(("127.0.0.1", local_port), timeout=10) as s:
            s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                part = s.recv(4096)
                if not part:
                    raise OSError("proxy closed")
                resp += part
            t_connect = time.time() - t0
            if b" 200 " not in resp.split(b"\r\n", 1)[0]:
                raise OSError(resp.split(b"\r\n", 1)[0].decode(errors="replace"))
            t1 = time.time()
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname=host)
            t_tls = time.time() - t1
            try:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                            b"\r\nUser-Agent: Mozilla/5.0 HookIP-diag\r\n"
                            b"Connection: close\r\n\r\n")
                data = tls.recv(512)
                t_ttfb = time.time() - t1
                line = data.split(b"\r\n", 1)[0].decode(errors="replace")
                return (f"{line} · connect {t_connect:.2f}s · tls {t_tls:.2f}s · "
                        f"first byte {t_ttfb:.2f}s")
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
            # the final save must never skip the cleanup below (tray icon,
            # log file) — a failed save used to leave the tray icon behind
            try:
                self.cfg.minimize_to_tray = self.tray_var.get()
                if self.cfg.remember:
                    self._cfg_save("exit")
            except Exception:
                pass
            # strategy memory is persisted by the APP after the system
            # proxy is restored (stop() no longer saves); keep a local
            # reference — self.proxy is cleared by stop_proxy
            _proxy = self.proxy
            try:
                if _proxy:
                    _proxy.persist_strat_memory()
            except Exception:
                pass
            self.log.session_end()
            self.log.close_file()
            try:
                self.tray.stop()
            except Exception:
                pass
        finally:
            self.root.destroy()


def run():
    # update leftover cleanup: a completed same-name update leaves the
    # previous version as HookIP.exe.old — once WE are the new exe and
    # hold the single-instance mutex, the old file is dead weight
    if getattr(sys, "frozen", False):
        try:
            old = os.path.join(os.path.dirname(os.path.abspath(sys.executable)),
                               "HookIP.exe.old")
            if os.path.exists(old):
                os.remove(old)
        except OSError:
            pass                        # locked/AV-scanning — next run
    # Single instance: if another HookIP is running, activate it and exit.
    # None = another instance holds the mutex; False = the mutex could not
    # be created at all (a NULL handle used to be reported as 'already
    # running', which was a lie) — proceed without single-instance then.
    mutex = winproxy.acquire_single_instance()
    if mutex is False:
        mutex = None
    elif mutex is None:
        root = tk.Tk()
        root.withdraw()
        if winproxy.notify_running_instance():
            messagebox.showinfo(
                APP_NAME,
                f"{APP_NAME} is already running —\nit was brought to the front instead.")
        else:
            messagebox.showwarning(
                APP_NAME,
                f"{APP_NAME} is already running.\n"
                f"Close the other instance before starting a new one.")
        root.destroy()
        return
    root = tk.Tk()
    try:
        app = App(root)
        root.mainloop()
    except Exception:
        # GUARD: a startup crash used to die silently (window blinks and
        # vanishes). Show what happened, and restore any proxy we changed.
        import traceback
        err = "".join(traceback.format_exception_only(
            sys.exc_info()[0], sys.exc_info()[1])).strip()
        try:
            from .logutil import Log
            l = Log()
            l.error(f"Startup failure: {err}")
            l.session_end()
            l.close_file()
        except Exception:
            pass
        try:
            if winproxy.has_backup():
                winproxy.restore_from_file()
            elif winproxy._is_ours(winproxy.read_current()):
                # no app instance exists here — heuristic fallback
                winproxy.remove_proxy()
        except Exception:
            pass
        try:
            messagebox.showerror(
                APP_NAME,
                "HookIP failed to start:" + chr(10) * 2 + err[:600] +
                "Your internet settings were left untouched." + chr(10) +
                "Details are in the newest log file under "
                "%LOCALAPPDATA%" + chr(92) + "HookIP" + chr(92) + "logs.")
        except Exception:
            pass
    try:
        import ctypes
        ctypes.windll.kernel32.CloseHandle(mutex)
    except Exception:
        pass

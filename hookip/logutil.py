"""Thread-safe in-memory log with GUI subscription and file sink."""
import threading
import time
import os
import glob
from collections import deque

from . import dataguard
from .perf import profile

LEVEL_RANK = {"debug": 0, "info": 1, "ok": 1, "warn": 2, "error": 3}


def purge_old_logs(log_dir, days, keep=""):
    """Delete session log files older than `days` (mtime-based).

    Old .hlog files are encrypted, but encryption limits WHO can read a
    stolen file — not how LONG a years-deep browsing-history trove sits
    around waiting to be stolen. Retention is the privacy control that
    bounds the blast radius.

    `keep` is the CURRENT session's basename — never removed even if its
    mtime somehow reads old. Legacy .log/.migrating leftovers age out with
    the same clock. Returns the basenames removed. Never raises.
    """
    import glob as _glob
    import time as _time
    removed = []
    if not days or not log_dir or not os.path.isdir(log_dir):
        return removed
    cutoff = _time.time() - days * 86400
    patterns = (os.path.join(log_dir, "hookip_*.hlog"),
                os.path.join(log_dir, "hookip_*.log"),
                os.path.join(log_dir, "hookip_*.log.migrating"))
    seen = set()
    for pat in patterns:
        for p in _glob.glob(pat):
            b = os.path.basename(p)
            if b in seen or b == keep or b == f"{keep}.migrating":
                continue
            seen.add(b)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed.append(b)
            except OSError:
                pass
    return removed


class Log:
    def __init__(self, maxlen=None):
        # default buffer scales with the hardware tier (perf.py): a 2-core
        # laptop keeps 1200 entries, a desktop 3000 — the file sink always
        # gets everything regardless
        if maxlen is None:
            maxlen = profile().log_buffer
        self._lock = threading.Lock()
        self._buf = deque(maxlen=maxlen)
        self._subs = []
        self._file = None
        self.file_error = None     # last file-sink failure, surfaced once
        self.verbose = False

    def subscribe(self, callback):
        """callback(level, timestamp, message) for every *new* entry."""
        with self._lock:
            self._subs.append(callback)

    def unsubscribe(self, callback):
        with self._lock:
            if callback in self._subs:
                self._subs.remove(callback)

    def attach_file(self, path):
        """Mirror every log entry into a DPAPI-encrypted session file.

        Each line is encrypted individually before it touches disk, so a
        stolen log file shows no browsing history. A .log path is
        redirected to .hlog automatically.
        """
        with self._lock:
            # a previous file sink (re-attach) must not leak its handle
            old, self._file = self._file, None
            if old:
                try:
                    old.close()
                except OSError:
                    pass
            try:
                if path.endswith(".log"):
                    path = path[:-4] + ".hlog"
                os.makedirs(os.path.dirname(path), exist_ok=True)
                fh = open(path, "a", encoding="utf-8")
                fh.write(dataguard.encrypt_line(
                    f"# HookIP session log started {time.strftime('%Y-%m-%d %H:%M:%S')}",
                    magic=dataguard.LOG_MAGIC) + "\n")
                fh.flush()
                self._file = fh
            except OSError as exc:
                try:
                    fh.close()
                except (OSError, NameError, UnboundLocalError):
                    pass
                # a silent failure used to leave the UI claiming a session
                # file that does not exist; remember it so the app can say so
                if not self.file_error:
                    self.file_error = str(exc)

    def close_file(self):
        with self._lock:
            if self._file:
                try:
                    self._file.close()
                except OSError:
                    pass
                self._file = None

    @staticmethod
    def prune_session_files(log_dir, keep=7):
        """Delete old session logs, newest `keep` are kept."""
        try:
            files = [p for pat in ("hookip_*.log", "hookip_*.hlog")
                     for p in glob.glob(os.path.join(log_dir, pat))]
            files = sorted(files, key=os.path.getmtime, reverse=True)
            for old in files[keep:]:
                os.remove(old)
        except OSError:
            pass

    def _emit(self, level, ts, msg, screen=True):
        date = time.strftime("%Y-%m-%d")
        entry = (level, ts, msg, date)   # date travels with the entry:
                                         # a session spanning midnight must
                                         # not export every line under
                                         # today's date
        with self._lock:
            if self._file:
                try:
                    plain = f"[{date} {ts}] [{level.upper():5}] {msg}"
                    self._file.write(dataguard.encrypt_line(plain) + "\n")
                    self._file.flush()
                except OSError:
                    pass
            self._buf.append(entry)
            subs = list(self._subs) if screen else []
        for cb in subs:
            try:
                cb(*entry[:3])      # subscriber contract stays 3-arg
            except Exception:
                pass

    def write(self, level, msg, screen=True):
        self._emit(level, time.strftime("%H:%M:%S"), msg, screen)

    def info(self, msg):
        self.write("info", msg)

    def ok(self, msg):
        self.write("ok", msg)

    def warn(self, msg):
        self.write("warn", msg)

    def error(self, msg):
        self.write("error", msg)

    def debug(self, msg):
        # Always persisted to the session file (bug reports), shown on screen
        # only when verbose mode is on or the filter is set to 'Everything'.
        # The buffer keeps it so the 'Everything' filter can reveal it.
        self._emit("debug", time.strftime("%H:%M:%S"), msg,
                   screen=self.verbose)

    def session_end(self):
        """Write a footer so interrupted sessions are identifiable on disk."""
        self.write("info", "— session log ended —")

    def drain(self):
        """Atomically return and clear all buffered entries."""
        with self._lock:
            out = list(self._buf)
            self._buf.clear()
        return out

    def snapshot(self):
        with self._lock:
            return list(self._buf)

    def export_text(self, min_rank=0):
        """All buffered entries, formatted (per-entry date) for reports."""
        with self._lock:
            entries = list(self._buf)
        lines = []
        for level, ts, msg, date in entries:
            if LEVEL_RANK.get(level, 1) < min_rank:
                continue
            lines.append(f"[{date} {ts}] [{level.upper():5}] {msg}")
        return "\n".join(lines)

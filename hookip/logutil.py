"""Thread-safe in-memory log with GUI subscription and file sink."""
import threading
import time
import os
import glob
from collections import deque

LEVEL_RANK = {"debug": 0, "info": 1, "ok": 1, "warn": 2, "error": 3}


class Log:
    def __init__(self, maxlen=3000):
        self._lock = threading.Lock()
        self._buf = deque(maxlen=maxlen)
        self._subs = []
        self._file = None
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
        """Mirror every log entry into a session file."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                self._file = open(path, "a", encoding="utf-8")
                self._file.write(f"# HookIP session log started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._file.flush()
            except OSError:
                self._file = None

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
            files = sorted(glob.glob(os.path.join(log_dir, "hookip_*.log")),
                           key=os.path.getmtime, reverse=True)
            for old in files[keep:]:
                os.remove(old)
        except OSError:
            pass

    def _emit(self, level, ts, msg, screen=True):
        entry = (level, ts, msg)
        with self._lock:
            if self._file:
                try:
                    self._file.write(f"[{time.strftime('%Y-%m-%d')} {ts}] [{level.upper():5}] {msg}\n")
                    self._file.flush()
                except OSError:
                    pass
            self._buf.append(entry)
            subs = list(self._subs) if screen else []
        for cb in subs:
            try:
                cb(*entry)
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
        """All buffered entries, formatted (with date) for reports/bug filing."""
        with self._lock:
            entries = list(self._buf)
        today = time.strftime("%Y-%m-%d")
        lines = []
        for level, ts, msg in entries:
            if LEVEL_RANK.get(level, 1) < min_rank:
                continue
            lines.append(f"[{today} {ts}] [{level.upper():5}] {msg}")
        return "\n".join(lines)

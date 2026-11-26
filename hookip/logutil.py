"""Thread-safe in-memory log with GUI subscription."""
import threading
import time
from collections import deque


class Log:
    def __init__(self, maxlen=3000):
        self._lock = threading.Lock()
        self._buf = deque(maxlen=maxlen)
        self._subs = []
        self.verbose = False

    def subscribe(self, callback):
        """callback(level, timestamp, message) for every *new* entry."""
        with self._lock:
            self._subs.append(callback)

    def unsubscribe(self, callback):
        with self._lock:
            if callback in self._subs:
                self._subs.remove(callback)

    def _emit(self, level, ts, msg):
        entry = (level, ts, msg)
        with self._lock:
            self._buf.append(entry)
            subs = list(self._subs)
        for cb in subs:
            try:
                cb(*entry)
            except Exception:
                pass

    def write(self, level, msg):
        self._emit(level, time.strftime("%H:%M:%S"), msg)

    def info(self, msg):
        self.write("info", msg)

    def ok(self, msg):
        self.write("ok", msg)

    def warn(self, msg):
        self.write("warn", msg)

    def error(self, msg):
        self.write("error", msg)

    def debug(self, msg):
        if self.verbose:
            self.write("debug", msg)

    def drain(self):
        """Atomically return and clear all buffered entries."""
        with self._lock:
            out = list(self._buf)
            self._buf.clear()
        return out

    def snapshot(self):
        with self._lock:
            return list(self._buf)

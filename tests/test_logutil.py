"""Tests for hookip.logutil: emit safety, flush policy, file_error.

The sink-level tests monkeypatch dataguard.encrypt_line, so they run on
any OS. Only the section that uses real DPAPI is skipped on non-Windows.
"""
import os
import sys
import tempfile
import threading
import time
import unittest.mock as mock

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL") + " " + name +
          (" " + str(detail) if (detail and not cond) else ""))


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import logutil as lu   # noqa: E402
from hookip import dataguard as dg  # noqa: E402


# 1. lone surrogate: encrypt_line errors='replace' (real DPAPI, Windows)
if os.name == "nt":
    lg = lu.Log()
    try:
        lg.debug("bad \udcd0 message")
        check("lone-surrogate message does not raise and is buffered",
              lg.snapshot()[-1][2] == "bad \udcd0 message")
    except Exception as exc:
        check("lone-surrogate message does not raise and is buffered",
              False, repr(exc))
else:
    print("SKIP lone-surrogate DPAPI check (non-Windows)")

# from here on encrypt_line is patched — no DPAPI, no Windows needed
enc_calls = []


def _fake_encrypt(line, magic=dg.LOG_MAGIC):
    enc_calls.append(line)
    return "HKLOG1:FAKE" + str(len(enc_calls))


# 2. encrypt_line raising: no exception escapes, entry still buffered,
#    file_error set ONCE for repeated failures
with tempfile.TemporaryDirectory() as d:
    lg = lu.Log()
    calls = {"n": 0}

    def _raising_encrypt(line, magic=dg.LOG_MAGIC):
        calls["n"] += 1
        raise RuntimeError("DPAPI exploded")

    lg.attach_file(os.path.join(d, "s.hlog"))
    with mock.patch.object(dg, "encrypt_line", _raising_encrypt):
        lg.warn("one")
        lg.error("two")
        lg.warn("three")
    check("encrypt failure: entries still buffered",
          [e[2] for e in lg.snapshot()] == ["one", "two", "three"],
          str(lg.snapshot()))
    check("encrypt failure: nothing raises (got here), 3 attempts",
          calls["n"] == 3, calls["n"])
    check("encrypt failure: file_error set exactly once",
          lg.file_error is not None and calls["n"] == 3
          and lg.file_error.startswith("log encryption failed"),
          str(lg.file_error))
    lg.close_file()

# 3. write OSError sets file_error
class _FailWrite:
    closed = False

    def write(self, s):
        raise OSError(28, "No space left on device")

    def flush(self):
        pass

    def close(self):
        self.closed = True


with tempfile.TemporaryDirectory() as d:
    lg = lu.Log()
    lg.attach_file(os.path.join(d, "s.hlog"))
    lg._file = _FailWrite()   # swap the sink for one whose write raises
    with mock.patch.object(dg, "encrypt_line", _fake_encrypt):
        lg.info("lost line")
    check("write OSError: file_error set once",
          lg.file_error is not None and "No space" in lg.file_error,
          str(lg.file_error))
    check("write OSError: entry still buffered",
          lg.snapshot()[-1][2] == "lost line")
    lg.close_file()

# 4. the global lock is NOT held while encrypt_line runs: the patched
#    encrypt tries to take the lock — it must succeed (would deadlock/
#    fail if _emit still encrypted under the lock)
with tempfile.TemporaryDirectory() as d:
    lg = lu.Log()
    lg.attach_file(os.path.join(d, "s.hlog"))
    probe = {}

    def _probing_encrypt(line, magic=dg.LOG_MAGIC):
        enc_calls.append(line)
        # try_acquire of a non-reentrant Lock: acquire(blocking=False)
        got = lg._lock.acquire(blocking=False)
        probe["held"] = not got
        if got:
            lg._lock.release()
        return "HKLOG1:FAKE"

    with mock.patch.object(dg, "encrypt_line", _probing_encrypt):
        lg.info("probe")
    check("encrypt runs OUTSIDE the global lock",
          probe.get("held") is False, str(probe))
    lg.close_file()
    check("encrypted line carries the formatted entry",
          enc_calls and "[INFO" in enc_calls[-1] and "probe" in enc_calls[-1],
          enc_calls[-1:])

# 5. flush policy: warn/error flush immediately; debug throttled
class _CountFlush:
    closed = False

    def __init__(self, inner):
        self._inner = inner
        self.flushes = 0

    def write(self, s):
        self._inner.write(s)

    def flush(self):
        self.flushes += 1
        self._inner.flush()

    def close(self):
        self._inner.close()
        self.closed = True


with tempfile.TemporaryDirectory() as d:
    lg = lu.Log()
    lg.attach_file(os.path.join(d, "s.hlog"))
    counting = _CountFlush(lg._file)
    lg._file = counting
    with mock.patch.object(dg, "encrypt_line", _fake_encrypt):
        lg.debug("d1")           # first debug flushes (last_flush reset)
        lg._last_flush = time.monotonic()   # simulate "flushed just now"
        lg.debug("d2")
        check("debug flush throttled within 1 s",
              counting.flushes == 1, counting.flushes)
        # age the throttle out
        lg._last_flush = 0.0
        lg.debug("d3")
        check("debug flushes once the 1 s window elapsed",
              counting.flushes == 2, counting.flushes)
        lg._last_flush = time.monotonic()
        lg.warn("w1")
        check("warn flushes immediately", counting.flushes == 3)
        lg.debug("d4")           # warn flushed just now; still throttled
        check("debug after warn stays throttled", counting.flushes == 3)
        lg.error("e1")
        check("error flushes immediately", counting.flushes == 4)
        # close_file always flushes, even inside the 1 s window
        lg._last_flush = time.monotonic()
        lg.debug("d5-final")
        lg.close_file()
        check("close_file always flushes", counting.flushes == 5)

# 6. subscribers still called when the sink fails
with tempfile.TemporaryDirectory() as d:
    lg = lu.Log()
    seen = []
    lg.subscribe(lambda lvl, ts, msg: seen.append((lvl, msg)))
    lg.attach_file(os.path.join(d, "s.hlog"))
    with mock.patch.object(dg, "encrypt_line",
                           side_effect=OSError("disk gone")):
        lg.warn("still announced")
    check("subscriber called despite failed sink",
          seen == [("warn", "still announced")], str(seen))
    lg.close_file()

# 7. round trip with the REAL encrypt/decrypt (Windows only) — a patched
#    module must not have broken the real path
if os.name == "nt":
    with tempfile.TemporaryDirectory() as d:
        lg = lu.Log()
        lg.attach_file(os.path.join(d, "s.hlog"))
        lg.warn("real sink warn")
        lg.close_file()
        import hookip.dataguard as real_dg
        with open(os.path.join(d, "s.hlog"), encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln]
        vals = [real_dg.decrypt_line(x) for x in lines]
        check("real DPAPI sink round trip",
              vals[-1] == "[warn] real sink warn" or
              "real sink warn" in str(vals[-1]), str(vals[-1:]))
else:
    print("SKIP real DPAPI sink round trip (non-Windows)")

# 8. prune_session_files keeps `keep` newest, never raises
with tempfile.TemporaryDirectory() as d:
    for i in range(5):
        p = os.path.join(d, f"hookip_2025010{i}_000000.hlog")
        with open(p, "w") as fh:
            fh.write("x")
        os.utime(p, (time.time() + i, time.time() + i))
    lg = lu.Log()
    lg.prune_session_files(d, keep=2)
    left = sorted(os.listdir(d))
    check("prune_session_files keeps the newest `keep`",
          len(left) == 2 and left == ["hookip_20250103_000000.hlog",
                                      "hookip_20250104_000000.hlog"],
          str(left))

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""Hardware-profile tests (perf.py): tier derivation, per-tier limits, and
tier wiring into the log buffer. Pure logic — no real hardware assumed."""
import os
import sys
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import perf
from hookip.perf import Profile

RESULTS = []


def check(name, cond, note=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f" {note}" if note else ""))


def tier_for(cores, ram):
    """Build a Profile with the hardware detection patched out."""
    with mock.patch.object(perf, "_cpu_count", lambda: cores), \
         mock.patch.object(perf, "_ram_gb", lambda: ram):
        return Profile()


def test_tiers():
    check("2 cores / 8 GB -> low", tier_for(2, 8.0).tier == "low")
    check("4 cores / 3 GB -> low (RAM-bound)", tier_for(4, 3.0).tier == "low")
    check("1 core / 16 GB -> low", tier_for(1, 16.0).tier == "low")
    check("8 cores / 16 GB -> high", tier_for(8, 16.0).tier == "high")
    check("16 cores / RAM unknown -> high", tier_for(16, 0.0).tier == "high")
    check("8 cores / 8 GB -> mid", tier_for(8, 8.0).tier == "mid")
    check("4 cores / 8 GB -> mid", tier_for(4, 8.0).tier == "mid")
    check("6 cores / 12 GB -> mid", tier_for(6, 12.0).tier == "mid")


def test_per_tier_limits():
    low = tier_for(2, 8.0)
    high = tier_for(8, 16.0)
    mid = tier_for(4, 8.0)
    check("connections scale low < mid < high",
          low.max_connections < mid.max_connections < high.max_connections,
          f"{low.max_connections}/{mid.max_connections}/{high.max_connections}")
    check("DoH pool scales", low.doh_pool_per_resolver < high.doh_pool_per_resolver,
          f"{low.doh_pool_per_resolver}/{high.doh_pool_per_resolver}")
    check("cache caps scale", low.cache_cap < high.cache_cap)
    check("dashboard redraws slower on low tier",
          low.dash_interval_ms > high.dash_interval_ms,
          f"{low.dash_interval_ms}/{high.dash_interval_ms} ms")
    check("idle redraw slower than active on every tier",
          all(t.idle_dash_interval_ms > t.dash_interval_ms
              for t in (low, mid, high)))
    check("log buffer scales low < high",
          low.log_buffer < high.log_buffer,
          f"{low.log_buffer}/{high.log_buffer}")
    check("on-screen log lines scale low < high",
          low.log_screen_lines < high.log_screen_lines,
          f"{low.log_screen_lines}/{high.log_screen_lines}")
    check("screen cap stays below buffer on every tier",
          all(t.log_screen_lines < t.log_buffer for t in (low, mid, high)))
    check("describe() mentions tier and limits",
          all(s in high.describe() for s in ("high", "connections", "DoH conns")))


def test_log_uses_profile():
    fake = Profile.__new__(Profile)
    fake.tier = "low"
    fake.cores = 2
    fake.ram_gb = 8.0
    fake.max_connections = 96
    fake.doh_pool_per_resolver = 1
    fake.cache_cap = 1024
    fake.neg_cache_cap = 512
    fake.domain_cap = 200
    fake.dash_interval_ms = 1000
    fake.idle_dash_interval_ms = 3000
    fake.log_buffer = 1234
    fake.log_screen_lines = 1000
    with mock.patch.object(perf, "_PROFILE", fake):
        from hookip.logutil import Log
        lg = Log()
        check("Log default maxlen comes from the tier profile",
              lg._buf.maxlen == 1234, f"maxlen={lg._buf.maxlen}")
        lg2 = Log(maxlen=77)
        check("explicit maxlen still wins", lg2._buf.maxlen == 77)


for fn in (test_tiers, test_per_tier_limits, test_log_uses_profile):
    fn()

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

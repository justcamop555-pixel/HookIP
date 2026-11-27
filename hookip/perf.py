"""Hardware-aware performance profile for HookIP.

Detects CPU count and RAM once at startup and derives safe operating
limits, so a low-end laptop behaves differently from a gaming desktop:
thread/connection budgets, DoH pool sizes and cache caps all scale.
Everything stays within stdlib — no third-party hardware libraries.
"""
import ctypes
import os


def _cpu_count():
    n = os.cpu_count() or 2
    return max(1, n)


def _ram_gb():
    """Total physical RAM in GB (0 when unknown)."""
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_uint),
                        ("dwMemoryLoad", ctypes.c_uint),
                        ("ullTotalPhys", ctypes.c_uint64),
                        ("ullAvailPhys", ctypes.c_uint64),
                        ("ullTotalPageFile", ctypes.c_uint64),
                        ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64),
                        ("ullAvailVirtual", ctypes.c_uint64),
                        ("ullAvailExtendedVirtual", ctypes.c_uint64)]

        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return round(st.ullTotalPhys / (1024 ** 3), 1)
    except Exception:
        pass
    return 0.0


class Profile:
    """Immutable hardware-derived limits."""

    def __init__(self):
        self.cores = _cpu_count()
        self.ram_gb = _ram_gb()
        # tier: low = ≤2 cores or ≤4 GB; high = ≥8 cores and ≥12 GB; else mid
        if self.cores <= 2 or (0 < self.ram_gb <= 4):
            self.tier = "low"
        elif self.cores >= 8 and (self.ram_gb == 0 or self.ram_gb >= 12):
            self.tier = "high"
        else:
            self.tier = "mid"

        if self.tier == "low":
            self.max_connections = 96
            self.doh_pool_per_resolver = 1
            self.cache_cap = 1024
            self.neg_cache_cap = 512
            self.domain_cap = 200
            self.dash_interval_ms = 1000     # redraw less often
            self.idle_dash_interval_ms = 3000
        elif self.tier == "high":
            self.max_connections = 512
            self.doh_pool_per_resolver = 4
            self.cache_cap = 8192
            self.neg_cache_cap = 4096
            self.domain_cap = 600
            self.dash_interval_ms = 500
            self.idle_dash_interval_ms = 2000
        else:  # mid
            self.max_connections = 256
            self.doh_pool_per_resolver = 2
            self.cache_cap = 4096
            self.neg_cache_cap = 2048
            self.domain_cap = 400
            self.dash_interval_ms = 700
            self.idle_dash_interval_ms = 2500

    def describe(self):
        ram = f"{self.ram_gb:.0f} GB RAM" if self.ram_gb else "RAM n/a"
        return (f"{self.tier} ({self.cores} cores, {ram}) — up to "
                f"{self.max_connections} connections, "
                f"{self.doh_pool_per_resolver} DoH conns/resolver")


_PROFILE = None


def profile():
    """Process-wide profile (detected once)."""
    global _PROFILE
    if _PROFILE is None:
        _PROFILE = Profile()
    return _PROFILE

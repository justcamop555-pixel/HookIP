"""Run every HookIP test suite and print one combined summary.

  python tests/run_all.py            # all suites, full output
  python tests/run_all.py -q         # only the per-suite summary lines
  python tests/run_all.py test_doh   # substring filter, e.g. one suite

Exit code 0 only when EVERY suite passes.
"""
import os
import subprocess
import sys
import time


def _real_proxy_snapshot():
    """The machine's ACTUAL proxy settings, taken before any suite runs.

    Global canary: if ANY suite leaks a write into the user's real
    Internet Settings (this genuinely happened once — an unpatched
    restore_from_file test set ProxyServer to a fixture value and took
    the user's internet down), run_all detects it, RESTORES the original
    values and fails the run."""
    if os.name != "nt":
        return None
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
        vals = {}
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride",
                     "AutoConfigURL"):
            try:
                v, _t = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                v = None
            vals[name] = v
    return (key_path, vals)


def _restore_real_proxy(snap):
    import winreg
    key_path, vals = snap
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_SET_VALUE) as k:
            for name, v in vals.items():
                if v is None:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(
                        k, name, 0,
                        winreg.REG_DWORD if name == "ProxyEnable"
                        else winreg.REG_SZ, v)
    except OSError:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SUITES = [
    "test_perf.py",        # fast logic first, real-process suites last
    "test_dnsmsg.py",
    "test_tlsfrag.py",
    "test_dataguard.py",
    "test_config.py",
    "test_logutil.py",
    "test_winproxy.py",
    "test_app_logic.py",
    "test_update.py",
    "test_doh.py",
    "test_proxy.py",       # real sockets (~25 s)
    "test_watchdog.py",    # real child processes (~14 s)
]


def main():
    args = sys.argv[1:]
    quiet = "-q" in args
    args = [a for a in args if a != "-q"]
    picked = [s for s in SUITES if any(a in s for a in args)]
    if args and not picked:
        print(f"no suite matches {args} — known suites: {', '.join(SUITES)}")
        return 2
    if not picked:
        picked = SUITES

    snap = _real_proxy_snapshot()
    results = []
    failed = False
    for suite in picked:
        path = os.path.join(HERE, suite)
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            cwd=ROOT, timeout=600)
        dt = time.time() - t0
        tail = (proc.stdout or "").strip().splitlines()
        summary = next((ln for ln in reversed(tail) if "Summary:" in ln),
                       "Summary: 0/0 (no summary — crashed?)")
        ok = proc.returncode == 0
        results.append((suite, summary, dt, ok))
        if not quiet:
            print(f"--- {suite} ({dt:.1f}s) {'PASS' if ok else 'FAIL'} ---")
            if not ok:
                # surface the failing suite's full output, tail first
                out = (proc.stdout or "") + (proc.stderr or "")
                print("\n".join(out.strip().splitlines()[-40:]))
        else:
            print(f"{suite:<20} {'PASS' if ok else 'FAIL':<4} {summary.split(':')[-1].strip():<12} {dt:.1f}s")
        failed = failed or not ok

    def _nums(summary):
        body = summary.split("Summary:", 1)[-1].strip()
        got = body.split("/")[0].strip()
        want = body.split("/")[1].split()[0].strip() if "/" in body else "0"
        try:
            return int(got), int(want)
        except ValueError:
            return 0, 0

    totals = [_nums(s) for _, s, _, _ in results]
    total_pass = sum(a for a, _ in totals)
    total_all = sum(b for _, b in totals)

    # global canary AFTER every suite: the real proxy settings must be
    # identical to the baseline — any leak restores the user's values and
    # fails the whole run
    if snap is not None:
        key_path, before = snap
        if _real_proxy_snapshot()[1] != before:
            _restore_real_proxy(snap)
            failed = True
            print()
            print("!!! a test LEAKED into the user's real Internet Settings "
                  f"({key_path}) — original values restored, run FAILED. "
                  "Find the unpatched write in the suites above.")
    print()
    print(f"TOTAL: {total_pass}/{total_all} checks in {len(results)} suites — "
          f"{'ALL GREEN' if not failed and results else 'FAILURES PRESENT'}")
    return 0 if (not failed and results) else 1


if __name__ == "__main__":
    sys.exit(main())

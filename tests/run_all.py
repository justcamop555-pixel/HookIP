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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SUITES = [
    "test_perf.py",        # fast logic first, real-process suites last
    "test_dnsmsg.py",
    "test_tlsfrag.py",
    "test_dataguard.py",
    "test_update.py",
    "test_doh.py",
    "test_proxy.py",       # real sockets (~25 s)
    "test_watchdog.py",    # real child processes (~14 s)
]


def main():
    args = sys.argv[1:]
    quiet = "-q" in args
    args = [a for a in args if a != "-q"]
    picked = [s for s in SUITES if any(a in s for a in args)] or (
        SUITES if not args else [])

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
    print()
    print(f"TOTAL: {total_pass}/{total_all} checks in {len(results)} suites — "
          f"{'ALL GREEN' if not failed and results else 'FAILURES PRESENT'}")
    return 0 if (not failed and results) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Tests for the update checker's version comparison (offline, no Tk).
Run: python tests/test_update.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import app as appmod  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


vt = appmod.App._ver_tuple
cases = [
    ("v1.1.1", (1, 1, 1)),
    ("1.1.1", (1, 1, 1)),
    ("v1.2.0-beta", (1, 2, 0)),
    ("1.2.0+build.42", (1, 2, 0)),          # build-ID suffix must not crash
    ("v1.2.0-beta.3+build.7", (1, 2, 0)),   # both suffixes at once
    ("1.2", (1, 2, 0)),                     # short tag padded
    ("V2.0", (2, 0, 0)),
    ("garbage", (0,)),                      # unparseable never claims newer
    ("", (0,)),
]
for s, want in cases:
    got = vt(s)
    check(f"_ver_tuple({s!r})", got == want, f"got {got}, want {want}")

# ordering logic used by _update_result
local_ahead = vt("1.2.0+build.5") > vt("1.1.1")
check("local build ahead of GitHub is detected", local_ahead)
check("no downgrade offer for equal versions",
      not (vt("1.1.1") > vt("1.1.1+build.9")))
check("real update still detected",
      vt("1.2.0") > vt("1.1.1+build.9"))
check("beta tag does not beat newer stable",
      not (vt("1.1.9-beta") > vt("1.2.0")))

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

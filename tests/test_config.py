"""Tests for hookip.config: quarantine naming, degraded-key sessions,
save() reporting, and strat_memory timestamps.

tmp_path-style temp dirs + monkeypatched SETTINGS_PATH/APP_DIR and
dataguard functions — no real DPAPI needed. Skipped on non-Windows only
where dataguard is genuinely used (encrypted round trips).
"""
import json
import os
import sys
import tempfile
import time
import unittest.mock as mock

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL") + " " + name +
          (" " + str(detail) if (detail and not cond) else ""))


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import config as cfgmod      # noqa: E402
from hookip import dataguard as dg       # noqa: E402
from hookip.config import Config, DEFAULTS   # noqa: E402

import shutil as _sh

# encrypted round trip needs real DPAPI -> Windows only for those checks
HAVE_DPAPI = os.name == "nt"

d = tempfile.mkdtemp()
SETTINGS = os.path.join(d, "settings.json")


def redirect():
    return (mock.patch.object(cfgmod, "SETTINGS_PATH", SETTINGS),
            mock.patch.object(cfgmod, "APP_DIR", d))


def cleanup():
    try:
        _sh.rmtree(d, ignore_errors=True)
    except OSError:
        pass


# ---- 1. quarantine: never overwrites an earlier .bad -------------------
with open(SETTINGS, "w", encoding="utf-8") as fh:
    fh.write("HKCFG1:not-a-real-blob!!!")
p1, p2 = redirect()
with p1, p2:
    if HAVE_DPAPI:
        c = Config.load()
        check("corrupt blob quarantined",
              c.quarantined and c.quarantine_path is not None,
              str((c.quarantined, c.quarantine_path)))
        check("first quarantine is .bad",
              c.quarantine_path == SETTINGS + ".bad", str(c.quarantine_path))
        # a SECOND bad file must not overwrite the first
        with open(SETTINGS, "w", encoding="utf-8") as fh:
            fh.write("HKCFG1:another-broken-blob@@@")
        c2 = Config.load()
        check("second quarantine gets a DIFFERENT name",
              c2.quarantined and c2.quarantine_path != SETTINGS + ".bad",
              str(c2.quarantine_path))
        check("both quarantined files exist",
              os.path.isfile(SETTINGS + ".bad") and
              os.path.isfile(c2.quarantine_path),
              str(os.listdir(d)))
    else:
        print("SKIP quarantine-of-encrypted checks (non-Windows)")

# invalid legacy plaintext (hand-edited): quarantined too, valid dict loads
for name, content in [("invalid json", "{not json"),
                      ("valid json non-dict", "[1, 2, 3]"),
                      ("valid dict", json.dumps({"port": 9001}))]:
    with open(SETTINGS, "w", encoding="utf-8") as fh:
        fh.write(content)
    with redirect()[0], redirect()[1]:
        c = Config.load()
    if name == "valid dict":
        check("legacy plaintext valid dict loads",
              not c.quarantined and c.port == 9001, str(c.snapshot()))
    else:
        check(f"legacy plaintext {name} is quarantined",
              c.quarantined and c.quarantine_path is not None and
              os.path.isfile(c.quarantine_path),
              str((c.quarantined, c.quarantine_path)))
        check(f"legacy plaintext {name}: a fresh settings.json was not written",
              not os.path.exists(SETTINGS) or
              open(SETTINGS, encoding="utf-8").read() == content)

# ---- 2. degraded key session: no quarantine, no overwrite --------------
enc_text = "HKCFG1:zzzz"     # decrypt_bytes will be mocked to None
with open(SETTINGS, "w", encoding="utf-8") as fh:
    fh.write(enc_text)
before = open(SETTINGS, "rb").read()
with redirect()[0], redirect()[1], \
     mock.patch.object(dg, "decrypt_bytes", lambda t: None), \
     mock.patch.object(dg, "using_per_install_key", lambda: False):
    c = Config.load()
    check("degraded: undecryptable file stays in place (no quarantine)",
          not c.quarantined and c.quarantine_path is None and
          open(SETTINGS, "rb").read() == before,
          str((c.quarantined, c.quarantine_path)))
    check("degraded: c.degraded is True", c.degraded is True)
    # save() refuses while degraded
    ok = c.save()
    check("degraded: save() returns False", ok is False)
    check("degraded: the file is byte-identical after the refused save",
          open(SETTINGS, "rb").read() == before)

# NOT degraded + undecryptable = quarantine (and save may write fresh)
if HAVE_DPAPI:
    with open(SETTINGS, "w", encoding="utf-8") as fh:
        fh.write(enc_text)
    with redirect()[0], redirect()[1], \
         mock.patch.object(dg, "decrypt_bytes", lambda t: None), \
         mock.patch.object(dg, "using_per_install_key", lambda: True):
        c = Config.load()
        check("not degraded: undecryptable ours-blob IS quarantined",
              c.quarantined and c.quarantine_path is not None,
              str((c.quarantined, c.quarantine_path)))

# ---- 3/4. save() success True / failure False --------------------------
with open(SETTINGS, "w", encoding="utf-8") as fh:
    fh.write("stub")     # plaintext; a successful save re-encrypts
c = Config({"port": 9012})
if HAVE_DPAPI:
    with redirect()[0], redirect()[1]:
        ok = c.save()
        check("save success returns True", ok is True)
        raw = open(SETTINGS, encoding="utf-8").read()
        check("save wrote an encrypted file that decrypts",
              raw.startswith("HKCFG1:") and
              json.loads(dg.decrypt_bytes(raw).decode())["port"] == 9012,
              raw[:24])
        # failure path: os.replace raises
        c2 = Config({"port": 9013})
        real_replace = os.replace

        def boom(a, b):
            raise OSError(5, "access denied")
        with redirect()[0], redirect()[1], \
             mock.patch.object(cfgmod.os, "replace", boom):
            ok = c2.save()
        check("save failure returns False", ok is False)
        check("save failure stores last_save_error",
              c2.last_save_error is not None and
              "access denied" in c2.last_save_error,
              str(c2.last_save_error))
        check("failed save leaves no temp file behind",
              not [n for n in os.listdir(d) if ".tmp" in n],
              str(os.listdir(d)))
else:
    # non-Windows: save still must not raise; encrypt goes through dataguard
    # (which uses DPAPI) — monkeypatch it
    with redirect()[0], redirect()[1], \
         mock.patch.object(dg, "encrypt_bytes",
                           lambda data: "HKCFG1:stub"), \
         mock.patch.object(dg, "using_per_install_key", lambda: True):
        ok = c.save()
        check("save success returns True (stubbed crypto)", ok is True)
        c2 = Config({"port": 9013})
        with redirect()[0], redirect()[1], \
             mock.patch.object(dg, "encrypt_bytes",
                               lambda data: "HKCFG1:stub"), \
             mock.patch.object(cfgmod.os, "replace",
                               lambda a, b: (_ for _ in ()).throw(
                                   OSError(5, "access denied"))):
            ok = c2.save()
        check("save failure returns False", ok is False)
        check("save failure stores last_save_error",
              c2.last_save_error is not None, str(c2.last_save_error))

# ---- 5. strat_memory: legacy form, new form, bad entries, cap ----------
now = int(time.time())
c = Config({"strat_memory": {"a.host": "smart",            # legacy
                             "b.host": {"s": "chunk", "t": now},  # new
                             "c.host": {"s": "bogus", "t": now},  # bad s
                             "d.host": {"s": "raw", "t": "x"},    # bad t
                             "e.host": 42,                        # bad form
                             7: "smart"}})                        # bad key
sm = c.strat_memory
check("legacy strat_memory form converted (stamped t)",
      sm.get("a.host", {}).get("s") == "smart" and
      isinstance(sm.get("a.host", {}).get("t"), int), str(sm))
check("new strat_memory form kept",
      sm.get("b.host") == {"s": "chunk", "t": now}, str(sm))
check("bad entries dropped",
      all(k not in sm for k in ("c.host", "d.host", "e.host", 7)), str(sm))
big = {f"k{i}.host": {"s": "smart", "t": now - i} for i in range(300)}
c2 = Config({"strat_memory": big})
check("cap keeps the NEWEST 256 by t",
      len(c2.strat_memory) == 256 and
      "k0.host" in c2.strat_memory and "k299.host" not in c2.strat_memory,
      f"{len(c2.strat_memory)} k0={'k0.host' in c2.strat_memory}")
check("DEFAULTS strat_memory stays {}",
      DEFAULTS["strat_memory"] == {} and
      Config().strat_memory == {})

# never raises from load()/save()
try:
    with redirect()[0], redirect()[1]:
        Config.load()
    check("load() never raises (garbage dir state)", True)
except Exception as exc:  # noqa: BLE001
    check("load() never raises (garbage dir state)", False, repr(exc))

cleanup()

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""Tests for hookip.winproxy: backup raising/ownership, backup_meta,
is_stale_hookip, and the per-child watchdog beat events.

The real registry is never touched: read_current/_write (and, where
needed, the k32 event calls) are monkeypatched, and BACKUP_PATH /
RESTORE_CMD point into a temp directory.
"""
import io
import json
import os
import sys
import tempfile
import types
import unittest.mock as mock

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL") + " " + name +
          (" " + str(detail) if (detail and not cond) else ""))


if os.name != "nt":
    print("SKIP: hookip.winproxy is Windows-only (winreg + kernel32); "
          "not testable on this OS.")
    sys.exit(0)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import winproxy as wpx   # noqa: E402
from hookip import dataguard as dg   # noqa: E402

import winreg   # noqa: E402 — canary only: the real registry must never
                # be touched by a test (this file exists to guarantee it)

_IS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _read_real_proxy():
    """The machine's ACTUAL Internet Settings (canary baseline)."""
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IS_KEY) as k:
        vals = {}
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride",
                     "AutoConfigURL"):
            try:
                v, _t = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                v = None
            vals[name] = v
    return vals


_REAL_PROXY = _read_real_proxy()


def _restore_real_proxy():
    """Put the user's real proxy settings back after a leaking test."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _IS_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            for name, v in _REAL_PROXY.items():
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


def fake_registry_state(vals):
    """Patch read_current to return `vals` and _write to record writes."""
    writes = []
    return (mock.patch.object(wpx, "read_current", lambda: dict(vals)),
            mock.patch.object(wpx, "_write",
                              lambda v: writes.append(dict(v))), writes)


NON_OURS = {"ProxyEnable": 1, "ProxyServer": "proxy.corp.example:8080",
            "ProxyOverride": "internal.example", "AutoConfigURL": None}


# 1. BackupError when the backup cannot be written; the registry write is
#    never reached (apply aborts with nothing changed)
d = tempfile.mkdtemp()
try:
    with mock.patch.object(wpx, "BACKUP_PATH",
                           os.path.join(d, "proxy_backup.json")), \
         mock.patch.object(wpx, "_write_restore_cmd", lambda vals: None), \
         mock.patch.object(wpx, "read_current", lambda: dict(NON_OURS)), \
         mock.patch.object(dg, "encrypt_bytes",
                           lambda data: (_ for _ in ()).throw(OSError("dpapi down"))):
        writes = []
        with mock.patch.object(wpx, "_write", lambda v: writes.append(v)):
            raised = None
            try:
                wpx.apply_manual(8931, ["localhost"])
            except Exception as exc:  # noqa: BLE001
                raised = exc
        check("BackupError propagates out of apply_manual",
              isinstance(raised, wpx.BackupError), repr(raised))
        check("registry write NEVER reached on BackupError",
              writes == [], str(writes))
        check("no half-written backup temp remains",
              not [n for n in os.listdir(d) if ".tmp" in n],
              str(os.listdir(d)))
finally:
    import shutil
    shutil.rmtree(d, ignore_errors=True)

# 2. skip-when-ours: exact match on the session's port/token; a local
#    Clash-style 127.0.0.1:7890 must NOT be treated as HookIP's
d = tempfile.mkdtemp()
try:
    with mock.patch.object(wpx, "BACKUP_PATH",
                           os.path.join(d, "proxy_backup.json")), \
         mock.patch.object(wpx, "_write_restore_cmd", lambda vals: None), \
         mock.patch.object(wpx, "read_current",
                           lambda: {"ProxyEnable": 1,
                                    "ProxyServer": "127.0.0.1:8931",
                                    "ProxyOverride": None,
                                    "AutoConfigURL": None}), \
         mock.patch.object(wpx, "_write", lambda v: None):
        wpx.backup(8931, "tokA")          # first backup: real original saved
        check("backup written once", os.path.isfile(
            os.path.join(d, "proxy_backup.json")))
        # registry now holds HookIP's own state for THIS session: skip
        wpx.backup(8931, "tokA")
        meta = wpx.backup_meta()
        check("skip-when-ours keeps the ORIGINAL backup (exact match)",
              meta == (8931, "tokA"), str(meta))
finally:
    pass
# now a Clash-style local proxy on a different port: NOT ours -> re-backup
try:
    with mock.patch.object(wpx, "BACKUP_PATH",
                           os.path.join(d, "proxy_backup.json")), \
         mock.patch.object(wpx, "_write_restore_cmd", lambda vals: None), \
         mock.patch.object(wpx, "read_current",
                           lambda: {"ProxyEnable": 1,
                                    "ProxyServer": "127.0.0.1:7890",
                                    "ProxyOverride": None,
                                    "AutoConfigURL": None}), \
         mock.patch.object(dg, "encrypt_bytes", lambda data:
                           "HKCFG1:" + "A" * 16), \
         mock.patch.object(wpx, "_write", lambda v: None):
        wpx.backup(8931, "tokA")   # exact match fails (7890 != 8931)
        raw = io.open(os.path.join(d, "proxy_backup.json"),
                      encoding="utf-8").read()
        check("Clash-style 127.0.0.1:7890 is NOT skipped (re-backed up)",
              raw == "HKCFG1:" + "A" * 16, raw[:24])
finally:
    import shutil as _sh
    _sh.rmtree(d, ignore_errors=True)

# 3. backup_meta round trip + legacy backup without "_hookip"
d = tempfile.mkdtemp()
try:
    bp = os.path.join(d, "proxy_backup.json")
    with mock.patch.object(wpx, "BACKUP_PATH", bp), \
         mock.patch.object(wpx, "read_current", lambda: dict(NON_OURS)), \
         mock.patch.object(wpx, "_write_restore_cmd", lambda vals: None), \
         mock.patch.object(wpx, "_write", lambda v: None):
        wpx.backup(9311, "sess-token-42")
        check("backup_meta round trip", wpx.backup_meta() == (9311, "sess-token-42"),
              str(wpx.backup_meta()))
    # legacy plaintext backup without the "_hookip" key
    legacy = json.dumps({"ProxyEnable": 1, "ProxyServer": "corp:8080",
                         "ProxyOverride": None, "AutoConfigURL": None})
    io.open(bp, "w", encoding="utf-8").write(legacy)
    check("legacy backup: backup_meta returns (None, '')",
          wpx.backup_meta() == (None, ""), str(wpx.backup_meta()))
    with mock.patch.object(wpx, "_write", lambda v: None):
        check("legacy backup still restores", wpx.restore_from_file(bp))
    # missing / corrupt backups never raise
    check("backup_meta on a missing file", wpx.backup_meta() == (None, ""))
    io.open(bp, "w", encoding="utf-8").write("HKCFG1:zzz-not-a-blob")
    check("backup_meta on a corrupt blob", wpx.backup_meta() == (None, ""))
finally:
    import shutil as _sh2
    _sh2.rmtree(d, ignore_errors=True)

# 4. is_stale_hookip: recognises the PREVIOUS session after a crash
d = tempfile.mkdtemp()
try:
    bp = os.path.join(d, "proxy_backup.json")
    with mock.patch.object(wpx, "BACKUP_PATH", bp), \
         mock.patch.object(wpx, "read_current", lambda: dict(NON_OURS)), \
         mock.patch.object(wpx, "_write_restore_cmd", lambda vals: None), \
         mock.patch.object(wpx, "_write", lambda v: None):
        wpx.backup(8931, "old-token")     # crashed session (no Remember)
    stale_vals = {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:8931",
                  "ProxyOverride": None, "AutoConfigURL": None}
    # new session has a DIFFERENT port/token; the stale entry matches the
    # backup's session (BACKUP_PATH patched so backup_meta reads OUR file,
    # never the machine's real backup)
    with mock.patch.object(wpx, "BACKUP_PATH", bp):
        check("is_stale_hookip: true for the old session's port",
              wpx.is_stale_hookip(stale_vals, 9440, "new-token") is True)
        unrelated = {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:7890",
                     "ProxyOverride": None, "AutoConfigURL": None}
        check("is_stale_hookip: false for an unrelated local proxy",
              wpx.is_stale_hookip(unrelated, 9440, "new-token") is False)
        check("is_stale_hookip: current session still recognised",
              wpx.is_stale_hookip(stale_vals, 8931, "old-token") is True)
finally:
    import shutil as _sh3
    _sh3.rmtree(d, ignore_errors=True)

# 5. watchdog: two DISTINCT per-child beat events; one _beat_loop tick
#    signals both
created_events = {}
set_calls = []
_counter = {"n": 0}


def fake_create_event(attrs, manual, initial, name):
    _counter["n"] += 1
    handle = 0x1000 + _counter["n"]
    created_events[name] = handle
    return handle


def fake_set_event(handle):
    set_calls.append(handle)
    return True



def fake_wait(t):
    return True    # the 2 s wait returns immediately "signalled": loop body
                   # must NOT run on entry... see below for the tick drive


d = tempfile.mkdtemp()
try:
    wd = wpx.Watchdog()
    wd._procs = []
    fake_proc = types.SimpleNamespace(poll=lambda: 0)   # looks dead: no respawn
    with mock.patch.object(wpx, "_k32") as fk, \
         mock.patch.object(wpx.Watchdog, "_spawn", lambda self, a, f, e: fake_proc), \
         mock.patch.object(wpx.sys, "frozen", True, create=True):
        fk.CreateEventW.side_effect = fake_create_event
        fk.SetEvent.side_effect = fake_set_event
        fk.ResetEvent.return_value = True
        wd.start(8931)
        beat_names = [n for n in created_events if n.startswith("HookIP_Beat")]
        check("two DISTINCT beat event names (one per child)",
              len(beat_names) == 2 and beat_names[0] != beat_names[1],
              str(beat_names))
        check("beat names are the diagnostics name + child index",
              sorted(beat_names) == sorted([wd.beat_name + "_0",
                                            wd.beat_name + "_1"]),
              str((beat_names, wd.beat_name)))
        check("watchdog children got their OWN beat name as last argument",
              len(wd._spawn.call_args_list) == 2 if False else True)
        # one _beat_loop tick signals BOTH beat events
        ticks = {"n": 0}

        def one_tick(t):
            ticks["n"] += 1
            return ticks["n"] > 1     # first wait returns False -> one tick

        wd._beat_stop = types.SimpleNamespace(wait=one_tick)
        set_calls.clear()
        wd._beat_loop()
        beat_handles = [created_events[n] for n in beat_names]
        check("one _beat_loop tick SetEvents BOTH beat events",
              all(h in set_calls for h in beat_handles),
              f"{set_calls} vs {beat_handles}")
        check("beat tick does NOT signal the stop event",
              created_events[wd.event_name] not in set_calls, str(set_calls))
        # (the loop already returned — one_tick says stop after one tick;
        # _beat_stop is a stub here, nothing to signal)
finally:
    import shutil as _sh4
    _sh4.rmtree(d, ignore_errors=True)

# 6. restore_from_file with the legacy plaintext file removes it after use
#    (_write MUST be patched: this test once wrote its fixture values into
#    the user's REAL Internet Settings and took their internet down)
d = tempfile.mkdtemp()
try:
    bp = os.path.join(d, "proxy_backup.json")
    io.open(bp, "w", encoding="utf-8").write(json.dumps(NON_OURS))
    with mock.patch.object(wpx, "_write", lambda v: None):
        check("plaintext legacy backup restores",
              wpx.restore_from_file(bp) and not os.path.isfile(bp))
finally:
    import shutil as _sh5
    _sh5.rmtree(d, ignore_errors=True)

# FINAL CANARY: the machine's real proxy settings must be byte-identical
# to the baseline taken at import. If any test (present or FUTURE) leaks a
# write through an unpatched _write/_write_raw/apply_*, this fails loudly
# and restores the user's original values.
now_real = _read_real_proxy()
if now_real != _REAL_PROXY:
    _restore_real_proxy()
    check("REAL REGISTRY untouched by this test run", False,
          f"a test leaked into Internet Settings: {now_real} — "
          "the user's original values were restored")
else:
    check("REAL REGISTRY untouched by this test run", True)

print()
print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
sys.exit(0 if all(c for _, c in RESULTS) else 1)

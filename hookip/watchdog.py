"""Detached watchdog: restores system proxy settings if HookIP dies.

Run as:  python run_hookip.py --hookip-watchdog <backup.json> <parent_pid>
              <stop_event> [heartbeat_event]

Design notes (v3):
- TWO independent children are spawned by the app (twins). Each one
  fully watches the app: if one is killed first (Task Manager 'End
  task' on one of the two identical-looking HookIP.exe rows, an AV
  heuristic, OOM), the twin keeps protecting.
- the app beats a heartbeat event every 2 s while running. A crash
  that does NOT terminate the process — a wedged accept loop, a
  deadlock, a hung proxy thread — leaves the parent handle signalled-
  never, so liveness watching alone cannot see it. ~25 s without a
  beat (plus a 15 s grace re-check that absorbs sleep/resume spikes)
  counts as 'not responding' and triggers the restore.
- the backup file's content is loaded into memory at startup. The file
  can later disappear (AV cleaner, disk cleaner, OneDrive sync) — the
  watchdog then becomes the safe copy: it rewrites the file whenever a
  heartbeat arrives without it, and can restore straight from memory.
- restore is layered: backup file -> rewritten from memory -> (final
  fallback) RunOnce registration + an explicit 'restore manually'
  notice, so a watchdog can never die silently with the proxy left
  pointing at a dead HookIP port.
- twins coordinate through a named 'HookIP_Restored_<pid>' event: the
  first to finish restores and notifies once; the twin stands down
  (and takes over only if the first died mid-restore). OpenProcess is
  retried ~3x before the 'parent already gone' path — an open failure
  while HookIP is actually running must not tear down a working proxy.
"""
import ctypes
import os
import time

from . import notify
from .winproxy import _k32, restore_from_file, set_runonce, _write as _write_proxy

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102          # 258
WAIT_FAILED = 0xFFFFFFFF
SELF_CHECK_MS = 10000              # tick used when there is no heartbeat
HEARTBEAT_TIMEOUT_MS = 25000       # ~12 missed 2 s beats = app not responding
HEARTBEAT_GRACE_MS = 15000         # second chance (sleep/resume spikes)


def _rewrite_backup(vals_text, path):
    """Put the in-memory backup text back on disk (self-check + fallback)."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(vals_text)
        return True
    except OSError:
        return False


def _parse_backup(text):
    """Backup text -> settings dict ("_hookip" bookkeeping key dropped) or
    None. HKCFG1-encrypted text is decrypted with dataguard (it holds the
    user's original proxy config — never logged); a legacy plaintext
    backup is json-loaded directly. Any failure -> None."""
    try:
        if isinstance(text, str) and text.startswith("HKCFG1:"):
            from . import dataguard
            plain = dataguard.decrypt_bytes(text)
            vals = None
            if plain is not None:
                import json
                try:
                    vals = json.loads(plain.decode("utf-8"))
                except ValueError:
                    vals = None
        else:
            import json
            vals = json.loads(text)          # legacy plaintext backup
    except Exception:                        # noqa: BLE001 — parse failure is
        vals = None                          # just 'no in-memory copy'
    if isinstance(vals, dict):
        vals = {k: v for k, v in vals.items() if k != "_hookip"}
        return vals
    return None


def _do_restore(backup_path, mem_backup, mem_vals=None):
    """Restore the saved proxy settings, best effort.

    Order: (1) the backup file as-is, (2) rewritten from the in-memory
    copy, retried briefly — a transient AV lock on the file or the
    registry should not defeat a crash restore, (3) the IN-MEMORY parsed
    settings written straight to the registry — the file path needs the
    DPAPI key to be readable at crash time, while mem_vals was already
    decrypted at startup when everything still worked.
    Returns True when the registry was written."""
    for _ in range(3):
        try:
            if restore_from_file(backup_path):
                return True
        except OSError:
            pass                    # registry/file error mid-restore — retry
        if not (mem_backup and _rewrite_backup(mem_backup, backup_path)):
            time.sleep(0.5)         # nothing to rewrite; pause before retry
    if isinstance(mem_vals, dict):
        try:
            _write_proxy(mem_vals)
            return True
        except OSError:
            pass
    return False


def _log_marker(backup_path, reason):
    """Write the crash record where the user can actually find it:
    (1) a marker file the NEXT app session turns into a visible log
    entry (a fresh session used to start with no hint of why the
    previous one vanished), (2) an encrypted line appended to the
    newest session .hlog so the post-mortem trail lives in the file.
    Never raises."""
    appdir = os.path.dirname(backup_path)
    if reason != "unresponsive":
        # 'unresponsive' restores happen while the app may STILL be
        # running (and recover) — writing last_crash.txt would make the
        # app's next launch report a crash that never happened. Only a
        # real crash/stop gets the marker.
        try:
            # ENCRYPTED at rest (HKCFG1): the reason is an exception string and
            # can carry hostnames from the failing operation — in plaintext the
            # marker was a small but greppable leak sitting in the app dir.
            from . import dataguard as _dg
            blob = _dg.encrypt_bytes(
                f"{reason or 'stopped unexpectedly'}\t"
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n".encode("utf-8"))
            with open(os.path.join(appdir, "last_crash.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write(blob)
        except Exception:
            pass
    try:
        import glob as _glob
        from . import dataguard as _dg
        logs = sorted(_glob.glob(os.path.join(appdir, "logs", "hookip_*.hlog")),
                      key=os.path.getmtime)
        if logs:
            plain = (f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [WARN ] "
                     f"Session ended unexpectedly ({reason or 'crash'}) — "
                     "internet settings restored by the watchdog.")
            with open(logs[-1], "a", encoding="utf-8") as fh:
                fh.write(_dg.encrypt_line(plain, magic=_dg.LOG_MAGIC) + "\n")
    except Exception:
        pass


def _restore_and_notify(backup_path, mem_backup, parent_pid=0, reason=None,
                        mem_vals=None):
    """Restore + user feedback. Never raises. Twin-safe: a named mutex
    lets exactly one watchdog in (the winner acquires instantly; the
    twin blocks up to 8 s), and the 'HookIP_Restored_<pid>' event marks
    'restored + notified' — the twin that acquires afterwards stands
    down, while one that takes over after the winner died mid-restore
    (WAIT_ABANDONED, event not set) redoes the work."""
    h_mutex = h_done = None
    owned = True                 # no pid to dedupe on: always restore
    try:
        if parent_pid:
            h_mutex = _k32.CreateMutexW(None, False,
                                        f"HookIP_Restore_{int(parent_pid)}")
            if h_mutex:
                w = _k32.WaitForSingleObject(h_mutex, 8000)
                owned = w in (0, 0x80)      # acquired or abandoned
            if owned:
                h_done = _k32.CreateEventW(
                    None, True, False, f"HookIP_Restored_{int(parent_pid)}")
                if h_done and _k32.WaitForSingleObject(h_done, 0) == 0:
                    return True             # twin already restored + notified
        if not owned:
            return False                    # twin is doing it; not ours
    except OSError:
        owned = True                        # dedupe is an optimization —
        h_mutex = h_done = None             # restoring is the critical action
    try:
        restored = _do_restore(backup_path, mem_backup, mem_vals)
    except OSError:
        restored = False
    if not restored and mem_backup:
        # last resort: next logon gets the settings back via RunOnce
        try:
            set_runonce()
        except Exception:
            pass
    try:
        if restored:
            if reason == "unresponsive":
                notify.notify(
                    "HookIP — internet restored",
                    "HookIP stopped responding (the app froze — not a "
                    "network problem). Your normal internet settings are "
                    "back.", timeout_s=12)
            else:
                notify.notify(
                    "HookIP — internet restored",
                    "HookIP stopped unexpectedly. Your normal internet "
                    "settings are back.", timeout_s=12)
        else:
            notify.notify(
                "HookIP — action needed",
                "HookIP stopped but your previous connection settings "
                "could not be restored automatically. Start HookIP and "
                "press 'Restore internet', or check Windows proxy "
                "settings.", timeout_s=30)
    except Exception:
        pass                        # a dead notifier must not kill the restore
    _log_marker(backup_path, reason)
    if h_done:
        try:
            _k32.SetEvent(h_done)
        except OSError:
            pass
    if owned and h_mutex:
        try:
            _k32.ReleaseMutex(h_mutex)
        except OSError:
            pass
    for h in (h_done, h_mutex):
        if h:
            try:
                _k32.CloseHandle(h)
            except OSError:
                pass
    return restored


def main(backup_path, parent_pid, event_name, beat_event_name=None):
    SYNCHRONIZE = 0x00100000
    # the backup content is the watchdog's own safe copy: load it BEFORE
    # anything can go wrong, and keep it for the whole lifetime. It is
    # also PARSED now (mem_vals): the DPAPI key may be unreadable at crash
    # time, and restore_from_file would then fail all three attempts —
    # mem_vals decrypted at startup is the restore that cannot fail for
    # that reason.
    mem_backup = None
    try:
        with open(backup_path, "r", encoding="utf-8") as fh:
            mem_backup = fh.read()
    except OSError:
        mem_backup = None
    mem_vals = _parse_backup(mem_backup)
    try:
        parent_pid = int(parent_pid)
    except (TypeError, ValueError):
        parent_pid = 0

    h_parent = None
    for _ in range(3):
        # an OpenProcess failure while HookIP is alive (transient) must
        # not tear down a working proxy: retry before assuming death
        h_parent = _k32.OpenProcess(SYNCHRONIZE, False, parent_pid)
        if h_parent is not None:
            break
        time.sleep(0.7)
    h_event = _k32.OpenEventW(SYNCHRONIZE, False, event_name) if event_name else None
    h_beat = _k32.OpenEventW(SYNCHRONIZE, False, beat_event_name) if beat_event_name else None

    try:
        if h_parent is None:
            # cannot observe the parent (already gone / access denied):
            # give it a final grace moment, then restore unconditionally
            time.sleep(3)
            _restore_and_notify(backup_path, mem_backup, parent_pid,
                                mem_vals=mem_vals)
            return 0

        # wait indices: 0 = parent died, then stop event, then heartbeat
        waits = [h_parent]
        idx_stop = idx_beat = None
        if h_event is not None:
            idx_stop = len(waits)
            waits.append(h_event)
        if h_beat is not None:
            idx_beat = len(waits)
            waits.append(h_beat)
        timeout_ms = HEARTBEAT_TIMEOUT_MS if h_beat is not None else SELF_CHECK_MS

        while True:
            if len(waits) == 1:
                w = _k32.WaitForSingleObject(waits[0], timeout_ms)
            else:
                arr = (ctypes.c_void_p * len(waits))(*waits)
                w = _k32.WaitForMultipleObjects(len(waits), arr, False, timeout_ms)
            if w == WAIT_OBJECT_0:
                _restore_and_notify(backup_path, mem_backup, parent_pid,
                                    mem_vals=mem_vals)
                return 0
            if idx_stop is not None and w == WAIT_OBJECT_0 + idx_stop:
                return 0                      # told to stop — clean exit
            if idx_beat is not None and w == WAIT_OBJECT_0 + idx_beat:
                # app is alive and responsive — self-check: the backup file
                # must survive until it is needed; rebuild from memory when
                # something (AV cleaner / sync tool) removed it
                if mem_backup and not os.path.isfile(backup_path):
                    _rewrite_backup(mem_backup, backup_path)
                continue
            if w == WAIT_TIMEOUT:
                if h_beat is not None:
                    # no beat for ~25 s — but suspend/resume can stall the
                    # beat thread without anything being wrong: one grace
                    # re-check before declaring the app unresponsive
                    g = _k32.WaitForSingleObject(h_beat, HEARTBEAT_GRACE_MS)
                    if g == 0:
                        continue
                    # parent alive but silent for ~40 s: wedged — restore
                    _restore_and_notify(backup_path, mem_backup, parent_pid,
                                        reason="unresponsive",
                                        mem_vals=mem_vals)
                    return 0
                if mem_backup and not os.path.isfile(backup_path):
                    _rewrite_backup(mem_backup, backup_path)
                continue
            # WAIT_FAILED or anything unexpected: fall back to polling so a
            # broken multi-wait can never leave the proxy unprotected
            if _k32.WaitForSingleObject(h_parent, 0) == 0:
                _restore_and_notify(backup_path, mem_backup, parent_pid,
                                    mem_vals=mem_vals)
                return 0
            time.sleep(1.0)
    finally:
        for h in (h_parent, h_event, h_beat):
            if h:
                _k32.CloseHandle(h)

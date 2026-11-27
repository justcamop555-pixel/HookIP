"""Detached watchdog: restores system proxy settings if HookIP dies.

Run as:  python run_hookip.py --hookip-watchdog <backup.json> <parent_pid> <event_name>

Design notes (v2):
- the backup file's CONTENT is loaded into memory at startup. The file can
  later disappear (AV cleaner, disk cleaner, OneDrive sync) — the watchdog
  itself then becomes the safe copy: it rewrites the file during its
  periodic self-check and can restore straight from memory.
- WaitForMultipleObjects(parent, stop_event): reacts to the parent's death
  INSTANTLY (the old loop polled once per second) and burns no CPU while
  idle. A 10 s wait timeout doubles as the self-check tick.
- restore is layered: backup file -> rewritten from memory -> (final
  fallback) RunOnce registration + an explicit 'restore manually' notice,
  so a watchdog can never die silently with the proxy left pointing at a
  dead HookIP port.
- OpenProcess is retried ~3x before the 'parent is already gone' path: an
  open failure while HookIP is actually running must not restore the
  proxy out from under a working session.
"""
import ctypes
import os
import sys
import time

from . import notify
from .winproxy import BACKUP_PATH, _k32, restore_from_file, set_runonce

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102          # 258
WAIT_FAILED = 0xFFFFFFFF
SELF_CHECK_MS = 10000              # self-check / backup-file watch tick


def _rewrite_backup(vals_text, path):
    """Put the in-memory backup text back on disk (self-check + fallback)."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(vals_text)
        return True
    except OSError:
        return False


def _do_restore(backup_path, mem_backup):
    """Restore the saved proxy settings, best effort.

    Order: (1) the backup file as-is, (2) rewritten from the in-memory
    copy, retried briefly — a transient AV lock on the file or the
    registry should not defeat a crash restore.
    Returns True when the registry was written."""
    for _ in range(3):
        try:
            if restore_from_file(backup_path):
                return True
        except OSError:
            pass                    # registry/file error mid-restore — retry
        if not (mem_backup and _rewrite_backup(mem_backup, backup_path)):
            time.sleep(0.5)         # nothing to rewrite; pause before retry
    return False


def _restore_and_notify(backup_path, mem_backup):
    """Restore + user feedback. Never raises."""
    try:
        restored = _do_restore(backup_path, mem_backup)
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
    return restored


def main(backup_path, parent_pid, event_name):
    SYNCHRONIZE = 0x00100000
    # the backup content is the watchdog's own safe copy: load it BEFORE
    # anything can go wrong, and keep it for the whole lifetime
    mem_backup = None
    try:
        with open(backup_path, "r", encoding="utf-8") as fh:
            mem_backup = fh.read()
    except OSError:
        mem_backup = None

    h_parent = None
    for _ in range(3):
        # an OpenProcess failure while HookIP is alive (transient) must
        # not tear down a working proxy: retry before assuming death
        h_parent = _k32.OpenProcess(SYNCHRONIZE, False, int(parent_pid))
        if h_parent is not None:
            break
        time.sleep(0.7)
    h_event = _k32.OpenEventW(SYNCHRONIZE, False, event_name) if event_name else None

    try:
        if h_parent is None:
            # cannot observe the parent (already gone / access denied):
            # give it a final grace moment, then restore unconditionally
            time.sleep(3)
            _restore_and_notify(backup_path, mem_backup)
            return 0

        # WAIT_OBJECT_0   -> parent died
        # WAIT_OBJECT_0+1 -> clean-stop signal
        # WAIT_TIMEOUT    -> self-check tick
        # WAIT_FAILED     -> wait broken; poll as a fallback
        arr = (ctypes.c_void_p * 2)(h_parent, h_event) if h_event is not None else None
        while True:
            if arr is not None:
                w = _k32.WaitForMultipleObjects(2, arr, False, SELF_CHECK_MS)
            else:
                w = _k32.WaitForSingleObject(h_parent, SELF_CHECK_MS)
            if w == WAIT_OBJECT_0:
                _restore_and_notify(backup_path, mem_backup)
                return 0
            if w == WAIT_OBJECT_0 + 1:
                return 0                      # told to stop — clean exit
            if w == WAIT_TIMEOUT:
                # self-check: the backup file must survive until it is
                # needed — restore it from memory when something removed it
                if mem_backup and not os.path.isfile(backup_path):
                    _rewrite_backup(mem_backup, backup_path)
                continue
            # WAIT_FAILED or anything unexpected: fall back to polling so a
            # broken multi-wait can never leave the proxy unprotected
            if _k32.WaitForSingleObject(h_parent, 0) == 0:
                _restore_and_notify(backup_path, mem_backup)
                return 0
            time.sleep(1.0)
    finally:
        if h_parent:
            _k32.CloseHandle(h_parent)
        if h_event:
            _k32.CloseHandle(h_event)

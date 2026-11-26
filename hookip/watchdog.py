"""Detached watchdog: restores system proxy settings if HookIP dies.

Run as:  python run_hookip.py --hookip-watchdog <backup.json> <parent_pid> <event_name>
"""
import ctypes
import sys
import time

from .winproxy import _k32


def main(backup_path, parent_pid, event_name):
    SYNCHRONIZE = 0x00100000
    h_parent = _k32.OpenProcess(SYNCHRONIZE, False, int(parent_pid))
    h_event = _k32.OpenEventW(SYNCHRONIZE, False, event_name)
    from . import winproxy  # inside try so a broken cwd still works
    if h_parent is None:
        # cannot observe the parent (already gone / access denied):
        # give it a grace moment, then restore unconditionally.
        time.sleep(3)
        winproxy.restore_from_file(backup_path)
        return 0
    while True:
        if h_event and _k32.WaitForSingleObject(h_event, 0) == 0:
            return 0                      # told to stop — parent exited cleanly
        if _k32.WaitForSingleObject(h_parent, 0) == 0:
            # parent died — restore, best effort, then quit
            for _ in range(3):
                if winproxy.restore_from_file(backup_path):
                    break
                time.sleep(0.5)
            return 0
        time.sleep(1.0)


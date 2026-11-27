"""HookIP launcher.

  python run_hookip.py                 → desktop app
  python run_hookip.py --hookip-watchdog <backup> <ppid> <event>  → crash-safety watchdog
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    if "--hookip-watchdog" in sys.argv:
        i = sys.argv.index("--hookip-watchdog")
        args = sys.argv[i + 1:i + 5]      # backup ppid stop_event [beat_event]
        if len(args) < 3:
            return 2
        from hookip import watchdog
        try:
            watchdog.main(*args)
        except Exception:
            # last-resort restore if anything above fails
            try:
                from hookip import winproxy
                winproxy.restore_from_file(args[0])
            except Exception:
                pass
        return 0
    from hookip.app import run
    run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

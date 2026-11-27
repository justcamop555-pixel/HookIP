"""HookIP — user-space DPI/SNI bypass proxy for Windows."""

# Release version — the number that is PUBLISHED on GitHub. Bump it only
# when the release is actually uploaded; the updater compares this against
# the latest GitHub tag.
__version__ = "1.1.1"
# Local build ID — identifies a build that may NOT be on GitHub yet
# (dev/test builds). Leave "" for published builds; set something like
# "20261127.1" for a local build so the updater can tell 'ahead of
# GitHub' from 'up to date' and never offer a downgrade.
__build_id__ = ""
APP_NAME = "HookIP"

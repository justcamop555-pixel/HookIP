"""Settings persistence for HookIP (%LOCALAPPDATA%\\HookIP\\settings.json)."""
import json
import os

from . import APP_NAME

APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME)
SETTINGS_PATH = os.path.join(APP_DIR, "settings.json")

DEFAULTS = {
    "port": 8890,
    "fragment_size": 2,
    "strategy": "smart",          # smart | chunk | random
    "doh_enabled": True,
    "verbose": False,
    "proxy_mode": "manual",       # manual | pac
    "excluded": ["localhost", "*.local", "*.lan", "127.0.0.1"],
    "remember": True,
}


class Config:
    """Thin mutable wrapper around the settings dict."""

    def __init__(self, data=None):
        self._data = dict(DEFAULTS)
        if data:
            self._data.update({k: v for k, v in data.items() if k in DEFAULTS})

    # -- dict-style access ------------------------------------------------
    def __getattr__(self, name):
        try:
            return self.__dict__["_data"][name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if name == "_data":
            self.__dict__["_data"] = value
        elif name in self._data:
            self._data[name] = value
        else:
            self.__dict__[name] = value

    # -- persistence ------------------------------------------------------
    @classmethod
    def load(cls):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return cls(data)
        except (OSError, ValueError):
            return cls()

    def save(self):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
        except OSError:
            pass

    def snapshot(self):
        return dict(self._data)

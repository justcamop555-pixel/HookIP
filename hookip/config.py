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
    "proxy_mode": "manual",       # manual | pac | both
    "excluded": ["localhost", "*.local", "*.lan", "127.0.0.1"],
    "remember": True,
    "minimize_to_tray": True,
    "pac_token": "",              # stable PAC URL token (generated once)
    "upstream_proxy": "",         # network's own mandatory proxy (restricted Wi-Fi), "" = none
}


class Config:
    """Thin mutable wrapper around the settings dict."""

    def __init__(self, data=None):
        self._data = dict(DEFAULTS)
        if data:
            clean = {k: v for k, v in data.items() if k in DEFAULTS}
            self._data.update(self._sanitize(clean))

    @staticmethod
    def _sanitize(clean):
        """Type-check loaded settings: a hand-edited (or corrupt) settings.json
        must not put a string into cfg.port or a string into the excluded
        LIST (which used to explode into single characters in the editor box)."""
        if not isinstance(clean.get("port"), int) or not (1 <= clean["port"] <= 65535):
            clean["port"] = DEFAULTS["port"]
        if not isinstance(clean.get("fragment_size"), int) or not (1 <= clean["fragment_size"] <= 255):
            clean["fragment_size"] = DEFAULTS["fragment_size"]
        if clean.get("strategy") not in ("smart", "chunk", "random"):
            clean["strategy"] = DEFAULTS["strategy"]
        if clean.get("proxy_mode") not in ("manual", "pac", "both"):
            clean["proxy_mode"] = DEFAULTS["proxy_mode"]
        for k in ("doh_enabled", "verbose", "remember", "minimize_to_tray"):
            if not isinstance(clean.get(k), bool):
                clean[k] = DEFAULTS[k]
        if not isinstance(clean.get("excluded"), list) or \
                not all(isinstance(x, str) for x in clean["excluded"]):
            clean["excluded"] = list(DEFAULTS["excluded"])
        if not isinstance(clean.get("pac_token"), str):
            clean["pac_token"] = DEFAULTS["pac_token"]
        if not isinstance(clean.get("upstream_proxy"), str):
            clean["upstream_proxy"] = DEFAULTS["upstream_proxy"]
        return clean

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
            # atomic write: settings.json is replaced only after the temp
            # file is fully on disk — a crash or power loss mid-save can no
            # longer corrupt the settings file (it used to truncate it)
            tmp = SETTINGS_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, SETTINGS_PATH)
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def snapshot(self):
        return dict(self._data)

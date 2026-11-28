"""Settings persistence for HookIP (%LOCALAPPDATA%\\HookIP\\settings.json)."""
import json
import os
import threading

from . import APP_NAME
from . import dataguard

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
    "strat_memory": {},           # host -> ClientHello strategy that last worked (persisted)
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
        sm = clean.get("strat_memory")
        if isinstance(sm, dict):
            # per-entry filter: one hand-edited bad value must not throw
            # away the whole learned map (all-or-nothing used to reset it)
            sm = {k: v for k, v in sm.items()
                  if isinstance(k, str) and isinstance(v, str)
                  and v in ("smart", "chunk", "random", "raw")}
            clean["strat_memory"] = sm
        else:
            clean["strat_memory"] = {}
        # bound it: a marathon session on a browsing-heavy machine can
        # learn thousands of hosts; keep the most recently LEARNED 256
        # (dict insertion order — evictions re-insert learned hosts at
        # the end, so the tail is the live set)
        if len(clean["strat_memory"]) > 256:
            clean["strat_memory"] = dict(list(clean["strat_memory"].items())[-256:])
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
            with open(SETTINGS_PATH, "rb") as fh:
                raw_bytes = fh.read()
        except OSError:
            return cls()
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw = ""
        if raw.startswith(dataguard.CFG_MAGIC):
            # encrypted-at-rest settings (the normal case)
            plain = dataguard.decrypt_bytes(raw)
            if plain is None:
                # ours but UNREADABLE (corrupt blob / copied from another
                # account): quarantine instead of silently falling back
                # to defaults — falling back here would wipe the user's
                # site list on the next save. os.replace moves the bad
                # file aside; save() writes a fresh settings.json and
                # never touches the .bad file.
                try:
                    os.replace(SETTINGS_PATH, SETTINGS_PATH + ".bad")
                except OSError:
                    pass
                c = cls()
                # the caller surfaces this loudly (log + toast) — the old
                # file with the user's site list is recoverable at .bad
                c.quarantined = True
                return c
            try:
                return cls(json.loads(plain.decode("utf-8")))
            except ValueError:
                return cls()
        # legacy plaintext file (older version / manual edit): honor it;
        # the next save() re-encrypts it
        try:
            return cls(json.loads(raw))
        except ValueError:
            return cls()

    def save(self):
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            # atomic write: settings.json is replaced only after the temp
            # file is fully on disk — a crash or power loss mid-save can no
            # longer corrupt the settings file (it used to truncate it)
            # UNIQUE temp name per thread: saves can legitimately happen
            # from two threads (PAC-token bootstrap, settings dialog) — a
            # shared .tmp let the second writer truncate the first one's
            # file mid-write and publish a corrupt mix.
            tmp = SETTINGS_PATH + f".{threading.get_ident()}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                # DPAPI-encrypted at rest: a copied settings.json shows no
                # bypassed-site list, no port, nothing to profile
                fh.write(dataguard.encrypt_bytes(
                    json.dumps(self._data, indent=2).encode("utf-8")))
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

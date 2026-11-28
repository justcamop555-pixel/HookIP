"""Settings persistence for HookIP (%LOCALAPPDATA%\\HookIP\\settings.json)."""
import json
import os
import threading
import time

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
    "log_retention_days": 14,     # session logs older than this are purged; 0 = keep forever
}


class Config:
    """Thin mutable wrapper around the settings dict."""

    def __init__(self, data=None):
        # _data MUST be the first assignment: __setattr__ reads it to
        # decide instance-attribute vs settings-dict routing
        self._data = dict(DEFAULTS)
        # load/save state surfaced for the app (all plain attributes,
        # never persisted):
        #   quarantined      a bad file was moved aside during load
        #   quarantine_path  where that file went
        #   degraded         this session could not read the encryption
        #                    key (transient registry error) — settings
        #                    were left untouched and saves are refused
        #   last_save_error  message of the last failed save()
        self.quarantined = False
        self.quarantine_path = None
        self.degraded = False
        self.last_save_error = None
        # dict(DEFAULTS) SHARES nested mutables with the class default —
        # an in-place cfg.excluded.append(...) or strat_memory update would
        # corrupt DEFAULTS for every future Config() in this process.
        # Copy them so mutation stays instance-local (all call sites rebind
        # today; this makes the hazard impossible rather than avoided).
        self._data["excluded"] = list(self._data["excluded"])
        self._data["strat_memory"] = dict(self._data["strat_memory"])
        if data:
            clean = {k: v for k, v in data.items() if k in DEFAULTS}
            self._data.update(self._sanitize(clean))

    @staticmethod
    def _sanitize(clean):
        """Type-check loaded settings: a hand-edited (or corrupt) settings.json
        must not put a string into cfg.port or a string into the excluded
        LIST (which used to explode into single characters in the editor box)."""
        # bool is an int subclass: a JSON `true` used to pass the int check
        # and silently become port 1 / fragment size 1
        for k, lo, hi in (("port", 1, 65535), ("fragment_size", 1, 255),
                          ("log_retention_days", 0, 3650)):
            v = clean.get(k)
            if not isinstance(v, int) or isinstance(v, bool) or not (lo <= v <= hi):
                clean[k] = DEFAULTS[k]
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
        now = int(time.time())
        if isinstance(sm, dict):
            # per-entry filter: one hand-edited bad value must not throw
            # away the whole learned map (all-or-nothing used to reset it)
            # Two persisted forms are accepted:
            #   legacy  host: "smart"            -> stamped t=now
            #   current host: {"s": "smart", "t": epoch}
            entries = {}
            for k, v in sm.items():
                if not isinstance(k, str):
                    continue
                if isinstance(v, str) and \
                        v in ("smart", "chunk", "random", "raw"):
                    entries[k] = {"s": v, "t": now}
                elif isinstance(v, dict):
                    s, t = v.get("s"), v.get("t")
                    if isinstance(s, str) and \
                            s in ("smart", "chunk", "random", "raw") and \
                            isinstance(t, int) and not isinstance(t, bool):
                        entries[k] = {"s": s, "t": t}
            clean["strat_memory"] = entries
        else:
            clean["strat_memory"] = {}
        # bound it: a marathon session on a browsing-heavy machine can
        # learn thousands of hosts; keep the NEWEST 256 by timestamp
        if len(clean["strat_memory"]) > 256:
            top = sorted(clean["strat_memory"].items(),
                         key=lambda kv: kv[1].get("t", 0),
                         reverse=True)[:256]
            clean["strat_memory"] = dict(top)
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
    def _quarantine(self):
        """Move the unreadable settings file aside (never raises).

        The quarantine NEVER overwrites an earlier .bad: the second bad
        file gets a timestamped name (plus a counter when even that name
        is taken). The final path is exposed as cfg.quarantine_path."""
        base = SETTINGS_PATH + ".bad"
        target = base
        if os.path.exists(target):
            target = base + "." + time.strftime("%Y%m%d-%H%M%S")
            n = 0
            while os.path.exists(target + (f".{n}" if n else "")):
                n += 1
            target = target + (f".{n}" if n else "")
        try:
            os.replace(SETTINGS_PATH, target)
            self.quarantine_path = target
            self.quarantined = True
        except OSError:
            self.quarantine_path = None

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
                if not dataguard.using_per_install_key():
                    # DEGRADED KEY SESSION: the file was written by a
                    # session whose registry key we cannot read right
                    # now (transient registry error). It is probably
                    # PERFECTLY GOOD — quarantining it here would lose
                    # it; and save() refusing protects it too. Leave the
                    # file exactly where it is.
                    c = cls()
                    c.degraded = True
                    return c
                # ours but UNREADABLE (corrupt blob / copied from another
                # account): quarantine instead of silently falling back
                # to defaults — falling back here would wipe the user's
                # site list on the next save. os.replace moves the bad
                # file aside; save() writes a fresh settings.json and
                # never touches the .bad file.
                c = cls()
                c._quarantine()
                # the caller surfaces this loudly (log + toast) — the old
                # file with the user's site list is recoverable at .bad
                return c
            try:
                loaded = json.loads(plain.decode("utf-8"))
            except ValueError:
                loaded = None
            if not isinstance(loaded, dict):
                # decryptable but NOT valid settings JSON (truncated
                # write, hand-edit gone wrong): quarantine under the
                # same rules — the next save must not clobber it
                c = cls()
                c._quarantine()
                return c
            return cls(loaded)
        # legacy plaintext file (older version / manual edit): honor it;
        # the next save() re-encrypts it. Invalid JSON / non-dict is
        # quarantined too — a hand-edited broken file must not be
        # silently overwritten by the next save.
        try:
            loaded = json.loads(raw)
        except ValueError:
            loaded = None
        if not isinstance(loaded, dict):
            c = cls()
            if raw.strip():          # an empty/whitespace file is just a
                c._quarantine()      # never-saved placeholder — no history
            return c                 # to preserve, leave it alone
        return cls(loaded)

    def save(self):
        tmp = None
        try:
            # DEGRADED KEY SESSION: refuse to overwrite an encrypted file
            # we cannot decrypt this session (using_per_install_key()
            # False = transient registry error). Overwriting it would
            # destroy settings written by the real key.
            if self.degraded:
                self.last_save_error = (
                    "degraded session: the encryption key could not be "
                    "read, existing settings were left untouched")
                return False
            try:
                with open(SETTINGS_PATH, "rb") as fh:
                    existing = fh.read(16)
            except OSError:
                existing = b""
            if existing.startswith(dataguard.CFG_MAGIC.encode("ascii")):
                try:
                    with open(SETTINGS_PATH, "rb") as fh:
                        enc = fh.read()
                except OSError:
                    enc = ""
                if dataguard.decrypt_bytes(enc) is None and \
                        not dataguard.using_per_install_key():
                    self.last_save_error = (
                        "refused to overwrite encrypted settings that this "
                        "session cannot decrypt (key unavailable)")
                    return False
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
            self.last_save_error = None
            return True
        except OSError as exc:
            self.last_save_error = str(exc)
            # tmp may be unbound if makedirs failed before the assignment
            try:
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False
        except Exception as exc:   # noqa: BLE001 — save() must never raise
            self.last_save_error = f"{type(exc).__name__}: {exc}"
            try:
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False

    def snapshot(self):
        return dict(self._data)

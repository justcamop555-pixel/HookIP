r"""Data-theft guard: encrypts everything sensitive HookIP keeps on disk.

Threat: malware running on this machine bulk-copies folders (browsers,
apps, %LOCALAPPDATA%) looking for browsing history, site lists and
saved settings. HookIP's log files ARE a browsing history and
settings.json IS a list of bypassed sites — in plaintext, both are a
bounty for that scan.

Guard, in layers (all stdlib/ctypes, still no admin):
1. LOG ENCRYPTION (DPAPI + per-install key): every session log line is
   encrypted individually (CryptProtectData, user scope + a random
   32-byte per-install key) before it touches disk. A copied .hlog file
   is opaque base64 blobs — no domains, no verdicts, nothing to grep.
2. SETTINGS ENCRYPTION: settings.json is encrypted whole. A plaintext
   file found at load (older version / manual edit) is honored once and
   re-encrypted on the next save.
3. FOLDER ACL HARDENING: the HookIP data directory's inherited ACEs
   are stripped and access is granted to the current user's SID and
   SYSTEM (both as *SID, not account names, so domain-joined and
   Microsoft-account machines resolve unambiguously). Malware running
   as a different (non-admin) account or at low integrity gets nothing.
4. MIGRATION: at startup, any legacy plaintext .log files left by older
   versions are encrypted and merged into .hlog files. The source .log
   is claimed first by renaming it to foo.log.migrating (a locked file
   is skipped without writing anything), the claim file is deleted
   last, a leftover foo.log.migrating from a crashed run is finished on
   the next run, and each merge writes ONE encrypted idempotency marker
   ("# migrated <name> sha256=<hex>") as the last line of the migrated
   block — a rerun scans the .hlog for that marker and skips the merge
   if the same source file was already migrated, so no duplicates and
   an existing .hlog is never overwritten.
5. ENTROPY UPGRADE: one-time re-encryption of log lines and settings
   that were still written with the legacy static entropy.
6. PLAINTEXT HYGIENE: a startup sweep deletes plaintext leftovers the
   current code never reads (older versions' winhttp dumps, stale temp
   scripts); the crash marker, the system-proxy backup and restore.cmd
   credentials are encrypted/masked at the source; session logs age out
   after a retention window (default 14 days) instead of hoarding a
   years-deep browsing history forever.

Why the per-install key: the original entropy was a constant in the
public source AND inside the exe, so any generic DPAPI decryptor — or
anything that greps embedded strings out of the binary — could decrypt
every HookIP file at rest. The key is now random per install and lives
ONLY in the registry (HKCU\Software\HookIP\DataKey): a bulk copy of the
%LOCALAPPDATA%\HookIP folder alone decrypts to nothing, and offline
DPAPI-dump tools fail without the key. The legacy entropy is kept as a
READ fallback so pre-upgrade files stay readable, and upgrade_entropy()
re-encrypts them on the first run after the update.

Honest limits (stated in Diagnostics too): a determined attacker
running as YOUR user account with full access can reverse DPAPI, and
targeted malware that also dumps the registry key value can read
everything the current code wrote — no user-space app can stop that.
This guard defeats bulk folder-theft, cross-account snooping, offline
DPAPI-dump toolchains and anything that exfiltrates files to read
elsewhere. Antivirus/Defender stays the wall for live malware. Also
note: encrypting and deleting plaintext does not erase it from free
disk space, OneDrive version history or existing backups — full
erasure needs those layers too.

Return conventions:
- decrypt_line: None = "not our format"; UNREADABLE = "our format but
  the blob could not be decrypted" (callers can count and report those
  separately, e.g. "N unreadable lines" in Diagnostics).
- decrypt_bytes: None for both foreign input and failed decryption
  (single-call whole-file use; Config.load treats any None as
  "fall back to defaults / legacy plaintext").
"""
import base64
import ctypes
import hashlib
import os
import re
import secrets
import subprocess
import threading
import time
import winreg
from ctypes import wintypes

# ---- per-install encryption key (v2) --------------------------------
# The original entropy was the static string below: public in the repo
# source AND embedded in every built exe, so any generic DPAPI-decryption
# tool — or anything that dumps embedded strings from the binary — could
# decrypt every file at rest. The key is now random per install, stored
# OUTSIDE the data folder (so a bulk folder copy alone is useless) and
# OUTSIDE the binary (so string-scanning the exe finds nothing).
_KEY_REGISTRY_PATH = r"Software\HookIP"
_KEY_REGISTRY_VALUE = "DataKey"
_KEY_LEN = 32
_LEGACY_ENTROPY = b"HookIP-dataguard-v1"   # read fallback for pre-upgrade
                                           # blobs; never used for new writes

_entropy = None            # bytes actually used for NEW blobs
_legacy_fallback = False   # registry unusable -> degraded to static entropy
_key_lock = threading.Lock()
_KEY_BUF = None            # keeps the key bytes alive for the process
_ENTROPY_BLOB = None       # DATA_BLOB over the per-install key (lazy)


def _load_key():
    """Load (or create) the per-install key. Called on every crypto call
    but does real work once per process; thread-safe."""
    global _entropy, _legacy_fallback, _ENTROPY_BLOB, _KEY_BUF
    with _key_lock:
        if _ENTROPY_BLOB is not None:
            return
        # outcome of the registry probe: 'ok' (key loaded), 'missing'
        # (value absent — safe to create), 'invalid' (present but wrong
        # type/len — can never decrypt anything), 'unreachable' (transient
        # registry failure — we do NOT know whether the value exists)
        status = "ok"
        key = None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                _KEY_REGISTRY_PATH) as k:
                raw, _typ = winreg.QueryValueEx(k, _KEY_REGISTRY_VALUE)
            if isinstance(raw, bytes) and len(raw) == _KEY_LEN:
                key = raw
            else:
                status = "invalid"
        except FileNotFoundError:
            status = "missing"
        except OSError:
            # TRANSIENT registry failure (AV lock, key momentarily busy):
            # the old code regenerated the key on ANY OSError and
            # OVERWROTE a perfectly good one, orphaning every file ever
            # written with it. Retry once; only create a key when the
            # absence/invalidity is PROVEN.
            try:
                time.sleep(0.05)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    _KEY_REGISTRY_PATH) as k:
                    raw, _typ = winreg.QueryValueEx(k, _KEY_REGISTRY_VALUE)
                if isinstance(raw, bytes) and len(raw) == _KEY_LEN:
                    key = raw
                else:
                    status = "invalid"
            except FileNotFoundError:
                status = "missing"
            except OSError:
                status = "unreachable"
        if key is None and status in ("missing", "invalid"):
            # absent or provably garbage: create a fresh per-install key
            key = secrets.token_bytes(_KEY_LEN)
            try:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                      _KEY_REGISTRY_PATH) as k:
                    winreg.SetValueEx(k, _KEY_REGISTRY_VALUE, 0,
                                      winreg.REG_BINARY, key)
            except OSError:
                # no usable registry access: degrade to the legacy static
                # entropy (old behavior) rather than failing every write
                key = _LEGACY_ENTROPY
                _legacy_fallback = True
        elif key is None:
            # 'unreachable': do NOT write anything — the stored key (if
            # any) stays untouched, old files remain readable on the next
            # run; this session degrades to the legacy entropy
            key = _LEGACY_ENTROPY
            _legacy_fallback = True
        _entropy = key
        _KEY_BUF = ctypes.create_string_buffer(key, len(key))
        _ENTROPY_BLOB = _DATA_BLOB(
            len(key), ctypes.cast(_KEY_BUF, ctypes.POINTER(ctypes.c_char)))

# sentinel: the line IS ours (HKLOG1:) but the blob failed to decrypt
# (truncated, corrupted, or re-encrypted under a different account).
# Falsy by design: `if text:` cannot misread it as real content.
# Always compare with `is UNREADABLE`.
class _Unreadable:
    def __bool__(self):
        return False

    def __repr__(self):
        return "<UNREADABLE>"


UNREADABLE = _Unreadable()


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]

# legacy-entropy DATA_BLOB built once at import (static bytes)
_LEGACY_BUF = ctypes.create_string_buffer(_LEGACY_ENTROPY, len(_LEGACY_ENTROPY))
_LEGACY_BLOB = _DATA_BLOB(
    len(_LEGACY_ENTROPY), ctypes.cast(_LEGACY_BUF, ctypes.POINTER(ctypes.c_char)))


# ---- ctypes declarations: no pointer truncation, no GC accidents ----
# Private WinDLL instances: ctypes.windll.* returns process-wide cached
# objects, and setting argtypes on them would change behavior for other
# code in this process. use_last_error=True keeps GetLastError accurate.
_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32")

_BLOB_PTR = ctypes.POINTER(_DATA_BLOB)
_crypt32.CryptProtectData.argtypes = [
    _BLOB_PTR,                # pDataIn
    wintypes.LPCWSTR,         # szDataDescr
    _BLOB_PTR,                # pOptionalEntropy
    wintypes.LPVOID,          # pvReserved
    wintypes.LPVOID,          # pPromptStruct
    wintypes.DWORD,           # dwFlags
    _BLOB_PTR,                # pDataOut
]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [
    _BLOB_PTR,
    ctypes.POINTER(wintypes.LPWSTR),   # ppszDataDescr (we pass None)
    _BLOB_PTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    _BLOB_PTR,
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
_kernel32.LocalFree.restype = wintypes.HLOCAL

_advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)]
_advapi32.GetTokenInformation.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = [
    wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE

# CRYPTPROTECT_UI_FORBIDDEN: never surface a DPAPI prompt from a
# background thread
_CRYPTPROTECT_UI_FORBIDDEN = 0x1

# file magic prefixes: identify guarded formats at a glance
LOG_MAGIC = "HKLOG1:"
CFG_MAGIC = "HKCFG1:"


def _blob(data):
    """Return (DATA_BLOB, backing_buffer) — keep the buffer referenced
    until the C call has returned."""
    data = bytes(data)
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _unprotect_once(blob, ent_blob):
    """One CryptUnprotectData attempt with the given entropy blob.
    Returns bytes or None (never raises for a failed decrypt)."""
    pin, keep_in = _blob(blob)
    pout = _DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(ctypes.byref(pin), None,
                                     ctypes.byref(ent_blob),
                                     None, None,
                                     _CRYPTPROTECT_UI_FORBIDDEN,
                                     ctypes.byref(pout))
    if not ok:
        return None
    try:
        return ctypes.string_at(pout.pbData, pout.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(pout.pbData, ctypes.c_void_p))


def _crypt(data, decrypt):
    if decrypt:
        _load_key()
        ent = _ENTROPY_BLOB
        if ent is None:
            # same guard as the encrypt path: _load_key() always assigns
            # this; failing loudly beats a None deref inside ctypes
            raise OSError("dataguard: per-install key unavailable")
        # current key first (one call in the common case); pre-upgrade
        # blobs fall back to the legacy static entropy
        out = _unprotect_once(data, ent)
        if out is None and not _legacy_fallback and _entropy != _LEGACY_ENTROPY:
            out = _unprotect_once(data, _LEGACY_BLOB)
        if out is None:
            raise OSError("DPAPI CryptUnprotectData failed: blob not "
                          "decryptable with the per-install or legacy key")
        return out
    _load_key()
    ent = _ENTROPY_BLOB
    if ent is None:
        # unprovable-by-inference: _load_key() always assigns this — but
        # if it somehow did not, failing loudly beats a None deref in C
        raise OSError("dataguard: per-install key unavailable")
    pin, keep_in = _blob(data)
    pout = _DATA_BLOB()
    ok = _crypt32.CryptProtectData(ctypes.byref(pin), None,
                                   ctypes.byref(ent),
                                   None, None,
                                   _CRYPTPROTECT_UI_FORBIDDEN,
                                   ctypes.byref(pout))
    if not ok:
        # use_last_error=True on _crypt32 makes get_last_error() valid
        # here; the real error code lands in Diagnostics
        raise OSError("DPAPI CryptProtectData"
                      f" failed: {ctypes.WinError(ctypes.get_last_error())}")
    try:
        out = ctypes.string_at(pout.pbData, pout.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(pout.pbData, ctypes.c_void_p))
    # keep_in/its buffer stay alive until here
    del keep_in
    return out


def encrypt_line(text, magic=LOG_MAGIC):
    """One log line -> 'HKLOG1:<base64 dpapi blob>'.

    None is treated as an empty string so a logging path can never
    crash on a bad message; raises TypeError for non-str, non-None.
    Encodes with errors='replace': log lines carry raw host strings that
    Python may decode with surrogateescape — a lone surrogate crashes a
    strict utf-8 encode, and that exception used to escape _emit into
    the proxy's handler. Unpaired surrogates become '?' (b'\\x3f',
    Python 3.15's replace behavior) — round-trippable, never an escape.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise TypeError(f"encrypt_line expects str, got {type(text).__name__}")
    blob = _crypt(text.encode("utf-8", "replace"), decrypt=False)
    return magic + base64.b64encode(blob).decode("ascii")


def decrypt_line(line):
    """Inverse of encrypt_line.

    Returns:
      str         — decrypted text
      None        — the line is not our format (plain text, blank, ...)
      UNREADABLE  — our format (HKLOG1:) but decryption failed
                    (truncated/corrupt blob, or copied from another
                    Windows account)
    """
    if not isinstance(line, str):
        return None
    line = line.strip()
    if not line.startswith(LOG_MAGIC):
        return None
    try:
        blob = base64.b64decode(line[len(LOG_MAGIC):], validate=True)
        return _crypt(blob, decrypt=True).decode("utf-8", "replace")
    except Exception:
        return UNREADABLE


def encrypt_bytes(data):
    """Whole-file payload -> 'HKCFG1:<base64 dpapi blob>' as str.

    bytes or bytearray as-is; str is accepted too (encoded utf-8);
    anything else raises TypeError."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        # bytes(int) silently builds a zero-filled buffer — reject it
        raise TypeError(f"encrypt_bytes expects bytes or str, got {type(data).__name__}")
    blob = _crypt(bytes(data), decrypt=False)
    return CFG_MAGIC + base64.b64encode(blob).decode("ascii")


def decrypt_bytes(text):
    """Inverse of encrypt_bytes.

    Returns None for foreign/plaintext input AND for decryption
    failure (the whole-file caller wants a single 'cannot use this
    file' signal); never raises for those cases.
    """
    if not isinstance(text, (str, bytes)):
        return None
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else text
    text = text.strip()
    if not text.startswith(CFG_MAGIC):
        return None
    try:
        blob = base64.b64decode(text[len(CFG_MAGIC):], validate=True)
        return _crypt(blob, decrypt=True)
    except Exception:
        return None


def is_encrypted_file(path, magic):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(16).startswith(magic)
    except OSError:
        return False


# ------------------------------------------------------------- SIDs
def _current_user_sid():
    """Current process token's user SID as 'S-1-5-...' (string), or None.

    Uses OpenProcessToken + GetTokenInformation(TokenUser) +
    ConvertSidToStringSidW — the real SID, unambiguous on domain-joined
    and Microsoft-account machines (unlike os.environ['USERNAME']).
    """
    global _cached_sid
    if _cached_sid:
        return _cached_sid
    try:
        advapi32 = _advapi32
        TOKEN_QUERY = 0x0008
        TOKEN_USER = 1  # TOKEN_INFORMATION_CLASS
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
                _kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            needed = wintypes.DWORD()
            # probe the required buffer size
            advapi32.GetTokenInformation(token, TOKEN_USER, None, 0,
                                         ctypes.byref(needed))
            if needed.value == 0:
                return None
            buf = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                    token, TOKEN_USER, buf, needed.value, ctypes.byref(needed)):
                return None
            # TOKEN_USER = { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attrs; } }
            psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            if not psid:
                return None
            sid_str = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(
                    ctypes.c_void_p(psid), ctypes.byref(sid_str)):
                return None
            try:
                _cached_sid = sid_str.value
            finally:
                _kernel32.LocalFree(ctypes.cast(sid_str, ctypes.c_void_p))
            return _cached_sid
        finally:
            _kernel32.CloseHandle(token)
    except Exception:
        return None


_cached_sid = None


# -------------------------------------------------------------- ACLs
def harden_dir(path):
    """Strip inherited ACEs; grant full control to the current user's
    SID and to SYSTEM (both via *S-1-5-... so account-name ambiguity on
    domain-joined / Microsoft-account machines cannot mis-grant).

    Success is returncode == 0 from icacls — locale-independent, no
    dependence on English output text. No admin is needed (the dir is
    owned by the current user). OneDrive/AV locks make this
    best-effort; returns False when the SID is unavailable or icacls
    fails — callers must tolerate False.
    """
    try:
        sid = _current_user_sid()
        if not sid:
            return False
        cmd = ["icacls", path, "/inheritance:r",
               "/grant:r", f"*{sid}:(OI)(CI)F",
               "/grant:r", "*S-1-5-18:(OI)(CI)F"]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=20,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        return r.returncode == 0
    except Exception:
        return False


def acl_is_hardened(path):
    """True when the directory has no inherited ACEs.

    Checks EVERY icacls output line — including the first, because
    icacls prints the first ACE on the same line as the path — for
    ':(I)': icacls's inheritance marker, which always follows the
    account and a colon and is not localized.

    Limitations: this is a report-parse heuristic (icacls exposes no
    structured API without admin), and a path containing the literal
    ':(I)' would produce a false 'not hardened'. It also proves only
    that no ACEs are INHERITED: an explicit ACE for another principal
    still reads as hardened, and harden_dir's /grant:r does not remove
    such entries — acceptable for a freshly created data folder, whose
    ACL starts empty apart from what harden_dir grants.
    """
    try:
        r = subprocess.run(["icacls", path], capture_output=True, text=True,
                           errors="replace", timeout=10,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        if r.returncode != 0:
            return False
        lines = (r.stdout or "").splitlines()
        return not any(":(I)" in ln for ln in lines)
    except Exception:
        return False


# ------------------------------------------------- entropy upgrade

def _blob_is_legacy(blob):
    """True when `blob` decrypts with the legacy static entropy (and not
    already with the per-install key). False for current/foreign/corrupt
    blobs — nothing to upgrade."""
    _load_key()
    if _unprotect_once(blob, _ENTROPY_BLOB) is not None:
        return False
    if _legacy_fallback or _entropy == _LEGACY_ENTROPY:
        return False
    return _unprotect_once(blob, _LEGACY_BLOB) is not None


def _needs_upgrade(line, magic):
    """For a single guarded line/blob: True = written with the legacy
    static entropy and should be re-encrypted. Foreign/plaintext/blank
    and corrupt lines are False (left exactly as they are)."""
    if not isinstance(line, str):
        return False
    line = line.strip()
    if not line.startswith(magic):
        return False
    try:
        blob = base64.b64decode(line[len(magic):], validate=True)
    except Exception:
        return False
    return _blob_is_legacy(blob)


def settings_needs_entropy_upgrade(path):
    """True when the settings file still holds a legacy-entropy HKCFG1:
    blob — fixing it is one plain save (Config.save re-encrypts whole)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return _needs_upgrade(fh.read(), CFG_MAGIC)
    except OSError:
        return False


def upgrade_entropy(log_dir):
    """Re-encrypt legacy-entropy lines inside .hlog files, in place.

    Runs once per file: the first encrypted line is probed — a file with
    no legacy blob costs one DPAPI attempt and is skipped (cheap repeat
    runs). Upgraded files are rewritten atomically (tmp + os.replace);
    a crash leaves the original intact and the rerun redoes it.
    Never raises; locked files are skipped. Returns (files, lines)."""
    if not os.path.isdir(log_dir):
        return (0, 0)
    files_done = lines_done = 0
    try:
        names = sorted(n for n in os.listdir(log_dir) if n.endswith(".hlog"))
    except OSError:
        return (0, 0)
    for name in names:
        path = os.path.join(log_dir, name)
        tmp = path + ".upg"
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            # probe the first encrypted line (blank lines ahead of it
            # must not mask a legacy file)
            probe = next((ln for ln in lines if ln.startswith(LOG_MAGIC)), None)
            if probe is None or not _needs_upgrade(probe, LOG_MAGIC):
                continue
            out = []
            for ln in lines:
                # rewrite ONLY blobs still on the legacy static entropy —
                # already-current lines are left byte-identical
                if ln.startswith(LOG_MAGIC) and _needs_upgrade(ln, LOG_MAGIC):
                    v = decrypt_line(ln)          # dual-entropy read
                    if isinstance(v, str):
                        out.append(encrypt_line(v))
                        lines_done += 1
                        continue
                out.append(ln)   # current / blank / foreign / unreadable stay
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(out) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            files_done += 1
        except Exception:  # noqa: BLE001 — the upgrade must never crash startup
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
    return (files_done, lines_done)


# --------------------------------------------------------- migration
_MARKER_RE = re.compile(r"^# migrated .+ sha256=([0-9a-f]{64})$")


def is_marker(text):
    """True when text (a decrypted or plaintext log line) is a migration
    idempotency marker: '# migrated <basename> sha256=<hex>'. Public so
    callers (and tests) classify marker lines without reaching into the
    private regex."""
    return isinstance(text, str) and bool(_MARKER_RE.match(text.strip()))


def _decode_legacy(raw):
    """utf-8, then cp1252 (smart quotes/dashes), then latin-1 (cannot
    fail) — plain latin-1 would mangle cp1252's 0x80-0x9F bytes into
    control characters."""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")   # unreachable; latin-1 never fails


def migrate_plaintext_logs(log_dir):
    """Encrypt legacy .log files (older versions wrote plaintext).

    Per file: read BINARY, decode utf-8 -> cp1252 -> latin-1 (so
    non-UTF-8 bytes survive instead of being 'replace'-altered), split
    on "\n" only (splitlines() would also break on \x0c/\x1c-\x1e
    page/separator controls), normalize CRLF, encrypt line-by-line.

    Crash/lock safety: the source .log is first CLAIMED by renaming it
    to foo.log.migrating — if that rename fails (AV/OneDrive lock), the
    file is skipped and nothing is written. The .migrating file is then
    read, merged into foo.hlog (as the last lines, followed by ONE
    encrypted idempotency marker "# migrated <original file name>
    sha256=<hex of the raw source bytes>"), foo.hlog is rewritten
    atomically via temp + os.replace, and the .migrating file is
    deleted LAST. If that final delete fails, a rerun finishes the
    leftover foo.log.migrating instead of ignoring it: the existing
    .hlog is scanned for a marker with the same sha256 — found means
    the merge already happened, so the merge is skipped, the claim is
    deleted and the file counts as converted (NO duplicate lines;
    fresh .log claims never need the scan). If foo.hlog exists but
    cannot be READ (AV lock), the whole file is aborted with the claim
    left in place for the next run — an unreadable .hlog is never
    overwritten. Leftover claims are processed BEFORE their .log, and
    a .log whose claim still exists after that pass is skipped until
    the next run. An existing foo.hlog is NEVER overwritten.

    Concurrency note: the atomic replace covers only the rewrite, not
    concurrent appends — migration must run BEFORE the logger opens
    any .hlog files, or lines appended in between are lost.

    Returns (converted, total). Best-effort; locked files are skipped.
    """
    if not os.path.isdir(log_dir):
        return (0, 0)
    converted = total = 0
    try:
        names = os.listdir(log_dir)
    except OSError:
        return (0, 0)
    # leftover claims FIRST (their .log must not be claimed while the
    # claim from an unfinished pass is still in place), then fresh .log
    leftovers = [n for n in names if n.endswith(".log.migrating")]
    logs = [n for n in names if n.endswith(".log")]
    for name in leftovers + logs:
        is_leftover = name.endswith(".log.migrating")
        if is_leftover:
            migrating = os.path.join(log_dir, name)
            base = migrating[:-len(".migrating")]      # ...\foo.log
            dst = (base[:-4] if base.endswith(".log") else base) + ".hlog"
            # marker carries the BASENAME only — an absolute path would
            # leak the folder layout into the (decrypted) log and break
            # marker matching after the folder moves
            orig_name = os.path.basename(base)
            src = None              # never referenced on the leftover path
        else:
            src = os.path.join(log_dir, name)
            dst = src[:-4] + ".hlog"
            migrating = src + ".migrating"
            orig_name = name
        tmp = dst + ".mig"
        try:
            if is_leftover:
                if not os.path.exists(migrating):
                    continue        # vanished since listdir; nothing to do
                total += 1          # leftovers count like fresh sources
            else:
                # a .log whose claim still exists (unfinished leftover
                # pass above) is skipped THIS run — the second rename
                # must not clobber the existing claim
                if os.path.exists(migrating):
                    continue
                total += 1
                # claim first: locked source -> rename fails -> skip,
                # write nothing (a crash after this point leaves a
                # finishable .migrating file, handled on the next run
                # as a leftover entry). A fresh local (not the branch-
                # shared `src`, which is None on the leftover path) keeps
                # the rename provably str-typed.
                os.replace(os.path.join(log_dir, name), migrating)
            with open(migrating, "rb") as fh:
                raw = fh.read()
            src_sha = hashlib.sha256(raw).hexdigest()   # over the RAW bytes

            # read the existing .hlog FIRST and settle the leftover-marker
            # case BEFORE any decode/encrypt work — a claim whose merge
            # already happened needs neither (reordering per review)
            existing = []
            if os.path.exists(dst):
                with open(dst, "r", encoding="utf-8", errors="replace") as fh:
                    existing = fh.read().splitlines()
                if is_leftover and _has_marker(existing, src_sha):
                    # merge already happened on an earlier run — just
                    # finish the claim cleanup
                    os.remove(migrating)
                    converted += 1
                    continue
                if existing and not existing[-1].strip():
                    existing = existing[:-1]   # drop trailing blank for join

            text = _decode_legacy(raw)
            had_trailing_nl = text.endswith("\n")
            lines = text.split("\n")
            if had_trailing_nl:
                lines = lines[:-1]

            out = []
            for ln in lines:
                if ln.endswith("\r"):
                    ln = ln[:-1]      # normalize CRLF from Windows text files
                if not ln.strip() or ln.startswith(LOG_MAGIC):
                    out.append(ln)          # blanks / already-encrypted stay
                    continue
                out.append(encrypt_line(ln))

            # idempotency marker: last line of the migrated block
            marker = encrypt_line(
                f"# migrated {orig_name} sha256={src_sha}")
            combined = existing + out + [marker]
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(combined) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dst)
            # claim file is deleted LAST — after the encrypted copy is
            # durable. If this delete fails (AV lock), the leftover
            # .migrating is finished on the next run via the marker.
            os.remove(migrating)
            converted += 1
        except Exception:  # noqa: BLE001 — migration must never crash startup
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
    return (converted, total)


def _has_marker(lines, src_sha):
    """True when one of the (encrypted) .hlog lines decrypts to an
    idempotency marker carrying the same source-file sha256."""
    for ex in lines:
        v = decrypt_line(ex)
        # is_marker(v) implies v is a plain str (UNREADABLE/None are
        # falsy/non-str) — but proving that to a checker needs the str
        # test spelled out here too
        if isinstance(v, str) and is_marker(v) and \
                _MARKER_RE.match(v.strip()).group(1) == src_sha:
            return True
    return False


# ------------------------------------------------- plaintext hygiene sweep
_SWEEP_FILES = ("winhttp_backup.txt",)   # legacy SNIper-era leftovers


def sweep_plaintext(app_dir):
    """Delete known plaintext leftovers the current code never reads.

    Threat model: an infostealer bulk-copies folders and greps them. Every
    plaintext byte HookIP ever wrote still lying around is a free find even
    after everything else is encrypted. Best-effort, never raises; returns
    the basenames it removed (for the session log).

    Currently swept:
    - winhttp_backup.txt        (older version's plaintext winhttp dump)
    - settings.json.*.tmp       (stale atomic-save temp files; encrypted
                                 content, but hygiene)
    - %TEMP% hookip_toast_*.ps1 (toast scripts older than 24 h; new ones
                                 self-delete after running)
    """
    import glob as _glob
    import time as _time
    removed = []
    for name in _SWEEP_FILES:
        p = os.path.join(app_dir, name)
        try:
            if os.path.isfile(p):
                os.remove(p)
                removed.append(name)
        except OSError:
            pass
    try:
        for p in _glob.glob(os.path.join(app_dir, "settings.json.*.tmp")):
            try:
                os.remove(p)
                removed.append(os.path.basename(p))
            except OSError:
                pass
    except OSError:
        pass
    try:
        tmpdir = os.environ.get("TEMP") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local", "Temp")
        day_ago = _time.time() - 86400
        for p in _glob.glob(os.path.join(tmpdir, "hookip_toast_*.ps1")):
            try:
                if os.path.getmtime(p) < day_ago:
                    os.remove(p)
                    removed.append(os.path.basename(p))
            except OSError:
                pass
    except OSError:
        pass
    return removed

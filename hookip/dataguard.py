"""Data-theft guard: encrypts everything sensitive HookIP keeps on disk.

Threat: malware running on this machine bulk-copies folders (browsers,
apps, %LOCALAPPDATA%) looking for browsing history, site lists and
saved settings. HookIP's log files ARE a browsing history and
settings.json IS a list of bypassed sites — in plaintext, both are a
bounty for that scan.

Guard, in layers (all stdlib/ctypes, still no admin):
1. LOG ENCRYPTION (DPAPI): every session log line is encrypted
   individually (CryptProtectData, user scope + app entropy) before it
   touches disk. A copied .hlog file is opaque base64 blobs — no
   domains, no verdicts, nothing to grep. Lines stay appendable, so
   logging keeps working exactly as before.
2. SETTINGS ENCRYPTION: settings.json is encrypted whole. A plaintext
   file found at load (older version / manual edit) is honored once and
   re-encrypted on the next save.
3. FOLDER ACL HARDENING: the HookIP data directory's inherited ACEs
   are stripped and access is granted to the current user's SID and
   SYSTEM (both as *SID, not account names, so domain-joined and
   Microsoft-account machines resolve unambiguously). Malware running
   as a different (non-admin) account or at low integrity gets nothing.
4. MIGRATION: at startup, any legacy plaintext .log files left by older
   versions are encrypted in place and renamed .hlog. An existing
   .hlog target is never overwritten — new lines are appended to it
   (atomically) — and the source .log is deleted only after the
   encrypted write has succeeded.

Honest limits (stated in Diagnostics too): a determined attacker
running as YOUR user account with full access can reverse DPAPI — no
user-space app can stop that. This guard defeats bulk folder-theft,
cross-account snooping and anything that exfiltrates files to read
elsewhere. Antivirus/Defender stays the wall for live malware.

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
import os
import subprocess
from ctypes import wintypes

# app-specific entropy so a raw DPAPI blob dumped from another app's
# context cannot be replayed against HookIP files blindly
_ENTROPY = b"HookIP-dataguard-v1"

# file magic prefixes: identify guarded formats at a glance
LOG_MAGIC = "HKLOG1:"
CFG_MAGIC = "HKCFG1:"

# sentinel: the line IS ours (HKLOG1:) but the blob failed to decrypt
# (truncated, corrupted, or re-encrypted under a different account)
UNREADABLE = object()


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


# ---- ctypes declarations: no pointer truncation, no GC accidents ----
_crypt32 = ctypes.WinDLL("crypt32") if hasattr(ctypes, "WinDLL") else ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32

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

_advapi32 = ctypes.windll.advapi32
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

# entropy blob built ONCE and kept referenced for the process lifetime:
# the DATA_BLOB points into _ENTROPY_BUF, so the buffer backing the
# pointer can never be garbage-collected mid-call
_ENTROPY_BUF = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
_ENTROPY_BLOB = _DATA_BLOB(
    len(_ENTROPY), ctypes.cast(_ENTROPY_BUF, ctypes.POINTER(ctypes.c_char)))


def _blob(data):
    """Return (DATA_BLOB, backing_buffer) — keep the buffer referenced
    until the C call has returned."""
    data = bytes(data)
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _crypt(data, decrypt):
    pin, keep_in = _blob(data)
    pout = _DATA_BLOB()
    if decrypt:
        ok = _crypt32.CryptUnprotectData(ctypes.byref(pin), None,
                                         ctypes.byref(_ENTROPY_BLOB),
                                         None, None, 0, ctypes.byref(pout))
    else:
        ok = _crypt32.CryptProtectData(ctypes.byref(pin), None,
                                       ctypes.byref(_ENTROPY_BLOB),
                                       None, None, 0, ctypes.byref(pout))
    if not ok:
        raise OSError("CryptProtectData/CryptUnprotectData failed")
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
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise TypeError(f"encrypt_line expects str, got {type(text).__name__}")
    blob = _crypt(text.encode("utf-8"), decrypt=False)
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
    """Whole-file payload -> 'HKCFG1:<base64 dpapi blob>' as str."""
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
                _cached_sid = ctypes.wstring_at(sid_str)
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
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        return r.returncode == 0
    except Exception:
        return False


def acl_is_hardened(path):
    """True when the directory's own ACE lines carry no '(I)'
    inheritance flag.

    Locale-independent: '(I)' is icacls's symbolic inheritance marker
    and is not localized; we check only the ACE lines (everything after
    the path header line) so a *file name* containing '(I)' cannot
    trigger a false 'inherited'. Limitation: this is a report-parse
    heuristic — icacls gives no structured API without admin — and it
    assumes icacls prints the path on the first line and ACEs beneath
    it, which holds on Windows 7 through 11.
    """
    try:
        r = subprocess.run(["icacls", path], capture_output=True, text=True,
                           timeout=10,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        if r.returncode != 0:
            return False
        lines = (r.stdout or "").splitlines()
        ace_lines = lines[1:]          # line 0 is the path header
        return not any("(I)" in ln for ln in ace_lines)
    except Exception:
        return False


# --------------------------------------------------------- migration
def migrate_plaintext_logs(log_dir):
    """Encrypt legacy .log files (older versions wrote plaintext).

    Each file: read BINARY, decode UTF-8 with a latin-1 fallback (so
    non-UTF-8 bytes survive instead of being 'replace'-altered), split
    on "\\n" only (splitlines() would also break on \\x0c/\\x1c-\\x1e
    page/separator controls), encrypt line-by-line.

    An existing foo.hlog target is NEVER overwritten (an interrupted
    earlier run or a newer version may already be writing it): the
    newly encrypted lines are merged into a rewritten copy of the
    existing .hlog via temp + os.replace. The source .log is deleted
    only after the encrypted write has succeeded.

    Returns (converted, total). Best-effort; locked files are skipped.
    """
    if not os.path.isdir(log_dir):
        return (0, 0)
    converted = total = 0
    try:
        names = [n for n in os.listdir(log_dir) if n.endswith(".log")]
    except OSError:
        return (0, 0)
    for name in names:
        src = os.path.join(log_dir, name)
        dst = src[:-4] + ".hlog"
        tmp = dst + ".mig"
        total += 1
        try:
            with open(src, "rb") as fh:
                raw = fh.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1")
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

            # merge with any existing .hlog (never clobber its content)
            existing = []
            if os.path.exists(dst):
                try:
                    with open(dst, "r", encoding="utf-8",
                              errors="replace") as fh:
                        existing = fh.read().splitlines()
                except OSError:
                    existing = []
                if existing and existing[-1].startswith(LOG_MAGIC) is False \
                        and existing[-1].strip() == "":
                    existing = existing[:-1]   # drop trailing blank for join

            combined = existing + out
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(combined) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dst)
            # source is removed only after the encrypted copy is durable
            os.remove(src)
            converted += 1
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
    return (converted, total)

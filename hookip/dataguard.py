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
   versions are encrypted and merged into .hlog files. The source .log
   is claimed first by renaming it to foo.log.migrating (a locked file
   is skipped without writing anything), the claim file is deleted
   last, a leftover foo.log.migrating from a crashed run is finished on
   the next run, and each merge writes ONE encrypted idempotency marker
   ("# migrated <name> sha256=<hex>") as the last line of the migrated
   block — a rerun scans the .hlog for that marker and skips the merge
   if the same source file was already migrated, so no duplicates and
   an existing .hlog is never overwritten.

Honest limits (stated in Diagnostics too): a determined attacker
running as YOUR user account with full access can reverse DPAPI — no
user-space app can stop that. This guard defeats bulk folder-theft,
cross-account snooping and anything that exfiltrates files to read
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
import subprocess
from ctypes import wintypes

# app-specific entropy so a raw DPAPI blob dumped from another app's
# context cannot be replayed against HookIP files blindly
_ENTROPY = b"HookIP-dataguard-v1"

# file magic prefixes: identify guarded formats at a glance
LOG_MAGIC = "HKLOG1:"
CFG_MAGIC = "HKCFG1:"

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
                                         None, None,
                                         _CRYPTPROTECT_UI_FORBIDDEN,
                                         ctypes.byref(pout))
    else:
        ok = _crypt32.CryptProtectData(ctypes.byref(pin), None,
                                       ctypes.byref(_ENTROPY_BLOB),
                                       None, None,
                                       _CRYPTPROTECT_UI_FORBIDDEN,
                                       ctypes.byref(pout))
    if not ok:
        # use_last_error=True on _crypt32 makes get_last_error() valid
        # here; the real error code lands in Diagnostics
        raise OSError(f"DPAPI {'CryptUnprotectData' if decrypt else 'CryptProtectData'}"
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
                # as a leftover entry)
                os.replace(src, migrating)
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
        if is_marker(v) and _MARKER_RE.match(v.strip()).group(1) == src_sha:
            return True
    return False

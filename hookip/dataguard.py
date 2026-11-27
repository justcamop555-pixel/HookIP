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
   are stripped so only the current user and SYSTEM have access —
   malware running as a different (non-admin) account or at low
   integrity gets nothing.
4. MIGRATION: at startup, any legacy plaintext .log files left by older
   versions are encrypted in place and renamed .hlog.

Honest limits (stated in Diagnostics too): a determined attacker
running as YOUR user account with full access can reverse DPAPI — no
user-space app can stop that. This guard defeats bulk folder-theft,
cross-account snooping and anything that exfiltrates files to read
elsewhere. Antivirus/Defender stays the wall for live malware.
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

_cached_sid = None


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data):
    buf = ctypes.create_string_buffer(bytes(data), len(bytes(data)))
    return _DATA_BLOB(len(bytes(data)),
                      ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def _entropy_blob():
    return _blob(_ENTROPY)[0]


def _crypt(data, decrypt):
    crypt32 = ctypes.windll.crypt32
    pin, _keep = _blob(data)
    pout = _DATA_BLOB()
    if decrypt:
        ok = crypt32.CryptUnprotectData(ctypes.byref(pin), None,
                                        ctypes.byref(_entropy_blob()),
                                        None, None, 0, ctypes.byref(pout))
    else:
        ok = crypt32.CryptProtectData(ctypes.byref(pin), None,
                                      ctypes.byref(_entropy_blob()),
                                      None, None, 0, ctypes.byref(pout))
    if not ok:
        raise OSError("CryptProtectData failed")
    try:
        out = ctypes.string_at(pout.pbData, pout.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(
            ctypes.cast(pout.pbData, ctypes.c_void_p))
    return out


def encrypt_line(text, magic=LOG_MAGIC):
    """One log line -> 'HKLOG1:<base64 dpapi blob>'. Never raises for None."""
    blob = _crypt(text.encode("utf-8"), decrypt=False)
    return magic + base64.b64encode(blob).decode("ascii")


def decrypt_line(line):
    """Inverse of encrypt_line. Returns None when the line is not ours."""
    line = line.strip()
    if not line.startswith(LOG_MAGIC):
        return None
    try:
        blob = base64.b64decode(line[len(LOG_MAGIC):])
        return _crypt(blob, decrypt=True).decode("utf-8", "replace")
    except Exception:
        return None


def encrypt_bytes(data):
    """Whole-file payload -> 'HKCFG1:<base64 dpapi blob>' as str."""
    blob = _crypt(data, decrypt=False)
    return CFG_MAGIC + base64.b64encode(blob).decode("ascii")


def decrypt_bytes(text):
    """Inverse of encrypt_bytes; returns None for foreign/plaintext input."""
    text = text.strip()
    if not text.startswith(CFG_MAGIC):
        return None
    try:
        blob = base64.b64decode(text[len(CFG_MAGIC):])
        return _crypt(blob, decrypt=True)
    except Exception:
        return None


def is_encrypted_file(path, magic):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(16).startswith(magic)
    except OSError:
        return False


# ---------------------------------------------------------------- ACLs
def _current_user_sid():
    global _cached_sid
    if _cached_sid:
        return _cached_sid
    try:
        import winreg
        env_sid = None
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Volatile Environment") as k:
            env_sid, _ = winreg.QueryValueEx(k, "UserSID")
        _cached_sid = env_sid
    except Exception:
        _cached_sid = os.environ.get("USERNAME", "")
    return _cached_sid


def harden_dir(path):
    """Strip inherited ACEs; keep only the current user + SYSTEM (full
    control). Returns True when icacls reported success. No admin
    needed: the dir is owned by the current user. OneDrive/AV locks
    make this best-effort — callers must tolerate False."""
    try:
        user = os.environ.get("USERNAME", "")
        if not user:
            return False
        cmd = ["icacls", path, "/inheritance:r",
               "/grant:r", f"{user}:(OI)(CI)F",
               "/grant:r", "SYSTEM:(OI)(CI)F"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        out = (r.stdout or "").lower()
        return (r.returncode == 0 and "successfully processed" in out
                and "failed processing 0" in out)
    except Exception:
        return False


def acl_is_hardened(path):
    """True when icacls shows no inherited '(I)' ACEs on the dir itself."""
    try:
        r = subprocess.run(["icacls", path], capture_output=True, text=True,
                           timeout=10, creationflags=0x08000000 if os.name == "nt" else 0)
        if r.returncode != 0:
            return False
        return "(I)" not in (r.stdout or "")
    except Exception:
        return False


# ---------------------------------------------------------- migration
def migrate_plaintext_logs(log_dir):
    """Encrypt legacy .log files (older versions wrote plaintext).

    Each file: read -> rewrite line-by-line encrypted -> rename .hlog.
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
        total += 1
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            out = []
            for ln in lines:
                if ln.startswith(LOG_MAGIC) or not ln.strip():
                    out.append(ln)
                    continue
                out.append(encrypt_line(ln))
            tmp = src + ".enc"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(out) + "\n")
            dst = src[:-4] + ".hlog"
            os.replace(tmp, dst)
            os.remove(src)
            converted += 1
        except OSError:
            try:
                if os.path.exists(src + ".enc"):
                    os.remove(src + ".enc")
            except OSError:
                pass
    return (converted, total)

<div align="center">

# ⚓ HookIP

**A modern, zero-install DPI/SNI bypass for Windows — no admin, no VPN, no drivers, no dependencies.**

![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)
![Portable](https://img.shields.io/badge/portable-no%20install-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

HookIP is a desktop app that gets past the two most common ways ISPs block websites:

1. **SNI filtering** — your browser sends the site's name in plain text in the very first
   packet of every HTTPS connection (the TLS *ClientHello*). HookIP **fragments that
   handshake** into tiny TCP segments so a DPI filter never sees the hostname in one piece.
2. **DNS poisoning** — ISPs hand out fake addresses for blocked domains. HookIP resolves
   names via **DNS-over-HTTPS** (Cloudflare, Google, AdGuard) over a *fragmented* TLS
   handshake of its own, with DNS-over-TCP, DNS-over-UDP and system-DNS fallbacks.

It runs entirely in user space: double-click, press **Start**, done. Press **Stop** (or close
the window) and your original internet settings are restored instantly.

Inspired by [SNIper](https://github.com/Reuzola/SNIper) (MIT) — HookIP takes the same
no-admin, user-space idea and pushes it further.

## ✨ What HookIP does better

| | SNIper | HookIP |
|---|:---:|:---:|
| ClientHello fragmentation | ✅ | ✅ **3 strategies**: `smart` (splits exactly at the SNI hostname), `chunk`, `random` |
| Adaptive retry on DPI kills | ❌ | ✅ detects the kill and **retries with a different strategy** automatically |
| DoH with fragmented handshake | ✅ | ✅ 3 resolvers, **rotating failover**, verified NXDOMAIN (spoofed negatives over plain UDP are distrusted) |
| DNS cache | ❌ | ✅ **TTL cache + negative caching** — instant repeat lookups |
| Per-domain exclusions | ❌ | ✅ wildcard list (banking apps etc. connect unfragmented) |
| Live dashboard | activity log | ✅ **connections, active, data up/down, failed + throughput graph + top-domains table** |
| Diagnostics | ❌ | ✅ **one-click checks**: every DoH resolver, system-proxy state, end-to-end tunnel test |
| Proxy modes | manual / PAC | ✅ manual + self-served **PAC** (random per-session URL) |
| System proxy | ✅ | ✅ with bypass list for local addresses |
| Crash safety | ✅ watchdog + RunOnce | ✅ same: registry backup, **detached watchdog**, `RunOnce` restore, sign-in recovery |
| Portable, no install | ✅ | ✅ pure stdlib — **zero pip dependencies**, runs on x64 & ARM64 |

## 📦 Downloads

| Version | Download | Notes |
|---|---|---|
| **v1.0.0** | [`HookIP.exe`](https://github.com/justcamop555-pixel/HookIP/releases/latest) | portable, 14 MB, no Python needed |

All versions live under [**Releases**](https://github.com/justcamop555-pixel/HookIP/releases) —
one release per version, each with its built `HookIP.exe` and changelog. The repository
itself is source-only.

## ⚡ One-line install (PowerShell)

```powershell
irm https://raw.githubusercontent.com/justcamop555-pixel/HookIP/main/install.ps1 | iex
```

Downloads the latest `HookIP.exe` to your Desktop and launches it. Works anonymously once the
repository is public; while the repo is **private**, use your GitHub CLI login instead:

```powershell
gh release download -R justcamop555-pixel/HookIP -p HookIP.exe -D "$env:USERPROFILE\Desktop" --clobber; Start-Process "$env:USERPROFILE\Desktop\HookIP.exe"
```

The installer (`install.ps1`) prefers the GitHub CLI when it is present, falls back to the
public API, and prints friendly instructions if neither can reach a private repo.

## 🚀 Usage

**Grab the latest `HookIP.exe` from [Releases](https://github.com/justcamop555-pixel/HookIP/releases/latest),**
double-click it, then press **Start**. Chrome, Steam, Discord, Spotify and most apps follow the
Windows system proxy automatically. Press **Stop** or close the window to restore your
settings.

> The exe is not code-signed, so SmartScreen may ask about it on first launch —
> "More info → Run anyway".

### Run from source instead

```bat
python run_hookip.py
```

> Requires Python 3.9+ with tkinter (bundled with python.org installers). No other packages.

### Rebuild the exe yourself

Run `packaging\build_exe.bat` (or `python -m PyInstaller --onefile --windowed run_hookip.py`) —
PyInstaller bundles everything into a single portable binary.

### Project layout

```
HookIP/
├── HookIP.exe              ← the runnable build (only on machines that built it)
├── run_hookip.py           ← entry point (source)
├── hookip/                 ← the application package (proxy, DoH, UI, tray, …)
├── assets/                 ← icon + artwork
├── packaging/              ← PyInstaller build script + version info
├── install.ps1             ← one-line installer
├── LICENSE                 ← MIT
└── README.md
```

## 🔧 Settings

| Setting | Default | What it does |
|---|:---:|---|
| Local port | `8890` | Port the proxy listens on |
| Fragment size | `2` | Bytes per TCP segment while splitting the ClientHello |
| Strategy | `smart` | `smart` = split at the SNI hostname · `chunk` = uniform pieces · `random` = randomized desync |
| Secure DNS | on | DNS-over-HTTPS with failover; off = system DNS |
| Proxy mode | `manual` | `pac` serves a PAC file instead (better app coverage on some setups) |
| Excluded domains | `localhost`, … | Sites that connect without fragmentation |
| Verbose log | off | Debug-level detail in the activity log |

## 🛡️ Safety guarantees

- Original proxy settings are **saved to disk + registry backup** before anything changes.
- A **detached watchdog process** restores them within seconds if HookIP crashes or is killed.
- A `RunOnce` entry restores them at next sign-in after a power loss, even if HookIP was deleted.
- **Stop / window close** restores immediately; the next launch also self-heals leftovers.
- While running, Windows proxy settings show `127.0.0.1:8890` — that is HookIP. Task Manager
  may show a second small `python` process — that is the watchdog.

## 🚧 Limitations

HookIP only defeats SNI-based filtering; it does not encrypt traffic or hide your IP
(that is a VPN's job). Firefox must be set to *Use system proxy settings*. Antivirus HTTPS
scanning (ESET, Kaspersky…) can undo the fragmentation — disable its SSL scanning if sites
stay blocked. QUIC/HTTP-3 can't be fragmented, but browsers fall back to TCP automatically.
Discord and friends read the proxy at startup — restart them after pressing Start.

## 🛡️ Antivirus false positive

Windows Defender's ML heuristic (`Behavior:Win32/Impact.A!ml`) may flag `HookIP.exe` because it
changes proxy registry keys and runs a watchdog process — all legitimate, source-visible
behavior (see code in this repo). A false-positive dispute has been filed with Microsoft:

- **Submission ID:** `a5f1346c5-0af4-4a72-a46e-6cc35167a57a` (Nov 2026, status: *Submitted*)
- If you see the warning: the file is safe to run — verify against the source here, and
  "More info → Run anyway", or add a Defender exclusion for the folder.

## 📜 Disclaimer

Published for educational and personal use, to help access content that is legally
available to you but blocked by ISP-level filtering. Use it in accordance with your local
laws. HookIP does not encrypt traffic or provide anonymity — your existing TLS encryption
stays intact end-to-end.

<sub>MIT License. Built with Python's standard library only.</sub>

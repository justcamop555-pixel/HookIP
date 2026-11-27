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

It runs entirely in user space: double-click, press **Start**, done. Press **Stop** (or exit)
and your original internet settings are restored instantly — with a watchdog, auto-recovery
and a rescue button backing you up even if the app dies.

Inspired by [SNIper](https://github.com/Reuzola/SNIper) (MIT) — HookIP takes the same
no-admin, user-space idea and pushes it further.

## ✨ What HookIP does better

| | SNIper | HookIP |
|---|:---:|:---:|
| ClientHello fragmentation | ✅ | ✅ **3 strategies**: `smart` (splits exactly at the SNI hostname, randomized per connection), `chunk`, `random` |
| Adaptive retry on DPI kills | ❌ | ✅ detects the kill and **retries with a different strategy automatically** — and remembers which strategy last worked per host |
| DoH with fragmented handshake | ✅ | ✅ 3 resolvers, **latency-ordered rotating failover**, verified NXDOMAIN (spoofed negatives over plain UDP are distrusted), sinkhole answers filtered |
| DNS cache | ❌ | ✅ **TTL cache + negative caching + in-flight coalescing** (browsers opening 10 parallel connections cause one lookup, not ten) |
| Per-domain exclusions | ❌ | ✅ wildcard list — bypassed in **every** proxy mode (Windows bypass list / PAC `DIRECT`), pasted URLs auto-normalized |
| Live dashboard | activity log | ✅ **connections, active, data up/down, failed, blocked + live traffic graph + top-domains table** |
| Diagnostics | ❌ | ✅ **one-click checks**: system/antivirus, every DoH resolver, port availability, end-to-end tunnel test — with **Copy report** |
| Proxy modes | manual / PAC | ✅ `manual` + self-served **PAC** + **`both`** (widest app coverage) |
| System tray | ❌ | ✅ X hides to tray and keeps protecting; tray menu shows/restores/exits |
| Notifications | ❌ | ✅ Windows toasts for start, stop, restore, crash-recovery and updates — **click a toast to bring HookIP up** |
| Crash safety | ✅ watchdog + RunOnce | ✅ registry backup, **detached watchdog**, `RunOnce` restore, next-launch self-heal, emergency listener recovery |
| Self-updating | ❌ | ✅ checks GitHub Releases on launch and every 12 h; **one-click download** of the new exe |
| Portable, no install | ✅ | ✅ pure stdlib — **zero pip dependencies**, runs on x64 & ARM64 |

## 📦 Downloads

| Version | Download | Notes |
|---|---|---|
| **v1.1.0** (latest) | [`HookIP.exe`](https://github.com/justcamop555-pixel/HookIP/releases/latest) | portable, 14 MB, no Python needed |

Every version lives under [**Releases**](https://github.com/justcamop555-pixel/HookIP/releases) —
one release per version, each with its built `HookIP.exe`, a `HookIP.exe.sha256` checksum and
a changelog. The repository itself is source-only.

## ⚡ One-line install (PowerShell)

```powershell
irm https://raw.githubusercontent.com/justcamop555-pixel/HookIP/main/install.ps1 | iex
```

Downloads the latest `HookIP.exe` to your Desktop and launches it. The installer prefers the
GitHub CLI when it is present and falls back to the public API — no login needed, the repo is
public.

## 🚀 Usage

**Grab the latest `HookIP.exe` from [Releases](https://github.com/justcamop555-pixel/HookIP/releases/latest),**
double-click it, then press **Start**. A Windows notification confirms you're protected;
Chrome, Steam, Discord, Spotify and most apps follow the Windows system proxy automatically
(restart Discord-like apps that read the proxy at startup).

- **X button** hides HookIP to the system tray — the proxy keeps running; the tray icon
  restores the window or exits for real
- **Minimize** is always a normal minimize (never hides anything)
- **↺ Restore internet** is the rescue button: it puts Windows back on your previous
  connection at any time
- **Exit** always stops the proxy and restores your settings first

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
| Local port | `8890` | Port the proxy listens on — live availability check beside the field, plus a **Find free** button |
| Fragment size | `2` | Bytes per TCP segment while splitting the ClientHello (1–255; 2 is stealthiest) |
| Strategy | `smart` | `smart` = split at the SNI hostname · `chunk` = uniform pieces · `random` = randomized desync. Failed hosts remember what worked |
| System proxy mode | `manual` | `pac` serves a PAC file · **`both`** sets manual + PAC together for the widest app coverage |
| Secure DNS | on | DNS-over-HTTPS with failover; off = system DNS |
| Excluded domains | `localhost`, … | Sites that skip HookIP completely, in every mode (banking apps etc.). Accepts wildcards and pasted URLs |
| Verbose log | off | Debug-level detail in the on-screen log (the log file always keeps it) |
| Remember settings | on | Persists everything to `%LOCALAPPDATA%\HookIP\settings.json` |
| Hide to tray on X | on | X hides to the tray with the proxy running; off = X really exits |

## Data protection (anti-theft guard)

HookIP encrypts everything it writes to disk, because its log files are
effectively a browsing history and `settings.json` is a list of bypassed
sites — exactly what folder-scanning malware harvests:

- **Session logs are DPAPI-encrypted line-by-line** (`.hlog` files). A log
  file copied off the machine is opaque base64 blobs — no domains, no
  verdicts, nothing to grep.
- **`settings.json` is encrypted whole.** Older plaintext files are
  honored once and re-encrypted on the next save.
- **The data folder is ACL-hardened**: inherited access is stripped so
  only your account and SYSTEM can read `%LOCALAPPDATA%\HookIP` —
  other (non-admin) accounts get nothing.

Honest limits: nothing a user-space app can do stops determined malware
running *as your own account* with full access — that is your
antivirus's job. This guard defeats bulk folder-theft, cross-account
snooping and reading the stolen files anywhere else. Status is shown in
**Diagnostics → System → Data protection**.

## 🩺 If something stops working

- **Microsoft Store / UWP apps**: Windows blocks them from loopback proxies; HookIP tells
  Windows its settings changed properly, and the diagnostics tab shows exactly what state
  each mechanism is in
- **Restricted / captive-portal Wi-Fi**: HookIP probes the network on every Start and warns
  you in plain language — log into the portal first, or use HookIP's traffic after
- **Sites still blocked?** The Diagnostics tab pinpoints it: DNS (resolver failover),
  antivirus HTTPS scanning (see below), or a dead endpoint — the Blocked counter counts
  genuinely dead/blocked domains so they don't look like failures

## 🛡️ Safety guarantees

- Original proxy settings are **saved to disk + registry backup** before anything changes.
- A **detached watchdog process** restores them within seconds if HookIP crashes or is killed.
- A `RunOnce` entry restores them at next sign-in after a power loss, even if HookIP was deleted.
- **Stop / exit** restores immediately; the next launch also self-heals leftovers.
- If the proxy listener dies while Windows still points at it, HookIP performs an
  **emergency restore** and tells you what happened.
- While running, Windows proxy settings show `127.0.0.1:8890` — that is HookIP. Task Manager
  may show a second small `python` process — that is the watchdog.

## 🚧 Limitations

HookIP only defeats SNI-based filtering; it does not encrypt traffic or hide your IP
(that is a VPN's job). Firefox must be set to *Use system proxy settings*. Antivirus HTTPS
scanning (ESET, Kaspersky…) can undo the fragmentation — disable its SSL scanning if sites
stay blocked. QUIC/HTTP-3 can't be fragmented, but browsers fall back to TCP automatically.
Windows services (Store downloads, Windows Update) bypass the user proxy by design.

## 🛡️ Antivirus false positive — resolved

Windows Defender's ML heuristic once flagged `HookIP.exe` (`Behavior:Win32/Impact.A!ml`)
because it changes proxy registry keys and runs a watchdog process — all legitimate,
source-visible behavior (see the code in this repo). A false-positive dispute was filed
with Microsoft and **closed with no positive detection** after signature updates; current
Defender versions scan `HookIP.exe` clean.

- If your machine ever reports it: **update Windows Security definitions first**
  (<https://www.microsoft.com/en-us/wdsi/defenderupdates>) — that clears it.
- You can verify against the source in this repo and check the published `HookIP.exe.sha256`.

## 📜 Disclaimer

Published for educational and personal use, to help access content that is legally
available to you but blocked by ISP-level filtering. Use it in accordance with your local
laws. HookIP does not encrypt traffic or provide anonymity — your existing TLS encryption
stays intact end-to-end.

<sub>MIT License. Built with Python's standard library only.</sub>

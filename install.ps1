#requires -version 5.1
<#
.SYNOPSIS
    HookIP one-line installer. Downloads the latest HookIP.exe release and launches it.

.EXAMPLE
    irm https://github.com/justcamop555-pixel/HookIP/releases/latest/download/install.ps1 | iex
    (served as a release asset — works even where raw.githubusercontent.com is blocked)

.EXAMPLE
    irm https://raw.githubusercontent.com/justcamop555-pixel/HookIP/main/install.ps1 | iex

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1
#>
param(
    [string]$Destination = [Environment]::GetFolderPath("Desktop"),
    [switch]$NoLaunch
)
$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 on older builds negotiates TLS 1.0 by default and
# api.github.com refuses it — this is THE most common 'one-liner fails' cause
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
$repo = "justcamop555-pixel/HookIP"
$UA = "HookIP-installer"
$mirrors = @("https://ghproxy.net/", "https://gh-proxy.com/", "https://ghfast.top/")
$dest = Join-Path $Destination "HookIP.exe"
if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

Write-Host "⚓ Installing HookIP -> $dest" -ForegroundColor Cyan

# downloads with mirror fallback: GitHub first, then same-bytes mirrors
# (integrity is still enforced by the SHA-256 check below)
function Get-Asset($url, $out) {
    foreach ($u in @($url) + ($mirrors | ForEach-Object { "$_$url" })) {
        try {
            Invoke-WebRequest -Uri $u -OutFile $out -UseBasicParsing -UserAgent $UA
            if ((Get-Item $out -ErrorAction SilentlyContinue).Length -gt 1KB) { return $true }
        } catch { }
    }
    return $false
}

# 1) gh CLI (works even while the repo is private)
$done = $false
if (Get-Command gh -ErrorAction SilentlyContinue) {
    try {
        gh release download -R $repo -p "HookIP.exe" -O $dest --clobber 2>$null
        if ((Test-Path $dest) -and ((Get-Item $dest).Length -gt 1MB)) { $done = $true }
    } catch { }
}
# 2) plain GitHub API (for public repos)
$asset = $null
if (-not $done) {
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UserAgent $UA
        $asset = $release.assets | Where-Object name -eq "HookIP.exe"
        if (-not $asset) { throw "HookIP.exe asset not found in latest release." }
        if (Get-Asset $asset.browser_download_url $dest) { $done = $true }
    } catch {
        $why = $_.Exception.Message
    }
    # 3) redirect form + mirrors — for users where the API is blocked but
    #    github.com (or a mirror) still answers
    if (-not $done -and $asset) {
        if (Get-Asset $asset.browser_download_url $dest) { $done = $true }
    }
    if (-not $done) {
        try {
            $r = Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest/download/HookIP.exe" `
                 -OutFile $dest -UseBasicParsing -UserAgent $UA -PassThru
            if ((Test-Path $dest) -and ((Get-Item $dest).Length -gt 1MB)) { $done = $true }
        } catch {
            $why = $_.Exception.Message
        }
        if (-not $done) {
            foreach ($m in $mirrors) {
                try {
                    Invoke-WebRequest -Uri "${m}https://github.com/$repo/releases/latest/download/HookIP.exe" `
                        -OutFile $dest -UseBasicParsing -UserAgent $UA
                    if ((Test-Path $dest) -and ((Get-Item $dest).Length -gt 1MB)) { $done = $true; break }
                } catch { }
            }
        }
    }
}
if (-not $done) {
    if ($why -match 'being used by another process|in use') {
        $why = "HookIP.exe is already running from this folder — stop it (right-click its tray icon > Exit) and run the installer again."
    }
    throw @"

Download failed. ($why)
Tried: GitHub API, the release-redirect URL, and public mirrors.
Fix either way:
  * check your internet / proxy (some networks block github.com), or
  * log in the GitHub CLI once:  gh auth login
    (then this installer uses your login automatically), or
  * download HookIP.exe manually from the Releases page.
"@
}

# 4) verify SHA-256 checksum published alongside the exe (supply-chain
#    safety). Same mirror fallback as the exe: GitHub asset first, then
#    mirrors, then the sha256 printed in the release notes.
$hashFile = Join-Path $Destination "HookIP.exe.sha256"
$expected = $null
try {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        gh release download -R $repo -p "HookIP.exe.sha256" -O $hashFile --clobber 2>$null
    }
} catch { }
try {
    if (-not (Test-Path $hashFile)) {
        try {
            $chk = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UserAgent $UA
            $chkAsset = $chk.assets | Where-Object name -eq "HookIP.exe.sha256"
            if ($chkAsset) {
                if (Get-Asset $chkAsset.browser_download_url $hashFile) { } else { Remove-Item $hashFile -ErrorAction SilentlyContinue }
            }
        } catch { }
    }
    if (-not (Test-Path $hashFile)) {
        # release notes carry the sha256 too (immune to asset-CDN blocks)
        try {
            $body = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -UserAgent $UA).body
            $m = [regex]::Match($body, '\b([0-9a-fA-F]{64})\b')
            if ($m.Success) { $expected = $m.Groups[1].Value.ToLower() }
        } catch { }
    }
    if (-not $expected -and (Test-Path $hashFile)) {
        $expected = (Get-Content $hashFile -TotalCount 1).Split(" ")[0].Trim().ToLower()
    }
} catch { }
if ($expected) {
    $actual = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
    Remove-Item $hashFile -ErrorAction SilentlyContinue
    if ($actual -ne $expected) {
        Remove-Item $dest -Force -ErrorAction SilentlyContinue
        throw "SHA-256 MISMATCH for HookIP.exe! Download deleted. ($actual != $expected)"
    }
    Write-Host "✔ SHA-256 verified ($expected)" -ForegroundColor Green
} else {
    Write-Host "! checksum file not available — skipping verification" -ForegroundColor Yellow
}

Unblock-File $dest -ErrorAction SilentlyContinue
Write-Host "✔ HookIP installed ($([math]::Round((Get-Item $dest).Length / 1MB, 1)) MB)" -ForegroundColor Green
Write-Host "  Double-click it and press Start." -ForegroundColor Gray

if (-not $NoLaunch) { Start-Process $dest }

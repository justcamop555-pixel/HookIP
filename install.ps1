#requires -version 5.1
<#
.SYNOPSIS
    HookIP one-line installer. Downloads the latest HookIP.exe release and launches it.

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
$repo = "justcamop555-pixel/HookIP"
$dest = Join-Path $Destination "HookIP.exe"
if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

Write-Host "⚓ Installing HookIP -> $dest" -ForegroundColor Cyan

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
        $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
        $asset = $release.assets | Where-Object name -eq "HookIP.exe"
        if (-not $asset) { throw "HookIP.exe asset not found in latest release." }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest -UseBasicParsing
        $done = $true
    } catch {
        $why = $_.Exception.Message
        if ($why -match 'being used by another process|in use') {
            $why = "HookIP.exe is already running from this folder — stop it (right-click its tray icon > Exit) and run the installer again."
        }
        throw @"

Download failed. ($why)
The repository is private, so anonymous downloads don't work.
Fix either way:
  * make the repo public (GitHub -> Settings -> Change visibility), or
  * log in the GitHub CLI once:  gh auth login
    (then this installer uses your login automatically)
"@
    }
}

# 3) verify SHA-256 checksum published alongside the exe (supply-chain safety)
$hashFile = Join-Path $Destination "HookIP.exe.sha256"
$expected = $null
try {
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        gh release download -R $repo -p "HookIP.exe.sha256" -O $hashFile --clobber 2>$null
    }
    if (-not (Test-Path $hashFile) -and $asset) {
        $chk = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
        $chkAsset = $chk.assets | Where-Object name -eq "HookIP.exe.sha256"
        if ($chkAsset) { Invoke-WebRequest -Uri $chkAsset.browser_download_url -OutFile $hashFile -UseBasicParsing }
    }
    if (Test-Path $hashFile) {
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

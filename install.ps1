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
if (-not $done) {
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
        $asset = $release.assets | Where-Object name -eq "HookIP.exe"
        if (-not $asset) { throw "HookIP.exe asset not found in latest release." }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dest -UseBasicParsing
    } catch {
        throw @"

Download failed. The repository is private, so anonymous downloads don't work.
Fix either way:
  * make the repo public (GitHub -> Settings -> Change visibility), or
  * log in the GitHub CLI once:  gh auth login
    (then this installer uses your login automatically)
"@
    }
}

Unblock-File $dest -ErrorAction SilentlyContinue
Write-Host "✔ HookIP installed ($([math]::Round((Get-Item $dest).Length / 1MB, 1)) MB)" -ForegroundColor Green
Write-Host "  Double-click it and press Start." -ForegroundColor Gray

if (-not $NoLaunch) { Start-Process $dest }

# Irongrid DNS — one-line Windows installer
#
#   irm https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.ps1 | iex
#
# Downloads the latest release binary for your architecture, verifies its
# SHA-256 checksum, and installs it. Optional parameters:
#
#   -Version "v1.0.1"   install a specific release tag (default: latest)
#   -Dir "C:\Tools"     install into a custom directory (default: %LOCALAPPDATA%\Irongrid)
#
param(
  [string]$Version = "",
  [string]$Dir = ""
)

$ErrorActionPreference = "Stop"
$Repo = "eoghan2t9/Irongrid-DNS"

if (-not $Dir) { $Dir = Join-Path $env:LOCALAPPDATA "Irongrid" }

if (-not $Version) {
  Write-Host "==> querying latest release of $Repo ..."
  $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
    -Headers @{ "User-Agent" = "irongrid-installer" }
  $Version = $release.tag_name
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLower()
$Asset = "irongrid-windows-$arch.exe"
$base = "https://github.com/$Repo/releases/download/$Version"
$exe = Join-Path $Dir "irongrid.exe"

Write-Host "==> installing Irongrid DNS $Version ($arch) to $Dir"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Write-Host "==> downloading $Asset ..."
Invoke-WebRequest -Uri "$base/$Asset" -OutFile $exe
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $Dir "SHA256SUMS.txt")

Write-Host "==> verifying SHA-256 checksum ..."
$expected = (Get-Content (Join-Path $Dir "SHA256SUMS.txt") |
  Where-Object { $_ -match [regex]::Escape($Asset) } |
  ForEach-Object { ($_ -split "\s+")[0] } | Select-Object -First 1)
if (-not $expected) { throw "no checksum found for $Asset in SHA256SUMS.txt" }
$actual = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { throw "checksum mismatch - download may be corrupt; refusing to install" }
Write-Host "==> checksum OK ($actual)"

# Add the install dir to the user PATH if missing.
$path = [Environment]::GetEnvironmentVariable("Path", "User")
if ($path -notlike "*$Dir*") {
  [Environment]::SetEnvironmentVariable("Path", "$Dir;$path", "User")
  Write-Host "==> added $Dir to your user PATH (restart your terminal)"
}

Write-Host ""
Write-Host "Installed: $exe"
& $exe -version
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Start Dragonfly (required cache) - e.g. docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonfly/dragonfly"
Write-Host "  2. Run the setup wizard:   $exe install"
Write-Host "  3. Start the server:       $exe -config irongrid.yaml -data data"
Write-Host "  4. Dashboard:              http://localhost:8080"

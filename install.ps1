# Irongrid DNS — one-line Windows installer
#
#   irm https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.ps1 | iex
#
# Downloads the latest release binary for your architecture, verifies its
# SHA-256 checksum, and installs it. In an interactive console the TUI setup
# wizard (`irongrid install`) is then launched and handles the whole install
# itself: the config and the startup task. Non-interactive runs (e.g.
# `irm ... | iex` in CI), -NoWizard, or an existing config keep the script's
# built-in startup-task step instead. The cache is embedded in the binary, so
# there is nothing else to install; an upgrade removes the old Dragonfly
# container if a previous release started one.
# Optional parameters:
#
#   -Version "v1.0.1"   install a specific release tag (default: latest)
#   -Dir "C:\Tools"     install into a custom directory (default: %LOCALAPPDATA%\Irongrid)
#   -NoWizard           skip the interactive setup wizard (TUI)
#   -NoV3               always install the baseline build, even if this CPU
#                        supports the faster GOAMD64=v3 build
#
param(
  [string]$Version = "",
  [string]$Dir = "",
  [switch]$NoWizard,
  [switch]$NoV3
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

# ProcessArchitecture.ToString() returns "X64"/"Arm64", not the "amd64"/
# "arm64" release-asset naming convention (Makefile / release.yml) -
# .ToLower() alone ("x64") does not match any published asset.
$archRaw = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
$arch = switch ($archRaw) {
  "X64"   { "amd64" }
  "Arm64" { "arm64" }
  default { throw "unsupported architecture: $archRaw (Irongrid ships amd64 and arm64 Windows builds)" }
}

# Test-SupportsGOAMD64V3 detects whether this CPU supports the x86-64-v3
# microarchitecture level that Irongrid's "-v3" release binaries are
# compiled for. A wrong "yes" crashes the binary on its very first run, so
# this only returns $true when genuinely confirmed. System.Runtime.
# Intrinsics.X86 (Avx2/Bmi1/Bmi2/Fma/Lzcnt - 5 of the 9 required flags,
# real JIT-verified checks, not a guess) requires .NET Core - i.e.
# PowerShell 7+. Under the default Windows PowerShell 5.1 (.NET Framework,
# what most users get from `irm ... | iex`), that type doesn't exist and
# this falls back to $false rather than guessing via a less reliable
# source (Win32's IsProcessorFeaturePresent only exposes AVX/AVX2, no
# BMI/FMA/LZCNT constants at all - not enough on its own either).
function Test-SupportsGOAMD64V3 {
  if ($arch -ne "amd64") { return $false }
  try {
    return ([System.Runtime.Intrinsics.X86.Avx2]::IsSupported) -and
           ([System.Runtime.Intrinsics.X86.Bmi1]::IsSupported) -and
           ([System.Runtime.Intrinsics.X86.Bmi2]::IsSupported) -and
           ([System.Runtime.Intrinsics.X86.Fma]::IsSupported) -and
           ([System.Runtime.Intrinsics.X86.Lzcnt]::IsSupported)
  } catch {
    return $false
  }
}

$Asset = "irongrid-windows-$arch.exe"
$v3Asset = "irongrid-windows-$arch-v3.exe"
$base = "https://github.com/$Repo/releases/download/$Version"
$exe = Join-Path $Dir "irongrid.exe"
$configFile = Join-Path $Dir "irongrid.yaml"
$dataDir = Join-Path $Dir "data"
$sumsFile = Join-Path $Dir "SHA256SUMS.txt"
$configExists = Test-Path $configFile
# The interactive wizard handles the whole install: the config and the
# startup task. It only runs in a real console with no existing config
# (an existing config is always left untouched).
$wizardRuns = (-not $NoWizard) -and (-not [Console]::IsInputRedirected) -and (-not $configExists)

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# Fetched before picking the asset name (not just after, as before): it's
# also how we know whether this release actually has a -v3 asset for this
# platform, not just whether the CPU could run one (older releases, or a
# release where the v3 build for this platform was skipped, won't have
# one - each platform's v3 build is a separate step in release.yml).
Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsFile
$sums = Get-Content $sumsFile

if ((-not $NoV3) -and (Test-SupportsGOAMD64V3) -and ($sums -match [regex]::Escape($v3Asset))) {
  $Asset = $v3Asset
  Write-Host "==> installing Irongrid DNS $Version ($arch, GOAMD64=v3 build) to $Dir"
} else {
  Write-Host "==> installing Irongrid DNS $Version ($arch) to $Dir"
}

Write-Host "==> downloading $Asset ..."
Invoke-WebRequest -Uri "$base/$Asset" -OutFile $exe

Write-Host "==> verifying SHA-256 checksum ..."
$expected = ($sums |
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

# ---- Upgrades: remove the old Dragonfly container ---------
# Releases before the embedded cache ran Dragonfly in a Docker container. The
# binary's `cleanup-legacy` command removes only the containers the old
# installer created (matched by name and Dragonfly image); the volume with the
# old data is left in place. The wizard does this itself when it runs.
if (-not $wizardRuns) {
  Write-Host ""
  try { & $exe cleanup-legacy } catch { }
}

# ---- Install Irongrid as a Windows scheduled task ---------------
# A plain Go binary does not speak the Windows Service Control Manager
# protocol, so `sc.exe create` leaves it stuck in START_PENDING and SCM
# kills it after ~30s. A scheduled task runs it reliably instead.
# /RL HIGHEST is required: the default config binds 0.0.0.0:53, which a
# LIMITED (filtered-token) task cannot do. The /TR quoting is written to a
# temp .bat and run via cmd /c — PowerShell's native-argument marshalling
# does not reliably preserve schtasks' doubled-quote convention.
# The startup task is also handled by the wizard when it is about to run.
if ($wizardRuns) {
  Write-Host ""
  Write-Host "==> startup task install deferred to the interactive wizard"
} else {
Write-Host ""
Write-Host "==> installing Irongrid as a startup task ..."
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$taskName = "IrongridDNS"
$esc = '\"'
$tr = "$esc$exe$esc -config $esc$configFile$esc -data $esc$dataDir$esc"
$bat = "@echo off`r`n" +
  "schtasks /Create /TN $taskName /TR `"$tr`" /SC ONLOGON /RL HIGHEST /F`r`n" +
  "schtasks /Run /TN $taskName`r`n"
$batFile = Join-Path $env:TEMP "$taskName-install.bat"
Set-Content -Path $batFile -Value $bat -Encoding ASCII
try {
  cmd /c $batFile
  if ($LASTEXITCODE -eq 0) {
    Write-Host "==> IrongridDNS task installed (runs elevated at logon) and started"
  } else {
    Write-Host "!! Could not create the startup task - run this installer as Administrator" -ForegroundColor Yellow
  }
} finally {
  Remove-Item $batFile -Force -ErrorAction SilentlyContinue
}
}

# ---- Interactive setup wizard (TUI) -------------------------
# Launch `irongrid install`, which handles the whole install: the config,
# binary placement and the startup task. It needs a real console:
# when run via `irm ... | iex` stdin is redirected (a pipe), so it is
# skipped. The config path is double-quoted explicitly for PowerShell 5.1's
# native argument passing (paths under %LOCALAPPDATA% can contain spaces).
Write-Host ""
if ($NoWizard) {
  Write-Host "==> setup wizard skipped (-NoWizard)"
} elseif ([Console]::IsInputRedirected) {
  Write-Host "==> no interactive console detected - install finished with defaults"
  Write-Host "    (re-run the wizard anytime with: $exe install)"
} elseif ($configExists) {
  Write-Host "==> config already exists at $configFile - wizard skipped to leave it untouched"
  Write-Host "    (re-run it anytime with: $exe install)"
} else {
  Write-Host "==> launching the interactive setup wizard ..."
  Write-Host "    it handles the config and the startup task"
  & $exe install --config "`"$configFile`"" --data "`"$dataDir`""
  if ($LASTEXITCODE -ne 0) {
    Write-Host "!! wizard did not complete - the config at $configFile may be incomplete" -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Cache and query log are built in (stored under $dataDir\kv)"
if ($wizardRuns) {
  Write-Host "  - The startup task was handled by the wizard"
}
Write-Host "  2. Edit the config:       $configFile"
Write-Host "  3. Re-run the setup wizard anytime:  $exe install"
Write-Host "  4. Dashboard:              http://localhost:8080  (default login: admin / irongrid)"

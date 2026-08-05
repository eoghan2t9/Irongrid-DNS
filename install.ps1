# Irongrid DNS — one-line Windows installer
#
#   irm https://raw.githubusercontent.com/eoghan2t9/Irongrid-DNS/main/install.ps1 | iex
#
# Downloads the latest release binary for your architecture, verifies its
# SHA-256 checksum, and installs it. In an interactive console the TUI setup
# wizard (`irongrid install`) is then launched and handles the whole install
# itself: Dragonfly, the config, and the startup task. Non-interactive runs
# (e.g. `irm ... | iex` in CI), -NoWizard, or an existing config keep the
# script's built-in Dragonfly + startup-task steps instead.
# Optional parameters:
#
#   -Version "v1.0.1"   install a specific release tag (default: latest)
#   -Dir "C:\Tools"     install into a custom directory (default: %LOCALAPPDATA%\Irongrid)
#   -NoWizard           skip the interactive setup wizard (TUI)
#
param(
  [string]$Version = "",
  [string]$Dir = "",
  [switch]$NoWizard
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
$configFile = Join-Path $Dir "irongrid.yaml"
$dataDir = Join-Path $Dir "data"
$configExists = Test-Path $configFile
# The interactive wizard handles the whole install: Dragonfly, the config and
# the startup task. It only runs in a real console with no existing config
# (an existing config is always left untouched).
$wizardRuns = (-not $NoWizard) -and (-not [Console]::IsInputRedirected) -and (-not $configExists)

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

# ---- Dragonfly: the cache Irongrid requires ----------------
# Dragonfly has no native Windows build; it runs in Docker (WSL2 backend).
# When the interactive wizard is about to run, it installs Dragonfly itself.
if ($wizardRuns) {
  Write-Host ""
  Write-Host "==> Dragonfly install deferred to the interactive wizard"
} else {
Write-Host ""
Write-Host "==> installing Dragonfly (required cache) ..."

# If a Redis-compatible server already answers on 6379, just use it.
$existing = $false
try {
  $tcp = New-Object System.Net.Sockets.TcpClient
  $tcp.Connect("127.0.0.1", 6379)
  $stream = $tcp.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)
  $writer.Write("PING`r`n"); $writer.Flush()
  $reader = New-Object System.IO.StreamReader($stream)
  $pong = $reader.ReadLine()
  $tcp.Close()
  if ($pong -like "+PONG*") { $existing = $true }
} catch { }

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "==> a Redis-compatible server already answers on 127.0.0.1:6379 - using it"
  $dflyStarted = $true
} elseif (-not $docker) {
  Write-Host "!! Dragonfly has no native Windows build and Docker was not found." -ForegroundColor Yellow
  Write-Host "   Install Docker Desktop (WSL2 backend): https://www.docker.com/products/docker-desktop/"
  Write-Host "   then run:  docker run -d --name dragonfly --restart unless-stopped -p 127.0.0.1:6379:6379 docker.dragonflydb.io/dragonfly/dragonfly --cache_mode=true --maxmemory=512mb --proactor_threads=2"
} else {
  Write-Host "==> starting Dragonfly in Docker ..."
  docker rm -f dragonfly 2>$null | Out-Null
  docker run -d --name dragonfly --restart unless-stopped `
    -p 127.0.0.1:6379:6379 `
    docker.dragonflydb.io/dragonfly/dragonfly --cache_mode=true --maxmemory=512mb --proactor_threads=2 --port=6379 | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "==> Dragonfly running on 127.0.0.1:6379"
    $dflyStarted = $true
  } else {
    Write-Host "!! Docker failed to start Dragonfly - check that Docker Desktop is running." -ForegroundColor Yellow
  }
}
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
# Launch `irongrid install`, which handles the whole install: Dragonfly, the
# config, binary placement and the startup task. It needs a real console:
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
  Write-Host "    it handles Dragonfly, the config, and the startup task"
  # The wizard installs Dragonfly itself when asked, so --with-dragonfly is
  # not passed here (older release binaries don't define that flag anyway).
  & $exe install --config "`"$configFile`"" --data "`"$dataDir`""
  if ($LASTEXITCODE -ne 0) {
    Write-Host "!! wizard did not complete - the config at $configFile may be incomplete" -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "Next steps:"
if ($dflyStarted) {
  Write-Host "  - Dragonfly cache is running on 127.0.0.1:6379"
} elseif ($wizardRuns) {
  Write-Host "  - Dragonfly + startup task were handled by the wizard"
} else {
  Write-Host "  1. Start Dragonfly (required cache) - see the notes above"
}
Write-Host "  2. Edit the config:       $configFile"
Write-Host "  3. Re-run the setup wizard anytime:  $exe install"
Write-Host "  4. Dashboard:              http://localhost:8080  (default login: admin / irongrid)"

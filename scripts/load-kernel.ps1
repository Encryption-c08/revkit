# load-kernel.ps1
# Loads cr-driver.sys via kdmapper (manual map, no test signing / Secure Boot needed)
# Must run as Administrator

param(
    [switch]$Unload
)

$bin    = "$PSScriptRoot\bin\Release"
$driver = "$bin\cr-driver.sys"
$mapper = "$bin\kdmapper.exe"

# --- check admin ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: must run as Administrator" -ForegroundColor Red
    exit 1
}

if ($Unload) {
    # Tell the device to go away — since the driver is manually mapped there's
    # no service to stop, but we can signal it via a DeviceIoControl if needed.
    # For now just report.
    Write-Host "Driver is manually mapped — reboot to unload." -ForegroundColor Yellow
    exit 0
}

# --- check files ---
if (-not (Test-Path $driver)) {
    Write-Host "ERROR: cr-driver.sys not found at $driver" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $mapper)) {
    Write-Host "ERROR: kdmapper.exe not found at $mapper" -ForegroundColor Red
    exit 1
}

# --- check if already loaded ---
$handle = $null
try {
    $handle = [System.IO.File]::Open('\\.\RvKit',
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::ReadWrite)
    $handle.Close()
    Write-Host "Driver already loaded — device is open." -ForegroundColor Green
    exit 0
} catch { }

Write-Host ""
Write-Host "  Loading cr-driver via kdmapper..." -ForegroundColor Cyan

$p = Start-Process $mapper -ArgumentList "`"$driver`"" -PassThru -Wait -NoNewWindow
if ($p.ExitCode -ne 0) {
    Write-Host "  kdmapper failed (exit $($p.ExitCode))" -ForegroundColor Red
    Write-Host "  Make sure no previous kdmapper run left iqvw64e.sys loaded:" -ForegroundColor Yellow
    Write-Host "    sc stop iqvw64e && sc delete iqvw64e" -ForegroundColor Yellow
    exit 1
}

# Verify device appeared
Start-Sleep -Milliseconds 300
try {
    $h = [System.IO.File]::Open('\\.\RvKit',
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::ReadWrite)
    $h.Close()
    Write-Host "  Driver loaded. Device \\.\RvKit is open." -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "  kdmapper ran but device did not appear." -ForegroundColor Red
    Write-Host "  Check if Windows Defender blocked iqvw64e.sys." -ForegroundColor Yellow
    exit 1
}

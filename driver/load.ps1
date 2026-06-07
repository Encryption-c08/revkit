param(
    [Parameter(Mandatory)][ValidateSet("load","unload")][string]$Action,
    [string]$DriverPath = "$PSScriptRoot\..\bin\Release\cr-driver.sys"
)

$ServiceName = "RvKit"

if ($Action -eq "load") {
    $abs = (Resolve-Path $DriverPath).Path
    sc.exe create $ServiceName type= kernel binPath= $abs | Out-Null
    sc.exe start  $ServiceName
    Write-Host "Driver loaded."
} elseif ($Action -eq "unload") {
    sc.exe stop   $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Driver unloaded."
}

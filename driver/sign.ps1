param([string]$DriverPath = "$PSScriptRoot\..\bin\Release\cr-driver.sys")

Write-Host "Enabling test signing..."
bcdedit /set testsigning on
Write-Host "REBOOT REQUIRED after first run."

$certName = "CRDriver"
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "Creating test certificate..."
    $cert = New-SelfSignedCertificate -Subject "CN=$certName" -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert
    Export-Certificate -Cert $cert -FilePath "$PSScriptRoot\CRDriver.cer" | Out-Null
    Import-Certificate -FilePath "$PSScriptRoot\CRDriver.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath "$PSScriptRoot\CRDriver.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    Write-Host "Certificate created and trusted."
}

if (Test-Path $DriverPath) {
    $signtool = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" | Where-Object { $_.FullName -like "*x64*" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
    if ($signtool) {
        & $signtool sign /fd SHA256 /a /s My /n $certName $DriverPath
        Write-Host "Driver signed: $DriverPath"
    } else {
        Write-Host "signtool.exe not found. Install Windows SDK."
    }
} else {
    Write-Host "Driver not found at: $DriverPath (build first)"
}

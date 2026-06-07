$url  = "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp"
$dest = "$PSScriptRoot\vendor\nlohmann\json.hpp"
if (-not (Test-Path (Split-Path $dest))) { New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null }
Invoke-WebRequest -Uri $url -OutFile $dest
Write-Host "json.hpp downloaded to $dest"

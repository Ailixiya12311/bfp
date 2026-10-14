$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$client = Join-Path $workspace 'credentials-client-ready/tun-debug06'
$result = Join-Path $PSScriptRoot 'windows-tun-real-attempt06.json'
& (Join-Path $PSScriptRoot 'verify-real.ps1') -ClientRoot $client -ResultPath $result

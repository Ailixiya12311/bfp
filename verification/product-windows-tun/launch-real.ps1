param([Parameter(Mandatory=$true)][string]$ResultName)
$ErrorActionPreference = 'Stop'
if ($ResultName -cnotmatch '^windows-tun-real-attempt[0-9]+\.json$') { throw 'Invalid result name.' }
$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$clientName = 'BFP ' + [char]0x5ba2 + [char]0x6237 + [char]0x7aef
$clientRoot = Join-Path $workspace ('credentials-client-ready\' + $clientName)
$result = Join-Path $PSScriptRoot $ResultName
$log = Join-Path $PSScriptRoot ($ResultName + '.startup.log')
if (Test-Path -LiteralPath $result) { throw 'Preserve the existing result.' }
try {
    & (Join-Path $PSScriptRoot 'verify-real.ps1') -ClientRoot $clientRoot -ResultPath $result *>&1 |
        Out-File -LiteralPath $log -Encoding UTF8
} catch {
    [ordered]@{ started_utc = [DateTime]::UtcNow.ToString('o'); result_created = (Test-Path -LiteralPath $result);
        startup_error_id = [string]$_.FullyQualifiedErrorId; startup_error_type = $_.Exception.GetType().FullName;
        startup_error_line = [int]$_.InvocationInfo.ScriptLineNumber } | ConvertTo-Json |
        Out-File -LiteralPath $log -Encoding UTF8
    exit 1
}

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$clientName = 'BFP ' + [char]0x5ba2 + [char]0x6237 + [char]0x7aef
$clientRoot = Join-Path $workspace ('credentials-client-ready\' + $clientName)
$result = Join-Path $PSScriptRoot 'windows-tun-real-attempt02.json'
$log = Join-Path $PSScriptRoot 'elevated-attempt02-startup.log'
try {
    & (Join-Path $PSScriptRoot 'verify-real.ps1') -ClientRoot $clientRoot -ResultPath $result *>&1 |
        Out-File -LiteralPath $log -Encoding UTF8
} catch {
    # This entrypoint only reports invocation/preflight failures. Product
    # evidence remains in verify-real's distinct, immutable result file.
    [ordered]@{ started_utc = [DateTime]::UtcNow.ToString('o'); result_created = (Test-Path -LiteralPath $result);
        startup_error_id = [string]$_.FullyQualifiedErrorId; startup_error_type = $_.Exception.GetType().FullName;
        startup_error_line = [int]$_.InvocationInfo.ScriptLineNumber } | ConvertTo-Json |
        Out-File -LiteralPath $log -Encoding UTF8
    exit 1
}

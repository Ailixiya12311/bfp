$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$recordDirectory = Join-Path $project 'deploy\runs\66af4a892648df0a6249d6af3947af68'
$upgrade = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $recordDirectory 'client-upgrade-preview2.json') | ConvertFrom-Json
$clientRoot = Split-Path -Parent $upgrade.entrypoint
$wrapper = Join-Path $clientRoot 'deploy\windows-client.ps1'
. (Join-Path $clientRoot 'deploy\windows-context.ps1')
. (Join-Path $clientRoot 'deploy\windows-lifecycle.ps1')
$context = Get-BfpDesktopContext -DeployRoot (Join-Path $clientRoot 'deploy')
[void][IO.Directory]::CreateDirectory($context.RunDirectory)
$result = [ordered]@{ time_utc = [DateTime]::UtcNow.ToString('o'); client_version = '0.1.0-preview.2'; native_version = '0.1.0-preview.32'; entrypoint = $upgrade.entrypoint }
$launcher = $null
try {
    $result.version = (& (Join-Path $clientRoot 'client\bin\bfp-windows-amd64.exe') version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $result.version -notmatch ('^bfp ' + [regex]::Escape($result.native_version) + '(\s|$)')) { throw 'Client binary version does not match the new package.' }
    $launcher = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $context.RunDirectory 'upgrade-check.out.log') -RedirectStandardError (Join-Path $context.RunDirectory 'upgrade-check.err.log') -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $status = Get-BfpDesktopClientStatus -ProjectRoot $clientRoot -InstanceId $context.InstanceId
        if ($status.proxy_owner_verified) { break }
        if ($launcher.HasExited) { throw 'Client exited before its owned proxy was ready.' }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $status.proxy_owner_verified) { throw 'Client proxy was not ready in its startup budget.' }
    $result.start = $status
    $checkOutput = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $wrapper -Action check -Json
    $checkExit = $LASTEXITCODE
    $result.public_https = $checkOutput | ConvertFrom-Json
    if ($checkExit -ne 0 -or -not $result.public_https.success) { throw 'Public HTTPS exit check failed.' }
} catch {
    $result.error = $_.Exception.Message
} finally {
    $stopOutput = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $wrapper -Action stop -Json
    $result.stop = $stopOutput | ConvertFrom-Json
    $result.final_status = Get-BfpDesktopClientStatus -ProjectRoot $clientRoot -InstanceId $context.InstanceId
    $result.pass = -not $result.Contains('error') -and $result.stop.cleanup_complete -and -not $result.final_status.running -and -not $result.final_status.port_listening -and -not $result.final_status.supervisor_lock_held
    $path = Join-Path $recordDirectory 'client-preview2-real.json'
    [IO.File]::WriteAllText($path, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    if ($null -ne $launcher) { $launcher.Dispose() }
}
$result | ConvertTo-Json -Depth 8
if (-not $result.pass) { exit 1 }

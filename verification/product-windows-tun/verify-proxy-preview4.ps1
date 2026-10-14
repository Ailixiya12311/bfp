param(
    [string]$ResultPath = (Join-Path $PSScriptRoot 'proxy-preview4-real.json')
)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$client = Join-Path $project 'credentials-client-ready\BFP 客户端'
$deploy = Join-Path $client 'deploy'
. (Join-Path $deploy 'windows-lifecycle.ps1')
. (Join-Path $deploy 'windows-context.ps1')
$context = Get-BfpDesktopContext -DeployRoot $deploy
$wrapper = Join-Path $deploy 'windows-client.ps1'
$powershell = Join-Path $PSHOME 'powershell.exe'
$result = [ordered]@{ pass = $false; mode = 'proxy'; private_config_dumped = $false; host_tun_started = $false }
$launcher = $null
try {
    $before = Get-BfpDesktopClientStatus $client $context.InstanceId
    if ($before.running -or $before.cleanup_pending -or $before.port_listening -or $before.tun.needs_recovery) { throw 'Client must already be stopped for the bounded proxy check.' }
    $stamp = [guid]::NewGuid().ToString('N')
    $launcher = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start','-Mode','proxy') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $context.RunDirectory ('smoke-' + $stamp + '.out.log')) -RedirectStandardError (Join-Path $context.RunDirectory ('smoke-' + $stamp + '.err.log'))
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $status = Get-BfpDesktopClientStatus $client $context.InstanceId
        if ($status.proxy_owner_verified -and $status.pid -eq $launcher.Id) { break }
        if ($launcher.HasExited) { throw 'Client exited before its owned proxy became ready.' }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $status.proxy_owner_verified) { throw 'Timed out waiting for the owned proxy.' }
    $checkText = & $powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper -Action check -Json
    if ($LASTEXITCODE -ne 0) { throw 'Public exit check failed; inspect the client log.' }
    $check = $checkText | ConvertFrom-Json
    if (-not $check.success -or $check.mode -ne 'proxy' -or $check.check_path -ne 'socks') { throw 'Exit check used the wrong client path.' }
    $result.exit_ip = $check.exit_ip
    $result.check_path = $check.check_path
    $result.pass = $true
} catch { $result.error = $_.Exception.Message }
finally {
    if ($null -ne $launcher) {
        $stopText = & $powershell -NoProfile -ExecutionPolicy Bypass -File $wrapper -Action stop -Json
        $stopCode = $LASTEXITCODE
        try { $stop = $stopText | ConvertFrom-Json; $result.cleanup_complete = $stop.cleanup_complete }
        catch { $result.cleanup_complete = $false }
        if ($stopCode -ne 0 -or -not $result.cleanup_complete) { $result.pass = $false }
        $launcher.Dispose()
    }
    $result.final_status = Get-BfpDesktopClientStatus $client $context.InstanceId
    $result.time_utc = [DateTime]::UtcNow.ToString('o')
    $ResultPath = [IO.Path]::GetFullPath($ResultPath)
    if (-not $ResultPath.StartsWith(([IO.Path]::GetFullPath($PSScriptRoot) + '\'), [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetExtension($ResultPath) -cne '.json') { throw 'ResultPath must be a JSON file under the product verification directory.' }
    [IO.File]::WriteAllText($ResultPath, ($result | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $result | ConvertTo-Json -Depth 8
}
if (-not $result.pass) { exit 1 }

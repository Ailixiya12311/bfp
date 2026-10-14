param()
$ErrorActionPreference = 'Stop'
$testId = [guid]::NewGuid().ToString('N')
$testDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('runs\lifecycle-' + $testId)))
$runsDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'runs')).TrimEnd('\') + '\'
if (-not $testDirectory.StartsWith($runsDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test directory.' }
$fixture = Join-Path $testDirectory 'project'
$fixtureDeploy = Join-Path $fixture 'deploy'
$recordPath = Join-Path $fixtureDeploy ('runs\' + $testId + '\windows-client.json')
$results = [Collections.Generic.List[object]]::new()
$launcher = $null
$original = $null

function Assert-Case([string]$Name, [bool]$Passed) {
    $results.Add([pscustomobject]@{ name = $Name; pass = $Passed })
    if (-not $Passed) { throw ('Lifecycle verification failed: ' + $Name) }
}

try {
    [void][IO.Directory]::CreateDirectory($fixtureDeploy)
    [IO.File]::Copy((Join-Path $PSScriptRoot 'windows-lifecycle.ps1'), (Join-Path $fixtureDeploy 'windows-lifecycle.ps1'))
    . (Join-Path $fixtureDeploy 'windows-lifecycle.ps1')
    Assert-Case 'empty_state_is_stopped' (-not (Get-BfpDesktopClientStatus $fixture $testId).running)
    try { [void](Get-BfpDesktopPaths $fixture ('..\' + $testId)); $rejected = $false } catch { $rejected = $true }
    Assert-Case 'invalid_instance_path_rejected' $rejected
    try { [void](Get-BfpDesktopPaths $testDirectory $testId); $rejected = $false } catch { $rejected = $true }
    Assert-Case 'wrong_project_root_rejected' $rejected
    $fixtureLauncher = @'
param([string]$Action = 'start')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
$lease = Begin-BfpClientRecord -ProjectRoot $root -InstanceId '__TEST_ID__' -LauncherPid $PID -Mode proxy
try { while ($true) { Start-Sleep -Milliseconds 100 } }
finally { Complete-BfpClientRecord -Lease $lease }
'@
    $launcherScript = Join-Path $fixtureDeploy 'windows-client.ps1'
    [IO.File]::WriteAllText($launcherScript, $fixtureLauncher.Replace('__TEST_ID__', $testId), [Text.UTF8Encoding]::new($true))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $launcherArgs = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File', ('"' + $launcherScript + '"'), '-Action','start')
    $launcher = Start-Process -FilePath $powershell -ArgumentList $launcherArgs -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $testDirectory 'launcher.stderr.log') -RedirectStandardOutput (Join-Path $testDirectory 'launcher.stdout.log')
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    do {
        if (Test-Path -LiteralPath $recordPath) { break }
        $launcher.Refresh()
        if ($launcher.HasExited) { throw 'Fixture launcher exited before writing ownership.' }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not (Test-Path -LiteralPath $recordPath)) { throw 'Timed out waiting for fixture owner record.' }
    $status = Get-BfpDesktopClientStatus $fixture $testId
    Assert-Case 'running_launcher_ownership_verified' ($status.running -and $status.owner_verified -and $status.pid -eq $launcher.Id)
    Assert-Case 'running_without_owned_proxy_is_not_ready' (-not $status.proxy_owner_verified)
    Assert-Case 'running_is_not_cleanup_pending' (-not $status.cleanup_pending -and -not $status.supervisor_stopping)

    $original = [IO.File]::ReadAllText($recordPath)
    try { [void](Begin-BfpClientRecord -ProjectRoot $fixture -InstanceId $testId -LauncherPid $PID); $rejected = $false } catch { $rejected = $true }
    Assert-Case 'duplicate_start_does_not_replace_owner' ($rejected -and [IO.File]::ReadAllText($recordPath) -ceq $original)
    $otherRecord = $original | ConvertFrom-Json; $otherRecord.owner_id = [guid]::NewGuid().ToString('N')
    Remove-BfpDesktopOwnerRecord $fixture $testId $otherRecord
    Assert-Case 'foreign_completion_does_not_remove_record' (Test-Path -LiteralPath $recordPath)

    $record = $original | ConvertFrom-Json
    $record.launcher_start_utc = [DateTime]::Parse($record.launcher_start_utc).ToUniversalTime().AddTicks(-1).ToString('o')
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $result = Stop-BfpDesktopClient $fixture $testId
    $launcher.Refresh()
    Assert-Case 'pid_reuse_identity_mismatch_never_stops_process' (-not $result.stopped -and $result.state -eq 'owner_mismatch' -and -not $launcher.HasExited)
    [IO.File]::WriteAllText($recordPath, $original, [Text.UTF8Encoding]::new($false))

    $record = $original | ConvertFrom-Json; $record.launcher_command_sha256 = ('0' * 64)
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $result = Stop-BfpDesktopClient $fixture $testId
    $launcher.Refresh()
    Assert-Case 'command_identity_mismatch_never_stops_process' (-not $result.stopped -and -not $launcher.HasExited)
    [IO.File]::WriteAllText($recordPath, $original, [Text.UTF8Encoding]::new($false))

    $result = Stop-BfpDesktopClient $fixture $testId -WaitSeconds 2
    $launcher.Refresh()
    Assert-Case 'owned_launcher_stops' ($result.stopped -and $result.cleanup_complete -and $launcher.HasExited)
    Assert-Case 'stopped_owner_record_removed' (-not (Test-Path -LiteralPath $recordPath))
    $result = Stop-BfpDesktopClient $fixture $testId
    Assert-Case 'repeat_stop_is_idempotent' ($result.stopped -and $result.cleanup_complete -and $result.reason -eq 'already_stopped')
} finally {
    if ($null -ne $launcher) {
        try {
            $launcher.Refresh()
            if (-not $launcher.HasExited -and $null -ne $original -and (Test-Path -LiteralPath $recordPath)) {
                [IO.File]::WriteAllText($recordPath, $original, [Text.UTF8Encoding]::new($false))
                [void](Stop-BfpDesktopClient $fixture $testId -WaitSeconds 2)
            }
        } finally { $launcher.Dispose() }
    }
    $summary = [pscustomobject]@{ pass = ($results.Count -eq 13 -and @($results | Where-Object { -not $_.pass }).Count -eq 0); tests = @($results.ToArray()); ps_version = $PSVersionTable.PSVersion.ToString(); scope = 'Local fixture launcher only. Real native supervisor and proxy are checked through the product entrypoint.' }
    [IO.File]::WriteAllText((Join-Path $testDirectory 'result.json'), ($summary | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $summary | ConvertTo-Json -Depth 5
}

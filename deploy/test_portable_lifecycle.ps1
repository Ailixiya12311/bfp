param()
$ErrorActionPreference = 'Stop'
$testId = [guid]::NewGuid().ToString('N')
$testDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('runs\portable-lifecycle-' + $testId)))
$runsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'runs')).TrimEnd('\') + '\'
if (-not $testDirectory.StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe portable test directory.' }
$fixture = Join-Path $testDirectory 'project'
$fixtureDeploy = Join-Path $fixture 'deploy'
$results = [Collections.Generic.List[object]]::new()
$launcher = $null
$original = $null
$descriptor = [pscustomobject][ordered]@{ version = 1; instance_id = $testId; public_endpoint = '192.0.2.10:51880'; expected_exit_ip = '192.0.2.10' }
$descriptorJson = $descriptor | ConvertTo-Json
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Assert-Case([string]$Name, [bool]$Passed) {
    $results.Add([pscustomobject]@{ name = $Name; pass = $Passed })
    if (-not $Passed) { throw ('Portable lifecycle verification failed: ' + $Name) }
}

function Start-Fixture([string]$DeployRoot) {
    $scriptPath = Join-Path $DeployRoot 'windows-client.ps1'
    $arguments = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File', ('"' + $scriptPath + '"'), '-Action','start')
    $process = Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardError (Join-Path $testDirectory ('launcher-' + [guid]::NewGuid().ToString('N') + '.stderr.log')) `
        -RedirectStandardOutput (Join-Path $testDirectory ('launcher-' + [guid]::NewGuid().ToString('N') + '.stdout.log'))
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(12)
        do {
            $process.Refresh()
            if ($process.HasExited) { throw 'Portable fixture launcher exited before ownership was ready.' }
            $status = Get-BfpDesktopClientStatus (Split-Path -Parent $DeployRoot) $testId
            if ($status.running -and $status.pid -eq $process.Id) { return $process }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        throw 'Timed out waiting for portable fixture owner record.'
    } catch {
        # Retain the exact fixture process object for the caller's cleanup.
        $script:launcher = $process
        throw
    }
}

try {
    [void][IO.Directory]::CreateDirectory($fixtureDeploy)
    [IO.File]::Copy((Join-Path $PSScriptRoot 'windows-lifecycle.ps1'), (Join-Path $fixtureDeploy 'windows-lifecycle.ps1'))
    $descriptorPath = Join-Path $fixtureDeploy 'portable-client.json'
    [IO.File]::WriteAllText($descriptorPath, $descriptorJson, [Text.UTF8Encoding]::new($false))
    . (Join-Path $fixtureDeploy 'windows-lifecycle.ps1')
    $paths = Get-BfpDesktopPaths $fixture $testId
    Assert-Case 'portable_layout_has_fixed_client_and_local_runs' ($paths.Portable -and $paths.NativeDirectory -eq (Join-Path $fixture 'client') -and
        $paths.RunDirectory -eq (Join-Path $fixtureDeploy ('runs\' + $testId)))

    $invalidDescriptors = @(
        ($descriptorJson.Replace('"version":  1', '"version":  2').Replace('"version": 1', '"version": 2')),
        ($descriptorJson.Replace('"version":  1', '"version":  "1"').Replace('"version": 1', '"version": "1"')),
        ($descriptorJson.Replace($testId, $testId.ToUpperInvariant())),
        ($descriptorJson.Replace(':51880', ':65536')),
        ($descriptorJson.Replace('192.0.2.10', '192.0.2.10')),
        ($descriptorJson.Replace('"expected_exit_ip"', '"native_directory"')),
        ($descriptorJson.TrimEnd().TrimEnd('}') + ', "native_directory": "C:\\outside" }'),
        ($descriptorJson.TrimEnd().TrimEnd('}') + ', "version": 1 }'),
        ($descriptorJson.Replace('"version"', '"\u0076ersion"')),
        ($descriptorJson + (' ' * 4097))
    )
    $rejections = 0
    foreach ($invalid in $invalidDescriptors) {
        [IO.File]::WriteAllText($descriptorPath, $invalid, [Text.UTF8Encoding]::new($false))
        try { [void](Read-BfpDesktopPortableDescriptor $fixture) } catch { $rejections++ }
    }
    [IO.File]::WriteAllText($descriptorPath, $descriptorJson, [Text.UTF8Encoding]::new($false))
    Assert-Case 'strict_public_descriptor_rejects_invalid_values_fields_and_size' ($rejections -eq $invalidDescriptors.Count)
    try { [void](Get-BfpDesktopPaths $fixture ('0' * 32)); $rejected = $false } catch { $rejected = $true }
    Assert-Case 'portable_identity_must_match_descriptor' $rejected

    $fixtureLauncher = @'
param([string]$Action = 'start')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
$lease = Begin-BfpClientRecord -ProjectRoot $root -InstanceId '__TEST_ID__' -LauncherPid $PID -Mode proxy
try { while ($true) { Start-Sleep -Milliseconds 100 } }
finally { Complete-BfpClientRecord -Lease $lease }
'@
    [IO.File]::WriteAllText((Join-Path $fixtureDeploy 'windows-client.ps1'), $fixtureLauncher.Replace('__TEST_ID__', $testId), [Text.UTF8Encoding]::new($true))
    $launcher = Start-Fixture $fixtureDeploy
    $recordPath = (Get-BfpDesktopPaths $fixture $testId).RecordPath
    $original = [IO.File]::ReadAllText($recordPath)
    $record = Read-BfpDesktopOwnerRecord $fixture $testId
    Assert-Case 'portable_owner_uses_relative_v2_and_live_identity_checks' ($record.version -eq 2 -and $record.native_directory -ceq 'client' -and
        (Get-BfpDesktopClientStatus $fixture $testId).owner_verified)

    $record.version = 1; $record.native_directory = (Join-Path (Join-Path $testDirectory 'previous-root') 'client')
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $result = Stop-BfpDesktopClient $fixture $testId
    $launcher.Refresh()
    Assert-Case 'live_legacy_record_with_foreign_layout_cannot_stop_process' (-not $result.stopped -and $result.state -eq 'owner_mismatch' -and -not $launcher.HasExited)
    [IO.File]::WriteAllText($recordPath, $original, [Text.UTF8Encoding]::new($false))

    # Simulate a crash only after matching the fixture's same-handle ownership.
    $processLease = [BfpDesktopProcessV1.Lease]::Open($launcher.Id, $true)
    try {
        if (-not (Test-BfpDesktopProcessOwner $processLease ($original | ConvertFrom-Json) (Get-BfpDesktopPaths $fixture $testId).LauncherScript)) {
            throw 'Fixture ownership could not be verified before simulated crash.'
        }
        $processLease.Terminate()
        if (-not $processLease.Wait(3000)) { throw 'Fixture did not exit after simulated crash.' }
    } finally { $processLease.Dispose() }
    $launcher.Dispose(); $launcher = $null

    # Model Windows reusing the former launcher's PID for this live test process.
    # The independent process has no desktop control mutex or native supervisor.
    $selfLease = [BfpDesktopProcessV1.Lease]::Open($PID, $false)
    try {
        $record = $original | ConvertFrom-Json
        $record.launcher_pid = $PID
        $record.launcher_start_utc = $selfLease.StartedUtc.AddTicks(-1).ToString('o')
        [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        $status = Get-BfpDesktopClientStatus $fixture $testId
        $result = Stop-BfpDesktopClient $fixture $testId
        Assert-Case 'reused_pid_discards_only_stale_metadata_and_never_stops_live_process' ($status.state -eq 'stale_record' -and $result.stopped -and
            $result.cleanup_complete -and $selfLease.Alive -and -not (Test-Path -LiteralPath $recordPath))
    } finally { $selfLease.Dispose() }
    [IO.File]::WriteAllText($recordPath, $original, [Text.UTF8Encoding]::new($false))

    $previousRoot = $fixture
    $fixture = Join-Path $testDirectory ('Portable space ' + [char]0x6d4b + [char]0x8bd5)
    # Both resolved targets are explicitly within this test's owned directory.
    if (-not ([IO.Path]::GetFullPath($fixture).StartsWith($testDirectory + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'Unsafe fixture move.' }
    Move-Item -LiteralPath $previousRoot -Destination $fixture
    $fixtureDeploy = Join-Path $fixture 'deploy'
    . (Join-Path $fixtureDeploy 'windows-lifecycle.ps1')
    $paths = Get-BfpDesktopPaths $fixture $testId
    $recordPath = $paths.RecordPath
    Assert-Case 'crashed_portable_record_remains_readable_after_directory_move' ((Get-BfpDesktopClientStatus $fixture $testId).state -eq 'stopped' -and
        (Read-BfpDesktopOwnerRecord $fixture $testId).native_directory -ceq 'client' -and $paths.NativeDirectory -eq (Join-Path $fixture 'client'))
    $launcher = Start-Fixture $fixtureDeploy
    $original = [IO.File]::ReadAllText($recordPath)
    $result = Stop-BfpDesktopClient $fixture $testId -WaitSeconds 2
    Assert-Case 'moved_portable_client_can_restart_and_stop' ($result.stopped -and $result.cleanup_complete -and -not (Test-Path -LiteralPath $recordPath))
    $launcher.Dispose(); $launcher = $null

    # A legacy absolute record left by a dead launcher is also recoverable.
    $record = $original | ConvertFrom-Json
    $record.version = 1; $record.native_directory = Join-Path $previousRoot 'client'
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $launcher = Start-Fixture $fixtureDeploy
    $original = [IO.File]::ReadAllText($recordPath)
    $result = Stop-BfpDesktopClient $fixture $testId -WaitSeconds 2
    Assert-Case 'dead_legacy_absolute_record_is_replaced_safely_after_move' ($result.stopped -and $result.cleanup_complete -and -not (Test-Path -LiteralPath $recordPath))
    $launcher.Dispose(); $launcher = $null
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
    $summary = [pscustomobject]@{ pass = ($results.Count -eq 9 -and @($results | Where-Object { -not $_.pass }).Count -eq 0); tests = @($results.ToArray())
        ps_version = $PSVersionTable.PSVersion.ToString(); descriptor_rejections = $rejections
        scope = 'Local portable fixture and ownership metadata only; no client credentials, proxy payload, remote host, or network request.' }
    [IO.File]::WriteAllText((Join-Path $testDirectory 'result.json'), ($summary | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $summary | ConvertTo-Json -Depth 5
}

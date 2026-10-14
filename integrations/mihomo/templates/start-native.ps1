param(
    [ValidateSet('proxy','tun')][string]$Mode = 'proxy',
    [string]$Runtime = '.\runtime',
    [int]$GraceSeconds = 5,
    [int]$ReadySeconds = 30
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-tun-support.ps1')
if ($GraceSeconds -lt 1 -or $GraceSeconds -gt 60) { throw 'GraceSeconds must be between 1 and 60.' }
if ($ReadySeconds -lt 5 -or $ReadySeconds -gt 120) { throw 'ReadySeconds must be between 5 and 120.' }
# Fail before creating runtime state or launching any process; never auto-elevate.
if ($Mode -eq 'tun') { Assert-BfpTunAdministrator }
if (-not (Test-Path -LiteralPath '.\credentials\client.json')) {
    throw 'Generate credentials/client.json with bin/bfp-windows-amd64.exe keygen first.'
}
$runtimePath = Resolve-BfpTunRuntime $Runtime
New-Item -ItemType Directory -Force -Path $runtimePath | Out-Null
$mutex = New-Object Threading.Mutex($false, 'Local\BFP-Mihomo')
$hasMutex = $false
$process = $null
$state = $null
$exitCode = 1
try {
    try { $hasMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $hasMutex = $true }
    if (-not $hasMutex) { throw 'Another BFP Mihomo instance is already running.' }
    $supervisorLock = Join-Path $runtimePath 'native-supervisor.lock'
    Assert-BfpTunPlainFile $supervisorLock
    try {
        $probe = [IO.File]::Open($supervisorLock, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $probe.Dispose()
    } catch { throw 'Another BFP native supervisor is still stopping.' }
    # Recovery is also required before proxy mode, so stale routes cannot remain.
    Remove-BfpWindowsTunState -Runtime $runtimePath
    $configToRun = Join-Path $PSScriptRoot ('configs\native-' + $Mode + '.yaml')
    if (-not (Test-Path -LiteralPath $configToRun)) { throw 'Missing native configuration.' }
    if ($Mode -eq 'tun') {
        $state = New-BfpWindowsTunState -Runtime $runtimePath -Config $configToRun -CredentialPath (Join-Path $PSScriptRoot 'credentials\client.json')
        $configToRun = Join-Path $runtimePath 'native-tun.generated.yaml'
    }
    if ($Mode -eq 'proxy') {
        # Keep ordinary proxy console logs and signal delivery as before.
        $directArguments = @('native-supervise','-runtime',$runtimePath,'-config',$configToRun,'-grace',($GraceSeconds.ToString() + 's'))
        & (Join-Path $PSScriptRoot 'bin\bfp-windows-amd64.exe') @directArguments
        $exitCode = $LASTEXITCODE
    } else {
    $arguments = @('native-supervise','-runtime',('"' + $runtimePath + '"'),'-config',('"' + $configToRun + '"'),'-grace',($GraceSeconds.ToString() + 's'))
    if ($Mode -eq 'tun') { $arguments += @('-device',$state.device) }
    $stdout = Join-Path $runtimePath 'native-supervisor.stdout.log'
    $stderr = Join-Path $runtimePath 'native-supervisor.stderr.log'
    Assert-BfpTunPlainFile $stdout
    Assert-BfpTunPlainFile $stderr
    if ($null -ne $state) {
        $state.phase = 'starting'
        Write-BfpTunJson (Join-Path $runtimePath 'bfp-windows-tun-journal.json') $state
        Write-BfpTunMarker $state
    }
    $process = Start-Process -FilePath (Join-Path $PSScriptRoot 'bin\bfp-windows-amd64.exe') -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($null -ne $state) {
        $state.supervisor_pid = $process.Id
        $state.supervisor_started_utc = $process.StartTime.ToUniversalTime().ToString('o')
        Write-BfpTunJson (Join-Path $runtimePath 'bfp-windows-tun-journal.json') $state
        Write-BfpTunMarker $state
        $deadline = [DateTime]::UtcNow.AddSeconds($ReadySeconds)
        while (-not $process.HasExited) {
            $children = @(Get-CimInstance Win32_Process -Filter ("ParentProcessId={0}" -f $process.Id) -ErrorAction Stop |
                Where-Object { $_.ExecutablePath -eq (Join-Path $PSScriptRoot 'bin\mihomo-bfp-windows-amd64.exe') })
            if ($children.Count -eq 1) {
                $child = Get-Process -Id $children[0].ProcessId -ErrorAction SilentlyContinue
                if ($null -ne $child) {
                    $state.mihomo_pid = $child.Id; $state.mihomo_started_utc = $child.StartTime.ToUniversalTime().ToString('o')
                }
            }
            # The fixed upstream line is emitted after main initializes routes,
            # proxies and listeners. Port-open logs alone are insufficient.
            if ((Test-Path -LiteralPath $stdout) -and (Select-String -LiteralPath $stdout -SimpleMatch 'Mihomo runtime ready' -Quiet)) { $state.initialized = $true }
            if ((Test-Path -LiteralPath $stderr) -and (Select-String -LiteralPath $stderr -SimpleMatch 'Mihomo runtime ready' -Quiet)) { $state.initialized = $true }
            Write-BfpTunJson (Join-Path $runtimePath 'bfp-windows-tun-journal.json') $state
            Write-BfpTunMarker $state
            $status = Get-BfpWindowsTunRuntimeStatus -Runtime $runtimePath -LauncherPid $PID
            # Preserve the last safe, public diagnostic even when successful
            # cleanup removes the private generated YAML and owner journal.
            Write-BfpTunJson (Join-Path $runtimePath 'native-tun-readiness.json') $status
            if ($status.ready) {
                $state.ready = $true; $state.phase = 'ready'; $state.interface_index = $status.interface_index
                Write-BfpTunJson (Join-Path $runtimePath 'bfp-windows-tun-journal.json') $state
                Write-BfpTunMarker $state
                Write-Host ('BFP TUN interface ready: ' + $state.device)
                break
            }
            if ([DateTime]::UtcNow -ge $deadline) { throw ('TUN 就绪超时：' + $status.reason) }
            Start-Sleep -Milliseconds 200
            $process.Refresh()
        }
        if (-not $state.ready) { throw 'Mihomo exited before TUN readiness was verified.' }
    }
    $process.WaitForExit()
    $process.Refresh()
    $exitCode = $process.ExitCode
    if ($null -eq $exitCode) { $exitCode = 1 }
    }
    if ($exitCode -ne 0) { Write-Warning 'BFP native process exited; inspect runtime/native-supervisor.stderr.log.' }
} finally {
    if ($null -ne $process) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                # Closing the Go supervisor's job also closes its owned Mihomo.
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                [void]$process.WaitForExit(($GraceSeconds + 2) * 1000)
            }
        } catch { $exitCode = 1; Write-Warning 'Native process shutdown could not be confirmed; recovery state was retained.' }
    }
    if ($hasMutex) {
        try { Remove-BfpWindowsTunState -Runtime $runtimePath }
        catch { $exitCode = 1; Write-Warning $_.Exception.Message }
    }
    if ($null -ne $process) { $process.Dispose() }
    if ($hasMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $exitCode

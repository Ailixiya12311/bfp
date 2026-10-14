param(
    [ValidateSet('start','stop','status','check','enable-system-proxy','restore-system-proxy')][string]$Action = 'start',
    [switch]$Json,
    [ValidateSet('proxy','tun')][string]$Mode = 'proxy'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'windows-context.ps1')
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
. (Join-Path $PSScriptRoot 'windows-system-proxy.ps1')

function Write-BfpResult($Value) {
    if ($Json) { $Value | ConvertTo-Json -Depth 8 -Compress }
    else { $Value | Format-List | Out-Host }
}

try {
    $context = Get-BfpDesktopContext -DeployRoot $PSScriptRoot
    if ($Action -eq 'status') {
        $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $status | Add-Member -NotePropertyName system_proxy -NotePropertyValue (Get-BfpSystemProxyStatus -Context $context -Status $status)
        Write-BfpResult $status
        exit 0
    }
    if ($Action -eq 'enable-system-proxy') {
        $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $result = Enable-BfpSystemProxy -Context $context -Status $status
        if ($result.success -and $result.owned -and $result.active) {
            try {
                $watcher = Join-Path $PSScriptRoot 'windows-proxy-watch.ps1'
                $readyId = [guid]::NewGuid().ToString('N')
                $readyPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory ('proxy-watch-' + $readyId + '.json')) $context.ProjectRoot
                $watchProcess = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $watcher + '"'),'-ExpectedLeaseId',$result.lease_id,'-ReadyId',$readyId) -WindowStyle Hidden -PassThru
                try {
                    $ready = $false
                    $watchDeadline = [DateTime]::UtcNow.AddSeconds(8)
                    do {
                        if (Test-Path -LiteralPath $readyPath -PathType Leaf) {
                            $ack = Get-Content -Raw -LiteralPath $readyPath | ConvertFrom-Json
                            $ready = $ack.lease_id -ceq $result.lease_id -and $ack.watcher_pid -eq $watchProcess.Id
                            if ($ready) { break }
                        }
                        if ($watchProcess.HasExited) { throw 'System proxy recovery watcher exited during startup.' }
                        Start-Sleep -Milliseconds 100
                    } while ([DateTime]::UtcNow -lt $watchDeadline)
                    if (-not $ready) { throw 'System proxy recovery watcher was not ready in time.' }
                } finally {
                    if (Test-Path -LiteralPath $readyPath) { [IO.File]::Delete($readyPath) }
                    $watchProcess.Dispose()
                }
            } catch {
                $rollback = Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $result.lease_id
                if ($rollback.success -or $rollback.external_change) { throw 'System proxy watcher failed to start; takeover was cancelled.' }
                throw 'System proxy watcher failed to start; saved settings require recovery.'
            }
        }
        Write-BfpResult $result
        if ($result.success) { exit 0 }
        exit 1
    }
    if ($Action -eq 'restore-system-proxy') {
        $result = Restore-BfpSystemProxy -Context $context
        Write-BfpResult $result
        if ($result.success -or $result.external_change) { exit 0 }
        exit 1
    }
    if ($Action -eq 'stop') {
        $stoppingStatus = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        if (($stoppingStatus.mode -eq 'tun' -or $stoppingStatus.tun.needs_recovery) -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Stopping global TUN requires administrator permission. Use the client window to confirm Windows UAC.'
        }
        $stoppingOwnerId = $stoppingStatus.owner_id
        $proxyRestore = Restore-BfpSystemProxy -Context $context
        $result = Stop-BfpDesktopClient -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId -WaitSeconds $(if ($stoppingStatus.mode -eq 'tun' -or $stoppingStatus.tun.needs_recovery) { 35 } else { 15 })
        $afterStopProxy = Get-BfpSystemProxyStatus -Context $context
        if ($afterStopProxy.owned -and $stoppingOwnerId -and $afterStopProxy.owner_id -ceq $stoppingOwnerId) {
            $proxyRestore = Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $afterStopProxy.lease_id
        }
        if ($result.cleanup_complete -and ($stoppingStatus.mode -eq 'tun' -or $stoppingStatus.tun.needs_recovery)) {
            $cleanupScript = Assert-BfpDesktopPath (Join-Path $context.NativeDirectory 'windows-tun-cleanup.ps1') $context.ProjectRoot
            if (-not (Test-Path -LiteralPath $cleanupScript -PathType Leaf)) { $result.cleanup_complete = $false; $result.reason = 'TUN recovery entry is missing.' }
            else {
                # Serialize recovery with native start. A newer launcher can
                # otherwise write a prepared journal before its child exists.
                $cleanupMutex = [Threading.Mutex]::new($false, 'Local\BFP-Mihomo')
                $cleanupOwned = $false
                try {
                    try { $cleanupOwned = $cleanupMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $cleanupOwned = $true }
                    if (-not $cleanupOwned) { $result.cleanup_complete = $false; $result.reason = 'Another native client is starting; its TUN state was preserved.' }
                    else {
                        $cleanupOutput = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cleanupScript -Runtime (Join-Path $context.NativeDirectory 'runtime') 2>&1
                        if ($LASTEXITCODE -ne 0) { $result.cleanup_complete = $false; $result.reason = 'TUN recovery failed; saved journal retained. See startup log.' }
                    }
                } finally { if ($cleanupOwned) { $cleanupMutex.ReleaseMutex() }; $cleanupMutex.Dispose() }
            }
        }
        $result | Add-Member -NotePropertyName system_proxy -NotePropertyValue $proxyRestore
        Write-BfpResult $result
        if ($result.cleanup_complete -and (-not $proxyRestore.owned -or $proxyRestore.success -or $proxyRestore.external_change)) { exit 0 }
        exit 1
    }
    if ($Action -eq 'start') {
        if ($Mode -eq 'tun' -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Global TUN requires administrator permission. Select global TUN in the client window and confirm Windows UAC.'
        }
        $before = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $priorProxy = Get-BfpSystemProxyStatus -Context $context -Status $before
        if ($priorProxy.owned -and $priorProxy.needs_restore -and $before.state -in @('stopped','stale_record','stopping')) {
            $recovery = Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $priorProxy.lease_id
            if (-not $recovery.success -and -not $recovery.external_change) { throw 'Previous system proxy settings require recovery before starting.' }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $context.NativeDirectory 'credentials\client.json'))) {
            if ($context.Layout -eq 'portable') {
                throw 'Copy your existing BFP client.json into client/credentials/client.json first. See README.md.'
            }
            throw 'Client configuration is missing. Prepare the deployment first.'
        }
        $lease = Begin-BfpClientRecord -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId -LauncherPid $PID -Mode $Mode
        try {
            if ($Mode -eq 'tun') { Write-Host 'BFP: global TUN; preparing owned network resources.' }
            else { Write-Host 'BFP: HTTP / SOCKS5 proxy 127.0.0.1:17890' }
            Write-Host 'Keep this window open. Close it or press Ctrl+C to stop.'
            & (Join-Path $context.NativeDirectory 'start-native.ps1') -Mode $Mode
            $nativeExit = $LASTEXITCODE
        } finally {
            try {
                $proxyState = Get-BfpSystemProxyStatus -Context $context
                if ($proxyState.owned -and $proxyState.owner_id -ceq $lease.OwnerId) {
                    $finalRestore = Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $proxyState.lease_id
                    if (-not $finalRestore.success -and -not $finalRestore.external_change) { $nativeExit = 1; Write-Warning 'Saved system proxy settings require recovery.' }
                }
            } finally { Complete-BfpClientRecord -Lease $lease }
        }
        exit $nativeExit
    }

    $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
    if (-not $status.running -or -not $status.owner_verified -or -not $status.proxy_owner_verified) {
        throw 'Start the BFP client before checking its public exit.'
    }
    if ($status.mode -eq 'tun') {
        if (-not $status.tun.ready) { throw 'Global TUN is not ready. Check the startup log before checking the exit.' }
        # No explicit proxy: this ordinary request must traverse the Windows
        # routing/DNS path. --noproxy '*' overrides all environment proxies.
        $trace = & curl.exe --noproxy '*' --connect-timeout 10 --max-time 20 --max-filesize 32768 --fail --silent --show-error https://www.cloudflare.com/cdn-cgi/trace 2>&1
        $checkPath = 'tun'
    } else {
        # PS5.1 drops empty native arguments; use a nonmatching bypass name.
        $trace = & curl.exe --proxy socks5h://127.0.0.1:17890 --noproxy bfp-never-bypass.invalid --connect-timeout 10 --max-time 20 --max-filesize 32768 --fail --silent --show-error https://www.cloudflare.com/cdn-cgi/trace 2>&1
        $checkPath = 'socks'
    }
    $curlExit = $LASTEXITCODE
    if ($curlExit -ne 0) { throw ('Exit check failed: ' + (($trace | Out-String).Trim())) }
    $ipLine = @($trace | Where-Object { [string]$_ -match '^ip=' })
    $exitIp = if ($ipLine.Count -eq 1) { ([string]$ipLine[0]).Substring(3).Trim() } else { '' }
    $afterCheck = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
    if (-not $afterCheck.proxy_owner_verified -or $afterCheck.owner_id -ne $status.owner_id -or $afterCheck.mode -ne $status.mode -or ($status.mode -eq 'tun' -and -not $afterCheck.tun.ready)) {
        throw 'The client changed or stopped during the exit check. Check the current client again.'
    }
    $check = [ordered]@{ success = ($exitIp -eq $context.ExpectedExitIp); exit_ip = $exitIp; expected_exit_ip = $context.ExpectedExitIp; proxy = $(if ($status.mode -eq 'proxy') { $context.ProxyAddress } else { $null }); mode = $status.mode; check_path = $checkPath; owner_id = $status.owner_id; checked_utc = [DateTime]::UtcNow.ToString('o') }
    Write-BfpResult $check
    if ($check.success) { exit 0 }
    exit 1
} catch {
    if ($Json) {
        [ordered]@{ success = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    } else { Write-Host ('BFP: ' + $_.Exception.Message) -ForegroundColor Red }
    exit 1
}

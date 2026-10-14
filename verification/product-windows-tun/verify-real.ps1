param(
    [Parameter(Mandatory=$true)][string]$ClientRoot,
    [Parameter(Mandatory=$true)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This verification requires an administrator process for the current Windows account. This script never elevates itself.'
}
$workspace = [IO.Path]::GetFullPath((Split-Path -Parent (Split-Path -Parent $PSScriptRoot))).TrimEnd('\')
$verificationRoot = Join-Path $workspace 'verification'
$ResultPath = [IO.Path]::GetFullPath($ResultPath)
if (-not $ResultPath.StartsWith($verificationRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetExtension($ResultPath) -cne '.json') { throw 'ResultPath must be a new JSON file inside this project verification directory.' }
if (Test-Path -LiteralPath $ResultPath) { throw 'Preserve the existing result and choose a new ResultPath.' }
$ClientRoot = [IO.Path]::GetFullPath($ClientRoot).TrimEnd('\')
. (Join-Path $ClientRoot 'deploy\windows-lifecycle.ps1')
. (Join-Path $ClientRoot 'deploy\windows-context.ps1')
$ResultPath = Assert-BfpDesktopPath $ResultPath $verificationRoot
$context = Get-BfpDesktopContext -DeployRoot (Join-Path $ClientRoot 'deploy')
if ($context.Layout -cne 'portable' -or $context.ExpectedExitIp -cne '192.0.2.10') {
    throw 'Use the authorized Los Angeles portable client for this verification.'
}
$paths = Get-BfpDesktopPaths -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
$wrapper = $paths.LauncherScript
$powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$resultDirectory = Split-Path -Parent $ResultPath
[void][IO.Directory]::CreateDirectory($resultDirectory)
$runId = [guid]::NewGuid().ToString('N')
$clock = [Diagnostics.Stopwatch]::StartNew()
$ownedLaunchers = [Collections.Generic.List[object]]::new()
$ownedDevices = [Collections.Generic.List[object]]::new()
$launcherHandles = [Collections.Generic.List[object]]::new()
$processes = [Collections.Generic.List[object]]::new()
$recoveryOperations = [Collections.Generic.List[object]]::new()
$failures = [Collections.Generic.List[string]]::new()
$scenarios = [Collections.Generic.List[object]]::new()
$accepted = $false
$baseline = $null
$adapterBaseline = @()
$chain = $null
$ready = $null
$requestCount = 0
$finalCleanup = $null
$result = [ordered]@{
    version = 1; run_id = $runId; started_utc = [DateTime]::UtcNow.ToString('o'); client_root = $ClientRoot
    scope = 'Windows TUN: direct HTTPS, normal stop, verified supervisor/launcher force termination, exact network baseline restoration'
    time_budget_seconds = 120; requested_https_checks = 0; baseline = $null; scenarios = @()
    final_cleanup = $null; cleanup_failed = $false; errors = @(); pass = $false
}
$clientManifest = Join-Path $ClientRoot 'client-manifest.json'
$packageIdentity = [IO.File]::ReadAllText($clientManifest) | ConvertFrom-Json
$result.client_version = [string]$packageIdentity.version
$result.native_version = [string]$packageIdentity.native_version
$result.client_manifest_sha256 = (Get-FileHash -LiteralPath $clientManifest -Algorithm SHA256).Hash.ToLowerInvariant()

function Get-BfpVerificationTimeout([int]$Maximum, [switch]$Cleanup) {
    # Leave 35 seconds for the mandatory final recovery and five seconds for
    # final state reads/result publication. Do not terminate a recovery worker.
    $reserve = if ($Cleanup) { 5 } else { 40 }
    $remaining = [Math]::Floor(120 - $clock.Elapsed.TotalSeconds - $reserve)
    if ($remaining -lt 1) {
        if ($Cleanup) { return 1 }
        throw 'The verification work deadline was reached; final recovery will still run.'
    }
    return [int][Math]::Min($Maximum, $remaining)
}
function Get-BfpNetworkBaseline {
    $physical = @(Get-NetAdapter -Physical -IncludeHidden -ErrorAction Stop | Sort-Object InterfaceIndex)
    $dns = @(foreach ($adapter in $physical) {
        foreach ($entry in @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction Stop | Sort-Object AddressFamily)) {
            [ordered]@{ interface_index = [int]$adapter.InterfaceIndex; interface_guid = ([guid]$adapter.InterfaceGuid).ToString('D'); address_family = [string]$entry.AddressFamily; servers = @($entry.ServerAddresses) }
        }
    })
    $defaults = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
        Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,Protocol | ForEach-Object {
            [ordered]@{ interface_index = [int]$_.InterfaceIndex; prefix = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop; metric = [int]$_.RouteMetric; protocol = [string]$_.Protocol }
        })
    $dnsJson = ConvertTo-Json -InputObject $dns -Depth 5 -Compress
    $routeJson = ConvertTo-Json -InputObject $defaults -Depth 5 -Compress
    return [pscustomobject]@{ physical_count = $physical.Count; dns_count = $dns.Count; default_route_count = $defaults.Count; dns_sha256 = Get-BfpDesktopHash $dnsJson; default_routes_sha256 = Get-BfpDesktopHash $routeJson }
}
function Get-BfpAdapterInventory {
    return @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object InterfaceGuid | ForEach-Object {
        [pscustomobject]@{ guid = ([guid]$_.InterfaceGuid).ToString('D'); name = [string]$_.Name }
    })
}
function Register-BfpObservedDevice($Status) {
    if ([string]::IsNullOrWhiteSpace($Status.device)) { return }
    $matching = @($ownedLaunchers | Where-Object { $_.pid -eq $Status.pid -and $_.start_utc -ceq $Status.launcher_start_utc })
    if ($matching.Count -ne 1 -or $Status.mode -cne 'tun') { return }
    $guid = [guid]::Empty
    if ($Status.device -cnotmatch '^bfp-tun-[a-f0-9]{8}$' -or
        -not [guid]::TryParse([string]$Status.interface_guid, [ref]$guid)) {
        throw 'The owned TUN device identity could not be verified; recovery evidence must not assume the adapter is absent.'
    }
    $duplicates = @($ownedDevices | Where-Object { $_.guid -ceq $guid.ToString('D') })
    if ($duplicates.Count -eq 0) {
        [void]$ownedDevices.Add([pscustomobject]@{ device = [string]$Status.device; guid = $guid.ToString('D'); launcher_pid = $Status.pid })
    }
}
function Get-BfpSafeStatus {
    $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
    return [pscustomobject]@{ state = $status.state; running = [bool]$status.running; owner_verified = [bool]$status.owner_verified; proxy_owner_verified = [bool]$status.proxy_owner_verified
        pid = $status.pid; owner_id = $status.owner_id; launcher_start_utc = $status.launcher_start_utc; mode = $status.mode
        port_listening = [bool]$status.port_listening; supervisor_lock_held = [bool]$status.supervisor_lock_held; cleanup_pending = [bool]$status.cleanup_pending
        tun_ready = [bool]$status.tun.ready; tun_phase = [string]$status.tun.phase; tun_needs_recovery = [bool]$status.tun.needs_recovery; device = [string]$status.tun.device; interface_guid = [string]$status.tun.interface_guid }
}
function Assert-BfpOnlyOwnLauncher {
    $status = Get-BfpSafeStatus
    Register-BfpObservedDevice $status
    if ($status.running -or $status.state -in @('owner_mismatch','owner_unverifiable','invalid_record')) {
        $owned = @($ownedLaunchers | Where-Object { $_.pid -eq $status.pid -and $_.start_utc -ceq $status.launcher_start_utc })
        if ($owned.Count -ne 1) { throw 'A launcher not owned by this verification is present; it will not be stopped.' }
    }
    return $status
}
function Invoke-BfpVerificationControl([ValidateSet('check','stop')][string]$Action, [int]$TimeoutSeconds) {
    if ($Action -eq 'stop') {
        [void](Assert-BfpOnlyOwnLauncher)
        # A timed-out stop remains responsible for recovery. Never race it
        # with a second worker, and never kill it to satisfy a timer.
        $activeRecovery = @($recoveryOperations | Where-Object { -not $_.HasExited })
        if ($activeRecovery.Count -gt 0) {
            throw 'An earlier owned recovery worker is still active; it was retained and no overlapping stop was started.'
        }
    }
    $tag = 'tun-' + $runId + '-' + $Action + '-' + [guid]::NewGuid().ToString('N')
    $stdout = Join-Path $resultDirectory ($tag + '.out.log')
    $stderr = Join-Path $resultDirectory ($tag + '.err.log')
    $operation = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action',$Action,'-Mode','tun','-Json') -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    [void]$processes.Add($operation)
    # Pin the native process handle before exit, so PS5.1 retains ExitCode.
    [void]$operation.Handle
    if ($Action -eq 'stop') { [void]$recoveryOperations.Add($operation) }
    if (-not $operation.WaitForExit($TimeoutSeconds * 1000)) {
        throw ('The ' + $Action + ' operation exceeded its bounded wait. Its own recovery process was retained; inspect ' + [IO.Path]::GetFileName($stderr) + '.')
    }
    $output = [IO.File]::ReadAllText($stdout)
    if ($output.Length -gt 32768) { throw ('The ' + $Action + ' response was too large; logs were retained.') }
    try { $reply = $output | ConvertFrom-Json -ErrorAction Stop }
    catch { throw ('The ' + $Action + ' response was invalid; inspect the retained control logs.') }
    $operation.Refresh()
    $controlExit = $operation.ExitCode
    if ($null -eq $controlExit -or $controlExit -ne 0) {
        throw ('The ' + $Action + ' operation did not exit successfully; inspect the retained control logs.')
    }
    if ($Action -eq 'check') {
        if ($reply.success -isnot [bool] -or $reply.success -ne $true -or $reply.check_path -cne 'tun' -or $reply.mode -cne 'tun' -or $reply.exit_ip -cne '192.0.2.10' -or $null -ne $reply.proxy) {
            $reason = if ($reply.error) { [string]$reply.error } elseif ($reply.reason) { [string]$reply.reason } else { 'The real HTTPS request did not prove the direct TUN path and authorized Los Angeles exit.' }
            if ($reason.Length -gt 1000) { $reason = $reason.Substring(0,1000) }
            throw ('check failed: ' + $reason)
        }
        $owner = Assert-BfpOnlyOwnLauncher
        if (-not $owner.running -or -not $owner.owner_verified -or -not $owner.proxy_owner_verified -or -not $owner.tun_ready -or $owner.mode -cne 'tun' -or $reply.owner_id -cne $owner.owner_id) {
            throw 'The successful HTTPS reply did not belong to the current verified launcher.'
        }
        return [pscustomobject]@{ success = $true; mode = $reply.mode; check_path = $reply.check_path; exit_ip = $reply.exit_ip; owner_id = $reply.owner_id; control_exit_code = $controlExit }
    }
    if ($reply.cleanup_complete -isnot [bool] -or $reply.cleanup_complete -ne $true -or $reply.stopped -isnot [bool] -or $reply.stopped -ne $true -or $reply.state -cne 'stopped') {
        $reason = if ($reply.error) { [string]$reply.error } elseif ($reply.reason) { [string]$reply.reason } else { 'The wrapper did not confirm that stop and recovery completed.' }
        if ($reason.Length -gt 1000) { $reason = $reason.Substring(0,1000) }
        throw ('stop failed: ' + $reason)
    }
    return [pscustomobject]@{ stopped = [bool]$reply.stopped; cleanup_complete = [bool]$reply.cleanup_complete; state = $reply.state; control_exit_code = $controlExit }
}
function Start-BfpVerificationTun([string]$Name) {
    [void](Get-BfpVerificationTimeout 40)
    $tag = 'tun-' + $runId + '-' + $Name
    $stdout = Join-Path $resultDirectory ($tag + '.out.log')
    $stderr = Join-Path $resultDirectory ($tag + '.err.log')
    $launcher = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start','-Mode','tun') -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    [void]$processes.Add($launcher)
    # Register the creation time through a pinned handle, using the same
    # FILETIME conversion as the public lifecycle ownership checks.
    $launcherHandle = [BfpDesktopProcessV1.Lease]::Open($launcher.Id,$false)
    [void]$launcherHandles.Add($launcherHandle)
    $started = $launcherHandle.StartedUtc.ToString('o')
    [void]$ownedLaunchers.Add([pscustomobject]@{ pid = $launcher.Id; start_utc = $started })
    $deadline = [DateTime]::UtcNow.AddSeconds((Get-BfpVerificationTimeout 40))
    do {
        $status = Get-BfpSafeStatus
        Register-BfpObservedDevice $status
        if ($status.running -and $status.owner_verified -and $status.proxy_owner_verified -and $status.mode -ceq 'tun' -and $status.tun_ready) {
            if ($status.pid -ne $launcher.Id -or $status.launcher_start_utc -cne $started -or $status.device -cnotmatch '^bfp-tun-[a-f0-9]{8}$') {
                throw 'The ready TUN does not belong to this verification launcher.'
            }
            return $status
        }
        if ($launcher.HasExited) { throw ('The TUN launcher exited before readiness; inspect ' + [IO.Path]::GetFileName($stderr) + '.') }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw ('TUN readiness was not reached within its bounded wait; inspect ' + [IO.Path]::GetFileName($stderr) + '.')
}
function Get-BfpVerifiedProcessChain($ExpectedStatus) {
    $record = Read-BfpDesktopOwnerRecord -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
    if ($null -eq $record -or $record.owner_id -cne $ExpectedStatus.owner_id) { throw 'The TUN owner changed before fault injection.' }
    $launcher = $null; $supervisor = $null; $child = $null; $transferred = $false
    try {
        $launcher = [BfpDesktopProcessV1.Lease]::Open([int]$record.launcher_pid,$true)
        if (-not (Test-BfpDesktopProcessOwner $launcher $record $paths.LauncherScript)) { throw 'The actual launcher handle did not verify.' }
        $childPath = Assert-BfpDesktopPath (Join-Path $paths.NativeDirectory 'bin\mihomo-bfp-windows-amd64.exe') $paths.ProjectRoot
        $supervisorPath = Assert-BfpDesktopPath (Join-Path $paths.NativeDirectory 'bin\bfp-windows-amd64.exe') $paths.ProjectRoot
        $config = Assert-BfpDesktopPath (Join-Path $paths.RuntimeDirectory 'native-tun.generated.yaml') $paths.ProjectRoot
        foreach ($listener in @(Get-NetTCPConnection -LocalPort 17890 -State Listen -ErrorAction Stop)) {
            try {
                $child = [BfpDesktopProcessV1.Lease]::Open([int]$listener.OwningProcess,$false)
                if (-not $child.Alive -or $child.Executable -ne $childPath) { continue }
                $supervisor = [BfpDesktopProcessV1.Lease]::Open($child.ParentId,$true)
                if (-not $supervisor.Alive -or $supervisor.Executable -ne $supervisorPath -or $supervisor.ParentId -ne $launcher.Id -or
                    $supervisor.StartedUtc -lt $launcher.StartedUtc -or $child.StartedUtc -lt $supervisor.StartedUtc) { continue }
                if (-not (Test-BfpDesktopArguments ($supervisor.CommandLine()) @{ '-runtime' = $paths.RuntimeDirectory; '-config' = $config } 'native-supervise') -or
                    -not (Test-BfpDesktopArguments ($child.CommandLine()) @{ '-d' = $paths.RuntimeDirectory; '-f' = $config })) { continue }
                $latest = Get-BfpSafeStatus
                if (-not $latest.owner_verified -or -not $latest.proxy_owner_verified -or $latest.owner_id -cne $record.owner_id) { throw 'Process ownership changed before fault injection.' }
                $transferred = $true
                return [pscustomobject]@{ Launcher = $launcher; Supervisor = $supervisor; Child = $child; OwnerRecord = $record; OwnerId = $record.owner_id }
            } finally {
                if (-not $transferred) {
                    if ($null -ne $child) { $child.Dispose(); $child = $null }
                    if ($null -ne $supervisor) { $supervisor.Dispose(); $supervisor = $null }
                }
            }
        }
        throw 'The real launcher, native supervisor and listening child chain could not be verified; no fault was injected.'
    } finally { if (-not $transferred -and $null -ne $launcher) { $launcher.Dispose() } }
}
function Get-BfpCleanupEvidence {
    $status = Get-BfpSafeStatus
    $inventory = @(Get-BfpAdapterInventory)
    $adapters = @($inventory | Where-Object {
        $entry = $_
        @($ownedDevices | Where-Object { $_.device -ceq $entry.name -or $_.guid -ceq $entry.guid }).Count -gt 0
    })
    # Compare every adapter identity as well as each observed owned device.
    # This catches a failed startup's adapter even if readiness was never
    # reached and its device name was never observed, including renamed TUNs.
    $baselineInventoryHash = Get-BfpDesktopHash (ConvertTo-Json -InputObject $adapterBaseline -Depth 3 -Compress)
    $currentInventoryHash = Get-BfpDesktopHash (ConvertTo-Json -InputObject $inventory -Depth 3 -Compress)
    $inventoryMatch = $baselineInventoryHash -ceq $currentInventoryHash
    $journalNames = @('bfp-windows-tun-journal.json','bfp-tun-supervisor.json','native-tun.generated.yaml')
    $retained = @($journalNames | Where-Object { Test-Path -LiteralPath (Join-Path $paths.RuntimeDirectory $_) })
    $current = Get-BfpNetworkBaseline
    $dnsMatch = $current.dns_sha256 -ceq $baseline.dns_sha256
    $routeMatch = $current.default_routes_sha256 -ceq $baseline.default_routes_sha256
    return [pscustomobject]@{ owned_adapter_absent = $adapters.Count -eq 0 -and $inventoryMatch; observed_owned_device_count = $ownedDevices.Count
        adapter_inventory_baseline_equal = $inventoryMatch; adapter_inventory_sha256_after = $currentInventoryHash
        journal_files_absent = $retained.Count -eq 0; retained_artifact_names = $retained
        physical_dns_baseline_equal = $dnsMatch; default_routes_baseline_equal = $routeMatch
        dns_sha256_after = $current.dns_sha256; default_routes_sha256_after = $current.default_routes_sha256
        client_stopped = -not $status.running; proxy_port_closed = -not $status.port_listening; supervisor_lock_released = -not $status.supervisor_lock_held
        pass = $adapters.Count -eq 0 -and $inventoryMatch -and $retained.Count -eq 0 -and $dnsMatch -and $routeMatch -and -not $status.running -and -not $status.port_listening -and -not $status.supervisor_lock_held -and -not $status.tun_needs_recovery }
}

try {
    $initial = Get-BfpSafeStatus
    $existingArtifacts = @(@('bfp-windows-tun-journal.json','bfp-tun-supervisor.json','native-tun.generated.yaml') |
        Where-Object { Test-Path -LiteralPath (Join-Path $paths.RuntimeDirectory $_) })
    if ($initial.running -or $initial.cleanup_pending -or $initial.port_listening -or $initial.tun_needs_recovery -or
        $existingArtifacts.Count -gt 0 -or $initial.state -in @('invalid_record','owner_mismatch','owner_unverifiable')) {
        throw 'An existing client or recovery record is present. Stop/recover it explicitly before verification; it will not be touched.'
    }
    $baseline = Get-BfpNetworkBaseline
    $adapterBaseline = @(Get-BfpAdapterInventory)
    $result.baseline = $baseline
    $result.adapter_inventory_baseline_count = $adapterBaseline.Count
    $result.adapter_inventory_baseline_sha256 = Get-BfpDesktopHash (ConvertTo-Json -InputObject $adapterBaseline -Depth 3 -Compress)
    $accepted = $true
    $normal = [ordered]@{ name = 'normal_stop'; ready = $false; https = $null; stop = $null; cleanup = $null; pass = $false }
    [void]$scenarios.Add($normal)
    $ready = Start-BfpVerificationTun 'normal'
    $normal.ready = $true; $normal.launcher_pid = $ready.pid; $normal.owner_id = $ready.owner_id; $normal.device = $ready.device
    $requestCount++
    $normal.https = Invoke-BfpVerificationControl 'check' (Get-BfpVerificationTimeout 22)
    $normal.stop = Invoke-BfpVerificationControl 'stop' (Get-BfpVerificationTimeout 35)
    $normal.cleanup = Get-BfpCleanupEvidence
    if (-not $normal.cleanup.pass) { throw 'Normal stop did not restore the full owned-resource and network baseline.' }
    $normal.pass = $true

    $fault = [ordered]@{ name = 'supervisor_and_launcher_force_termination'; ready = $false; https = $null; verified_chain = $null; child_exited = $false; stop = $null; cleanup = $null; pass = $false }
    [void]$scenarios.Add($fault)
    $ready = Start-BfpVerificationTun 'force'
    $fault.ready = $true; $fault.launcher_pid = $ready.pid; $fault.owner_id = $ready.owner_id; $fault.device = $ready.device
    $requestCount++
    $fault.https = Invoke-BfpVerificationControl 'check' (Get-BfpVerificationTimeout 22)
    $chain = Get-BfpVerifiedProcessChain $ready
    $fault.verified_chain = [ordered]@{ owner_id = $chain.OwnerId; launcher_pid = $chain.Launcher.Id; supervisor_pid = $chain.Supervisor.Id; child_pid = $chain.Child.Id
        launcher_started_utc = $chain.Launcher.StartedUtc.ToString('o'); supervisor_started_utc = $chain.Supervisor.StartedUtc.ToString('o'); child_started_utc = $chain.Child.StartedUtc.ToString('o')
        handle_identity_verified = $true; launcher_terminated = $false; supervisor_terminated = $false }
    if (-not (Test-BfpDesktopProcessOwner $chain.Launcher $chain.OwnerRecord $paths.LauncherScript) -or -not $chain.Supervisor.Alive -or -not $chain.Child.Alive) {
        throw 'The verified process chain ended before fault injection; no unknown process was terminated.'
    }
    # End the wrapper first so its PowerShell finally cannot mask the forced
    # supervisor failure. These handles pin the verified original processes.
    $chain.Launcher.Terminate(); $fault.verified_chain.launcher_terminated = $true
    if (-not $chain.Supervisor.Alive) { throw 'The supervisor exited before forced termination; the requested supervisor crash scenario was not proven.' }
    $chain.Supervisor.Terminate(); $fault.verified_chain.supervisor_terminated = $true
    if (-not $fault.verified_chain.launcher_terminated -or -not $fault.verified_chain.supervisor_terminated) {
        throw 'Both verified force terminations are required to prove this scenario.'
    }
    $fault.child_exited = $chain.Child.Wait((Get-BfpVerificationTimeout 10) * 1000)
    if (-not $fault.child_exited) { throw 'The job-owned Mihomo child remained alive after the verified supervisor was terminated.' }
    $fault.stop = Invoke-BfpVerificationControl 'stop' (Get-BfpVerificationTimeout 35)
    $fault.cleanup = Get-BfpCleanupEvidence
    if (-not $fault.cleanup.pass) { throw 'Force termination recovery did not restore the full owned-resource and network baseline.' }
    $fault.pass = $true
} catch {
    $message = $_.Exception.Message
    if ($message.Length -gt 1500) { $message = $message.Substring(0,1500) }
    [void]$failures.Add($message)
} finally {
    if ($accepted) {
        try {
            foreach ($worker in @($recoveryOperations | Where-Object { -not $_.HasExited })) {
                if (-not $worker.WaitForExit((Get-BfpVerificationTimeout 35 -Cleanup) * 1000)) {
                    throw 'An owned recovery worker remains active after the final bounded wait; its process, journals and diagnostics were retained.'
                }
            }
            [void](Invoke-BfpVerificationControl 'stop' (Get-BfpVerificationTimeout 35 -Cleanup))
            $finalCleanup = Get-BfpCleanupEvidence
            if (-not $finalCleanup.pass) { throw 'Final recovery did not restore resources/baseline; retained journals and diagnostics were preserved.' }
        } catch {
            $result.cleanup_failed = $true
            [void]$failures.Add(('Final cleanup failed: ' + $_.Exception.Message))
            try { $finalCleanup = Get-BfpCleanupEvidence }
            catch { [void]$failures.Add(('Final cleanup evidence could not be read: ' + $_.Exception.Message)) }
        }
    }
    if ($null -ne $chain) {
        foreach ($handle in @($chain.Child,$chain.Supervisor,$chain.Launcher)) {
            if ($null -ne $handle) {
                try { $handle.Dispose() } catch { [void]$failures.Add(('Process handle disposal failed: ' + $_.Exception.Message)) }
            }
        }
    }
    foreach ($handle in $launcherHandles) {
        try { $handle.Dispose() } catch { [void]$failures.Add(('Launcher handle disposal failed: ' + $_.Exception.Message)) }
    }
    foreach ($process in $processes) {
        try { $process.Dispose() } catch { [void]$failures.Add(('Control process disposal failed: ' + $_.Exception.Message)) }
    }
    $result.requested_https_checks = $requestCount
    $result.scenarios = @($scenarios.ToArray())
    $result.final_cleanup = $finalCleanup
    $result.errors = @($failures.ToArray())
    $result.completed_utc = [DateTime]::UtcNow.ToString('o')
    $result.elapsed_seconds = [Math]::Round($clock.Elapsed.TotalSeconds,2)
    $result.time_budget_met = $clock.Elapsed.TotalSeconds -le 120
    $result.pass = $accepted -and $scenarios.Count -eq 2 -and @($scenarios | Where-Object { -not $_.pass }).Count -eq 0 -and $failures.Count -eq 0 -and $null -ne $finalCleanup -and $finalCleanup.pass -and $result.time_budget_met
    $temporary = $ResultPath + '.' + $runId + '.tmp'
    [IO.File]::WriteAllText($temporary,($result | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary,$ResultPath)
}
[ordered]@{ result = $ResultPath; pass = $result.pass; cleanup_failed = $result.cleanup_failed; requested_https_checks = $requestCount; elapsed_seconds = $result.elapsed_seconds } | ConvertTo-Json -Compress
if ($result.pass) { exit 0 }
exit 1

param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
. (Join-Path $PSScriptRoot 'windows-system-proxy.ps1')
$testId = [guid]::NewGuid().ToString('N')
$root = Split-Path -Parent $PSScriptRoot
$testRegistry = 'Software\BFP\Tests\' + $testId
$registry = $testRegistry + '\Internet Settings'
$paths = Get-BfpDesktopPaths $root $testId
$context = [pscustomobject]@{ ProjectRoot = $root; InstanceId = $testId; RunDirectory = $paths.RunDirectory; ProxyAddress = '127.0.0.1:17890' }
$config = Get-BfpSystemProxyConfig $context $registry
$ready = [pscustomobject]@{ instance_id = $testId; owner_id = [guid]::NewGuid().ToString('N'); mode = 'proxy'; running = $true; owner_verified = $true; proxy_owner_verified = $true }
$cases = [Collections.Generic.List[object]]::new()
$notify = { }
$child = $null; $childReady = $null; $childRelease = $null

function Assert-ProxyCase([string]$Name, [bool]$Passed) {
    $cases.Add([pscustomobject]@{ name = $Name; pass = $Passed })
    if (-not $Passed) { throw ('System proxy verification failed: ' + $Name) }
}

function Reset-ProxyFixture {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($registry)
    try {
        foreach ($name in $script:BfpSystemProxyNames) { $key.DeleteValue($name, $false) }
        $key.SetValue('ProxyEnable', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.SetValue('ProxyServer', '127.0.0.1:10808', [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('ProxyOverride', '%LOCALAPPDATA%;*.test;<local>', [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $key.SetValue('AutoConfigURL', '%APPDATA%\private-test.pac', [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $key.SetValue('Unrelated', 'keep-me', [Microsoft.Win32.RegistryValueKind]::String)
    } finally { $key.Dispose() }
    return Get-BfpSystemProxyValues $config
}

try {
    $original = Reset-ProxyFixture
    $notReady = $ready.PSObject.Copy(); $notReady.proxy_owner_verified = $false
    $result = Enable-BfpSystemProxy -Context $context -Status $notReady -RegistrySubKey $registry -Notify $notify
    Assert-ProxyCase 'unowned_proxy_never_takes_over' (-not $result.success -and $result.state -eq 'client_not_ready' -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original) -and -not (Test-Path -LiteralPath $config.BackupPath))

    $enabled = Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify
    Assert-ProxyCase 'enable_applies_manual_proxy_and_disables_pac' ($enabled.success -and $enabled.active -and $enabled.owned -and $enabled.needs_restore -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) (Get-BfpSystemProxyAppliedValues)))
    $acl = Get-Acl -LiteralPath $config.BackupPath
    $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
    Assert-ProxyCase 'backup_acl_is_current_user_and_system_only' ($acl.AreAccessRulesProtected -and $sids.Count -eq 2 -and
        $config.Sid -in $sids -and 'S-1-5-18' -in $sids -and @($acl.Access | Where-Object { $_.AccessControlType -ne 'Allow' }).Count -eq 0)
    $backupBefore = [IO.File]::ReadAllText($config.BackupPath)
    $repeat = Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify
    Assert-ProxyCase 'repeat_enable_preserves_original_snapshot_and_lease' ($repeat.active -and $repeat.lease_id -ceq $enabled.lease_id -and
        [IO.File]::ReadAllText($config.BackupPath) -ceq $backupBefore)
    $summaryJson = $repeat | ConvertTo-Json -Compress
    Assert-ProxyCase 'public_summary_contains_no_saved_values' ($summaryJson -notmatch '10808|private-test|LOCALAPPDATA|APPDATA|ProxyOverride|AutoConfigURL')
    $stale = Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -ExpectedLeaseId ([guid]::NewGuid().ToString('N')) -Notify $notify
    Assert-ProxyCase 'stale_watchdog_cannot_restore_current_lease' (-not $stale.success -and $stale.state -eq 'lease_changed' -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) (Get-BfpSystemProxyAppliedValues)))
    $restored = Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -ExpectedLeaseId $enabled.lease_id -Notify $notify
    Assert-ProxyCase 'restore_preserves_exact_values_types_and_pac' ($restored.success -and -not $restored.needs_restore -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original) -and -not (Test-Path -LiteralPath $config.BackupPath))
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($registry, $false)
    try { $untouched = $key.GetValue('Unrelated') -ceq 'keep-me' } finally { $key.Dispose() }
    Assert-ProxyCase 'unrelated_registry_values_are_untouched' $untouched
    Assert-ProxyCase 'repeat_restore_is_idempotent' ((Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify).state -eq 'inactive')

    # Existing uncommon registry kinds are preserved rather than coerced.
    foreach ($kind in @('String','ExpandString','MultiString','Binary','None','DWord','QWord')) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($registry)
        try {
            foreach ($name in $script:BfpSystemProxyNames) { $key.DeleteValue($name, $false) }
            $data = switch ($kind) {
                'MultiString' { ,([string[]]@('', 'second', '%TEMP%')) }
                'Binary' { ,([byte[]]@(0, 1, 255)) }
                'None' { ,([byte[]]@(255, 0, 10)) }
                'DWord' { [int]-2147483648 }
                'QWord' { [long]9223372036854775807 }
                'ExpandString' { '%USERPROFILE%\literal' }
                default { '' }
            }
            $key.SetValue('ProxyOverride', $data, [Microsoft.Win32.RegistryValueKind]$kind)
        } finally { $key.Dispose() }
        $before = Get-BfpSystemProxyValues $config
        [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify)
        [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify)
        Assert-ProxyCase ('restore_absence_and_kind_' + $kind) (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $before)
    }

    $original = Reset-ProxyFixture
    $enabled = Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($registry, $true)
    try { $key.SetValue('ProxyServer', 'external.test:8080', [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
    $external = Get-BfpSystemProxyValues $config
    $observed = Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry
    Assert-ProxyCase 'external_change_status_is_read_only' ($observed.external_change -and $observed.owned -and $observed.needs_restore -and
        (Test-Path -LiteralPath $config.BackupPath) -and (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $external))
    $result = Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify
    $archive = Join-Path $config.PrivateDirectory ('archive-' + $enabled.lease_id + '.json')
    Assert-ProxyCase 'external_change_is_preserved_and_lease_archived_and_released' ($result.success -and $result.external_change -and $result.archived -and -not $result.owned -and -not $result.needs_restore -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $external) -and -not (Test-Path -LiteralPath $config.BackupPath) -and (Test-Path -LiteralPath $archive))
    [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify)
    $newLease = Read-BfpSystemProxyLease $config
    [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify)
    Assert-ProxyCase 'next_takeover_uses_external_settings_as_new_baseline' ((Test-BfpSystemProxyValuesEqual $newLease.Backup.original $external) -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $external))
    $original = Reset-ProxyFixture

    $beforeWrite = { param($Name, $Index); if ($Index -eq 1) { throw 'Injected registry write failure.' } }
    try { [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify -BeforeWrite $beforeWrite); $failed = $false } catch { $failed = $true }
    Assert-ProxyCase 'partial_setting_failure_rolls_back' ($failed -and (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original) -and
        (Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry).state -eq 'inactive')

    $script:proxyNotifyCalls = 0
    $onceFail = { $script:proxyNotifyCalls++; if ($script:proxyNotifyCalls -eq 1) { throw 'Injected notification failure.' } }
    try { [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $onceFail); $failed = $false } catch { $failed = $true }
    Assert-ProxyCase 'notification_failure_rolls_back_and_renotifies' ($failed -and $script:proxyNotifyCalls -eq 2 -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original) -and (Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry).state -eq 'inactive')

    try { [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify { throw 'Injected persistent notification failure.' }); $failed = $false } catch { $failed = $true }
    $pending = Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry
    Assert-ProxyCase 'failed_rollback_notification_retains_recoverable_journal' ($failed -and $pending.needs_restore -and $pending.state -eq 'already_restored' -and
        (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original))
    [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -ExpectedLeaseId $pending.lease_id -Notify $notify)

    $enabled = Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify
    $otherId = [guid]::NewGuid().ToString('N'); $otherPaths = Get-BfpDesktopPaths $root $otherId
    $otherContext = [pscustomobject]@{ ProjectRoot = $root; InstanceId = $otherId; RunDirectory = $otherPaths.RunDirectory; ProxyAddress = '127.0.0.1:17890' }
    $otherStatus = $ready.PSObject.Copy(); $otherStatus.instance_id = $otherId; $otherStatus.owner_id = [guid]::NewGuid().ToString('N')
    $other = Enable-BfpSystemProxy -Context $otherContext -Status $otherStatus -RegistrySubKey $registry -Notify $notify
    Assert-ProxyCase 'another_instance_cannot_replace_persistent_lease' (-not $other.success -and $other.state -eq 'owned_elsewhere' -and
        (Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry).lease_id -ceq $enabled.lease_id)
    [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify)

    $script:proxyReentryRejected = $false
    $reentry = {
        param($Name, $Index)
        if ($Index -eq 0) {
            try { [void](Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry) }
            catch { $script:proxyReentryRejected = $true }
        }
    }
    [void](Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify -BeforeWrite $reentry)
    Assert-ProxyCase 'same_process_reentrant_operation_is_rejected' $script:proxyReentryRejected
    [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify)

    # Hidden fixtures hold the same lock during a short read-only query or pause
    # after their first registry write, without touching actual Internet Settings.
    $eventSuffix = [guid]::NewGuid().ToString('N')
    $readyName = 'Local\BFPProxyTestReady-' + $eventSuffix
    $releaseName = 'Local\BFPProxyTestRelease-' + $eventSuffix
    $childReady = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $readyName)
    $childRelease = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, $releaseName)
    [void][IO.Directory]::CreateDirectory($paths.RunDirectory)
    $childScript = Join-Path $paths.RunDirectory 'isolated-proxy-child.ps1'
    $source = @'
param([string]$Deploy, [string]$Instance, [string]$Registry, [string]$ReadyEvent, [string]$ReleaseEvent, [int]$ReadOnlyHoldMilliseconds=0)
$ErrorActionPreference = 'Stop'
. (Join-Path $Deploy 'windows-lifecycle.ps1')
. (Join-Path $Deploy 'windows-system-proxy.ps1')
$root = Split-Path -Parent $Deploy
$paths = Get-BfpDesktopPaths $root $Instance
$context = [pscustomobject]@{ ProjectRoot=$root; InstanceId=$Instance; RunDirectory=$paths.RunDirectory; ProxyAddress='127.0.0.1:17890' }
$status = [pscustomobject]@{ instance_id=$Instance; owner_id=[guid]::NewGuid().ToString('N'); mode='proxy'; running=$true; owner_verified=$true; proxy_owner_verified=$true }
$ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEvent)
$release = [Threading.EventWaitHandle]::OpenExisting($ReleaseEvent)
try {
    if ($ReadOnlyHoldMilliseconds -gt 0) {
        $config = Get-BfpSystemProxyConfig $context $Registry
        $mutex = Enter-BfpSystemProxyLock $config
        try {
            [void](Get-BfpSystemProxyStatusCore $config)
            [void]$ready.Set()
            Start-Sleep -Milliseconds $ReadOnlyHoldMilliseconds
        } finally { Exit-BfpSystemProxyLock $mutex }
        return
    }
    [void](Enable-BfpSystemProxy -Context $context -Status $status -RegistrySubKey $Registry -Notify {} -BeforeWrite {
        param($Name, $Index)
        if ($Index -eq 1) { [void]$ready.Set(); if (-not $release.WaitOne(15000)) { throw 'Fixture wait expired.' } }
    })
} finally { $ready.Dispose(); $release.Dispose() }
'@
    [IO.File]::WriteAllText($childScript, $source, [Text.UTF8Encoding]::new($true))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File', ('"' + $childScript + '"'),
        '-Deploy', ('"' + $PSScriptRoot + '"'), '-Instance', $testId, '-Registry', ('"' + $registry + '"'), '-ReadyEvent', $readyName, '-ReleaseEvent', $releaseName)
    $child = Start-Process -FilePath $powershell -ArgumentList ($args + @('-ReadOnlyHoldMilliseconds','700')) -WindowStyle Hidden -PassThru
    [void]$child.Handle
    if (-not $childReady.WaitOne(10000)) { throw 'Fixture child did not reach its isolated read-only query.' }
    $wait = [Diagnostics.Stopwatch]::StartNew()
    $enabled = Enable-BfpSystemProxy -Context $context -Status $ready -RegistrySubKey $registry -Notify $notify
    $wait.Stop()
    if (-not $child.WaitForExit(3000)) { throw 'Short read-only fixture did not exit.' }
    $child.Refresh()
    Assert-ProxyCase 'short_read_only_contention_allows_takeover_after_bounded_wait' ($enabled.success -and $enabled.active -and
        $wait.ElapsedMilliseconds -ge 400 -and $wait.ElapsedMilliseconds -lt 5000 -and $child.ExitCode -eq 0)
    $child.Dispose(); $child = $null
    [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify)
    [void]$childReady.Reset()
    $child = Start-Process -FilePath $powershell -ArgumentList $args -WindowStyle Hidden -PassThru
    [void]$child.Handle
    if (-not $childReady.WaitOne(10000)) { throw 'Fixture child did not reach its isolated partial write.' }
    $wait = [Diagnostics.Stopwatch]::StartNew()
    try { [void](Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry); $locked = $false }
    catch { $locked = $_.Exception.Message -ceq 'Another system proxy operation is in progress.' }
    $wait.Stop()
    Assert-ProxyCase 'long_cross_process_contention_fails_within_bounded_wait' ($locked -and
        $wait.ElapsedMilliseconds -ge 1800 -and $wait.ElapsedMilliseconds -lt 5000)
    $child.Kill(); $child.WaitForExit(); $child.Dispose(); $child = $null
    $pending = Get-BfpSystemProxyStatus -Context $context -RegistrySubKey $registry
    Assert-ProxyCase 'killed_partial_takeover_is_recovery_pending' ($pending.state -eq 'recovery_pending' -and $pending.needs_restore)
    $result = Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -ExpectedLeaseId $pending.lease_id -Notify $notify
    Assert-ProxyCase 'killed_partial_takeover_restores_exact_original' ($result.success -and (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $original))
} finally {
    if ($null -ne $childRelease) { [void]$childRelease.Set() }
    if ($null -ne $child) { if (-not $child.HasExited) { [void]$child.WaitForExit(3000); if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() } }; $child.Dispose() }
    if ($null -ne $childReady) { $childReady.Dispose() }
    if ($null -ne $childRelease) { $childRelease.Dispose() }
    try { [void](Restore-BfpSystemProxy -Context $context -RegistrySubKey $registry -Notify $notify) } catch { }
    # These paths are fixed descendants of a unique isolated HKCU fixture.
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testRegistry, $false)
    $summary = [pscustomobject]@{ pass = (@($cases | Where-Object { -not $_.pass }).Count -eq 0 -and $cases.Count -eq 28);
        cases = @($cases.ToArray()); ps_version = $PSVersionTable.PSVersion.ToString(); scope = 'Isolated HKCU test key only; no real Internet Settings reads or writes; notifications injected.' }
    [void][IO.Directory]::CreateDirectory($paths.RunDirectory)
    [IO.File]::WriteAllText((Join-Path $paths.RunDirectory 'system-proxy-test-result.json'), ($summary | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    $summary | ConvertTo-Json -Depth 6
}

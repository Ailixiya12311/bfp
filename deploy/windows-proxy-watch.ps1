param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$ExpectedLeaseId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$ReadyId)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-context.ps1')
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
. (Join-Path $PSScriptRoot 'windows-system-proxy.ps1')
$context = Get-BfpDesktopContext -DeployRoot $PSScriptRoot
$initialProxy = Get-BfpSystemProxyStatus -Context $context
if (-not $initialProxy.owned -or $initialProxy.lease_id -cne $ExpectedLeaseId) { exit 1 }
$readyPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory ('proxy-watch-' + $ReadyId + '.json')) $context.ProjectRoot
$temporaryReady = $readyPath + '.tmp'
[IO.File]::WriteAllText($temporaryReady, ([ordered]@{ lease_id = $ExpectedLeaseId; watcher_pid = $PID } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
[IO.File]::Move($temporaryReady, $readyPath)
# This watcher remains independent of the launcher and control window. It
# holds no process-control lock and never terminates another process.
while ($true) {
    try {
        $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $proxy = Get-BfpSystemProxyStatus -Context $context -Status $status
        if (-not $proxy.owned -or $proxy.lease_id -cne $ExpectedLeaseId) { exit 0 }
        $ownerEnded = $status.state -in @('stopped','stale_record','stopping')
        $newVerifiedOwner = $status.running -and $status.owner_verified -and $status.owner_id -and $status.owner_id -cne $proxy.owner_id
        if ($ownerEnded -or $newVerifiedOwner) {
            $restored = Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $ExpectedLeaseId
            if ($restored.success -or $restored.external_change) { exit 0 }
        }
    } catch {
        # Transient registry/process reads leave the protected recovery record
        # intact. A later poll or the user's restore action can finish recovery.
    }
    Start-Sleep -Seconds 2
}

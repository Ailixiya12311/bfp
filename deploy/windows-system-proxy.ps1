# Current-user WinINET proxy lease. Public results never contain saved settings.
$script:BfpSystemProxyNames = @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL')
if ($null -eq (Get-Variable BfpSystemProxyBusy -Scope Script -ErrorAction SilentlyContinue)) { $script:BfpSystemProxyBusy = $false }

function Get-BfpSystemProxyConfig($Context, [string]$RegistrySubKey) {
    $paths = Get-BfpDesktopPaths -ProjectRoot $Context.ProjectRoot -InstanceId $Context.InstanceId
    if ([IO.Path]::GetFullPath([string]$Context.RunDirectory) -ne $paths.RunDirectory -or $Context.ProxyAddress -cne '127.0.0.1:17890') {
        throw 'Invalid system proxy context.'
    }
    $standard = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($RegistrySubKey -cne $standard -and $RegistrySubKey -cnotmatch '^Software\\BFP\\Tests\\[a-f0-9]{32}\\Internet Settings$') {
        throw 'Invalid system proxy registry target.'
    }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $hash = Get-BfpDesktopHash $RegistrySubKey.ToLowerInvariant()
    $claim = if ($RegistrySubKey -ceq $standard) { 'Software\BFP\SystemProxyOwnership\' + $hash } else { $RegistrySubKey + '\BFPSystemProxyOwnership' }
    $private = Assert-BfpDesktopPath (Join-Path $paths.RunDirectory 'system-proxy') $paths.ProjectRoot
    [pscustomobject]@{
        Context = $Context; Paths = $paths; Sid = $sid; RegistrySubKey = $RegistrySubKey; ClaimSubKey = $claim
        PrivateDirectory = $private; BackupPath = (Assert-BfpDesktopPath (Join-Path $private 'lease.json') $paths.ProjectRoot)
        MutexName = ('Global\BFP-WinINET-Proxy-' + $sid + '-' + $hash)
    }
}

function Enter-BfpSystemProxyLock($Config) {
    if ($script:BfpSystemProxyBusy) { throw 'Another system proxy operation is in progress.' }
    $mutex = [Threading.Mutex]::new($false, $Config.MutexName)
    $acquired = $false
    try {
        # Status polls share this mutex with takeover/restore. Give an in-flight
        # short poll time to finish without treating normal contention as a
        # failed client start; a genuinely stalled operation still fails within
        # two seconds. Reentrant calls above must keep failing immediately.
        try { $acquired = $mutex.WaitOne(2000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Another system proxy operation is in progress.' }
        $script:BfpSystemProxyBusy = $true
        return $mutex
    } catch { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose(); throw }
}

function Exit-BfpSystemProxyLock($Mutex) {
    $script:BfpSystemProxyBusy = $false
    $Mutex.ReleaseMutex(); $Mutex.Dispose()
}

function Get-BfpSystemProxyValue($Key, [string]$Name) {
    if ($null -eq $Key -or $Name -notin $Key.GetValueNames()) { return [pscustomobject][ordered]@{ exists = $false; kind = $null; data = $null } }
    $kind = $Key.GetValueKind($Name).ToString()
    $value = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $data = switch ($kind) {
        'DWord' { ([int]$value).ToString([Globalization.CultureInfo]::InvariantCulture) }
        'QWord' { ([long]$value).ToString([Globalization.CultureInfo]::InvariantCulture) }
        'Binary' { [Convert]::ToBase64String([byte[]]$value) }
        'None' { [Convert]::ToBase64String([byte[]]$value) }
        'MultiString' { ,([string[]]$value) }
        'String' { [string]$value }
        'ExpandString' { [string]$value }
        default { throw 'Unsupported system proxy registry value type.' }
    }
    return [pscustomobject][ordered]@{ exists = $true; kind = $kind; data = $data }
}

function Get-BfpSystemProxyValues($Config) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Config.RegistrySubKey, $false)
    try {
        $values = [ordered]@{}
        foreach ($name in $script:BfpSystemProxyNames) { $values[$name] = Get-BfpSystemProxyValue $key $name }
        return [pscustomobject]$values
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function Get-BfpSystemProxyAppliedValues {
    [pscustomobject][ordered]@{
        ProxyEnable = [pscustomobject][ordered]@{ exists = $true; kind = 'DWord'; data = '1' }
        ProxyServer = [pscustomobject][ordered]@{ exists = $true; kind = 'String'; data = '127.0.0.1:17890' }
        ProxyOverride = [pscustomobject][ordered]@{ exists = $true; kind = 'String'; data = '<local>' }
        AutoConfigURL = [pscustomobject][ordered]@{ exists = $false; kind = $null; data = $null }
    }
}

function Test-BfpSystemProxyValueEqual($Left, $Right) {
    if ($Left.exists -ne $Right.exists) { return $false }
    if (-not $Left.exists) { return $true }
    if ($Left.kind -cne $Right.kind) { return $false }
    if ($Left.kind -ceq 'MultiString') {
        $a = @($Left.data); $b = @($Right.data)
        if ($a.Count -ne $b.Count) { return $false }
        for ($i = 0; $i -lt $a.Count; $i++) { if ([string]$a[$i] -cne [string]$b[$i]) { return $false } }
        return $true
    }
    return [string]$Left.data -ceq [string]$Right.data
}

function Test-BfpSystemProxyValuesEqual($Left, $Right) {
    foreach ($name in $script:BfpSystemProxyNames) { if (-not (Test-BfpSystemProxyValueEqual $Left.$name $Right.$name)) { return $false } }
    return $true
}

function Assert-BfpSystemProxyValues($Values) {
    if ($Values -isnot [pscustomobject] -or @($Values.PSObject.Properties).Count -ne 4) { throw 'Invalid saved system proxy values.' }
    foreach ($name in $script:BfpSystemProxyNames) {
        $value = $Values.$name
        if ($null -eq $value -or $value.exists -isnot [bool] -or @($value.PSObject.Properties).Count -ne 3 -or
            @($value.PSObject.Properties.Name | Where-Object { $_ -notin @('exists','kind','data') }).Count -ne 0) { throw 'Invalid saved system proxy value.' }
        if (-not $value.exists) { if ($null -ne $value.kind -or $null -ne $value.data) { throw 'Invalid absent system proxy value.' }; continue }
        if ($value.kind -cnotin @('DWord','QWord','Binary','None','MultiString','String','ExpandString')) { throw 'Invalid saved system proxy type.' }
        switch ($value.kind) {
            'DWord' { [void][int]::Parse([string]$value.data, [Globalization.CultureInfo]::InvariantCulture) }
            'QWord' { [void][long]::Parse([string]$value.data, [Globalization.CultureInfo]::InvariantCulture) }
            'Binary' { [void][Convert]::FromBase64String([string]$value.data) }
            'None' { [void][Convert]::FromBase64String([string]$value.data) }
            'MultiString' { foreach ($entry in @($value.data)) { if ($entry -isnot [string]) { throw 'Invalid saved system proxy data.' } } }
            default { if ($value.data -isnot [string]) { throw 'Invalid saved system proxy data.' } }
        }
    }
}

function Set-BfpSystemProxyValues($Config, $Values, [scriptblock]$BeforeWrite) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($Config.RegistrySubKey)
    try {
        $index = 0
        foreach ($name in $script:BfpSystemProxyNames) {
            if ($null -ne $BeforeWrite) { [void](& $BeforeWrite $name $index) }
            $value = $Values.$name
            if (-not $value.exists) { $key.DeleteValue($name, $false) }
            else {
                $data = switch ($value.kind) {
                    'DWord' { [int]::Parse([string]$value.data, [Globalization.CultureInfo]::InvariantCulture) }
                    'QWord' { [long]::Parse([string]$value.data, [Globalization.CultureInfo]::InvariantCulture) }
                    'Binary' { ,([Convert]::FromBase64String([string]$value.data)) }
                    'None' { ,([Convert]::FromBase64String([string]$value.data)) }
                    'MultiString' { ,([string[]]@($value.data)) }
                    default { [string]$value.data }
                }
                $key.SetValue($name, $data, [Microsoft.Win32.RegistryValueKind]$value.kind)
            }
            $index++
        }
        $key.Flush()
    } finally { $key.Dispose() }
}

function Set-BfpSystemProxyPrivateAcl([string]$Path, [bool]$Directory) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if ($Directory) {
        $acl = [IO.Directory]::GetAccessControl($Path, [Security.AccessControl.AccessControlSections]::Access)
        $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { $acl = [IO.File]::GetAccessControl($Path, [Security.AccessControl.AccessControlSections]::Access); $inherit = [Security.AccessControl.InheritanceFlags]::None }
    # Read and write the DACL only; constructing a fresh all-sections security
    # descriptor can ask Set-Acl to write a SACL requiring administrator rights.
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
    foreach ($identity in @($sid, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    if ($Directory) { [IO.Directory]::SetAccessControl($Path, $acl) } else { [IO.File]::SetAccessControl($Path, $acl) }
}

function Write-BfpSystemProxyBackup($Config, $Backup) {
    $json = $Backup | ConvertTo-Json -Depth 10 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 262144) { throw 'Saved system proxy settings exceed the backup limit.' }
    [void][IO.Directory]::CreateDirectory($Config.PrivateDirectory)
    [void](Assert-BfpDesktopPath $Config.PrivateDirectory $Config.Paths.ProjectRoot)
    Set-BfpSystemProxyPrivateAcl $Config.PrivateDirectory $true
    $temporary = Assert-BfpDesktopPath (Join-Path $Config.PrivateDirectory ([guid]::NewGuid().ToString('N') + '.tmp')) $Config.Paths.ProjectRoot
    try {
        # The directory is private before any saved PAC URL is written.
        [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
        Set-BfpSystemProxyPrivateAcl $temporary $false
        if (Test-Path -LiteralPath $Config.BackupPath) { [IO.File]::Replace($temporary, $Config.BackupPath, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Config.BackupPath) }
    } finally { if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) } }
}

function Read-BfpSystemProxyLease($Config) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Config.ClaimSubKey, $false)
    try { $json = if ($null -ne $key) { $key.GetValue('Lease', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null } }
    finally { if ($null -ne $key) { $key.Dispose() } }
    if ($null -eq $json) { return $null }
    try {
        if ($json -isnot [string] -or $json.Length -gt 8192) { throw 'Invalid claim.' }
        $claim = $json | ConvertFrom-Json -ErrorAction Stop
        if ($claim.version -ne 1 -or $claim.instance_id -cnotmatch '^[a-f0-9]{32}$' -or $claim.lease_id -cnotmatch '^[a-f0-9]{32}$' -or
            $claim.owner_id -cnotmatch '^[a-f0-9]{32}$' -or $claim.user_sid -cne $Config.Sid -or $claim.registry_subkey -cne $Config.RegistrySubKey) { throw 'Invalid claim.' }
        if ($claim.instance_id -cne $Config.Context.InstanceId -or [string]$claim.backup_path -cne $Config.BackupPath) {
            return [pscustomobject]@{ Claim = $claim; Backup = $null; Ours = $false }
        }
        [void](Assert-BfpDesktopPath $Config.BackupPath $Config.Paths.ProjectRoot)
        if (-not (Test-Path -LiteralPath $Config.BackupPath -PathType Leaf) -or (Get-Item -LiteralPath $Config.BackupPath).Length -gt 262144) { throw 'Invalid backup.' }
        $backup = [IO.File]::ReadAllText($Config.BackupPath) | ConvertFrom-Json -ErrorAction Stop
        if ($backup.version -ne 1 -or $backup.instance_id -cne $claim.instance_id -or $backup.lease_id -cne $claim.lease_id -or
            $backup.owner_id -cne $claim.owner_id -or $backup.user_sid -cne $Config.Sid -or $backup.registry_subkey -cne $Config.RegistrySubKey -or
            $backup.phase -cnotin @('preparing','applied')) { throw 'Invalid backup.' }
        Assert-BfpSystemProxyValues $backup.original
        Assert-BfpSystemProxyValues $backup.applied
        if (-not (Test-BfpSystemProxyValuesEqual $backup.applied (Get-BfpSystemProxyAppliedValues))) { throw 'Invalid applied settings.' }
        return [pscustomobject]@{ Claim = $claim; Backup = $backup; Ours = $true }
    } catch { throw 'The saved system proxy lease cannot be safely verified.' }
}

function Get-BfpSystemProxySummary($Config, $Lease, [string]$State, [bool]$Active = $false, [bool]$Success = $true) {
    [pscustomobject][ordered]@{
        success = $Success; state = $State; owned = ($null -ne $Lease -and $Lease.Ours); active = $Active
        needs_restore = ($null -ne $Lease -and $Lease.Ours); external_change = ($State -eq 'external_change')
        lease_id = $(if ($null -ne $Lease) { [string]$Lease.Claim.lease_id } else { $null })
        owner_id = $(if ($null -ne $Lease) { [string]$Lease.Claim.owner_id } else { $null }); instance_id = $Config.Context.InstanceId
    }
}

function Test-BfpSystemProxyPreparingCompatible($Current, $Backup) {
    foreach ($name in $script:BfpSystemProxyNames) {
        if (-not (Test-BfpSystemProxyValueEqual $Current.$name $Backup.original.$name) -and
            -not (Test-BfpSystemProxyValueEqual $Current.$name $Backup.applied.$name)) { return $false }
    }
    return $true
}

function Get-BfpSystemProxyStatusCore($Config) {
    $lease = Read-BfpSystemProxyLease $Config
    if ($null -eq $lease) { return Get-BfpSystemProxySummary $Config $null 'inactive' }
    if (-not $lease.Ours) { return Get-BfpSystemProxySummary $Config $lease 'owned_elsewhere' $false $false }
    $current = Get-BfpSystemProxyValues $Config
    if ($lease.Backup.phase -ceq 'applied' -and (Test-BfpSystemProxyValuesEqual $current $lease.Backup.applied)) { return Get-BfpSystemProxySummary $Config $lease 'active' $true }
    if (Test-BfpSystemProxyValuesEqual $current $lease.Backup.original) { return Get-BfpSystemProxySummary $Config $lease 'already_restored' }
    if ($lease.Backup.phase -ceq 'preparing' -and (Test-BfpSystemProxyPreparingCompatible $current $lease.Backup)) {
        return Get-BfpSystemProxySummary $Config $lease 'recovery_pending'
    }
    return Get-BfpSystemProxySummary $Config $lease 'external_change' $false $false
}

function Invoke-BfpSystemProxyNotify([scriptblock]$Notify) {
    if ($null -ne $Notify) { [void](& $Notify); return }
    if ($null -eq ('BfpWinInetProxyV1.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace BfpWinInetProxyV1 {
    public static class Native {
        [DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length);
    }
}
'@
    }
    if (-not [BfpWinInetProxyV1.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) -or
        -not [BfpWinInetProxyV1.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)) { throw 'Windows could not refresh system proxy settings.' }
}

function Remove-BfpSystemProxyLease($Config) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Config.ClaimSubKey, $true)
    try { if ($null -ne $key) { $key.DeleteValue('Lease', $false); $key.Flush() } }
    finally { if ($null -ne $key) { $key.Dispose() } }
    if (Test-Path -LiteralPath $Config.BackupPath) { [IO.File]::Delete($Config.BackupPath) }
}

function Archive-BfpSystemProxyLease($Config, $Lease) {
    $archive = Assert-BfpDesktopPath (Join-Path $Config.PrivateDirectory ('archive-' + $Lease.Claim.lease_id + '.json')) $Config.Paths.ProjectRoot
    if (Test-Path -LiteralPath $archive) {
        if ((Get-BfpDesktopHash ([IO.File]::ReadAllText($archive))) -cne (Get-BfpDesktopHash ([IO.File]::ReadAllText($Config.BackupPath)))) {
            throw 'The previous system proxy backup archive cannot be safely replaced.'
        }
    } else {
        [IO.File]::Copy($Config.BackupPath, $archive, $false)
        Set-BfpSystemProxyPrivateAcl $archive $false
    }
    # Preserve the protected original snapshot, then relinquish only our own
    # verified lease. No live Internet Settings values are changed here.
    Remove-BfpSystemProxyLease $Config
}

function Restore-BfpSystemProxyCore($Config, [string]$ExpectedLeaseId, [scriptblock]$Notify) {
    $lease = Read-BfpSystemProxyLease $Config
    if ($null -eq $lease) { return Get-BfpSystemProxySummary $Config $null 'inactive' }
    if (-not $lease.Ours) { return Get-BfpSystemProxySummary $Config $lease 'owned_elsewhere' $false $false }
    if ($ExpectedLeaseId -ne '' -and $ExpectedLeaseId -cne $lease.Claim.lease_id) { return Get-BfpSystemProxySummary $Config $lease 'lease_changed' $false $false }
    $current = Get-BfpSystemProxyValues $Config
    $already = Test-BfpSystemProxyValuesEqual $current $lease.Backup.original
    $matches = Test-BfpSystemProxyValuesEqual $current $lease.Backup.applied
    $preparing = $lease.Backup.phase -ceq 'preparing' -and (Test-BfpSystemProxyPreparingCompatible $current $lease.Backup)
    if (-not $already -and -not $matches -and -not $preparing) {
        Archive-BfpSystemProxyLease $Config $lease
        $summary = Get-BfpSystemProxySummary $Config $null 'external_change'
        $summary | Add-Member -NotePropertyName archived -NotePropertyValue $true
        return $summary
    }
    if (-not $already) { Set-BfpSystemProxyValues $Config $lease.Backup.original $null }
    # A failed notification retains the journal. A later restore can safely
    # recognize the already-restored values and finish the notification.
    Invoke-BfpSystemProxyNotify $Notify
    Remove-BfpSystemProxyLease $Config
    return Get-BfpSystemProxySummary $Config $null 'restored'
}

function Get-BfpSystemProxyStatus {
    param([Parameter(Mandatory=$true)]$Context, $Status,
        [string]$RegistrySubKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
    $config = Get-BfpSystemProxyConfig $Context $RegistrySubKey
    $mutex = Enter-BfpSystemProxyLock $config
    try { Get-BfpSystemProxyStatusCore $config } finally { Exit-BfpSystemProxyLock $mutex }
}

function Enable-BfpSystemProxy {
    param([Parameter(Mandatory=$true)]$Context, $Status,
        [string]$RegistrySubKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', [scriptblock]$Notify, [scriptblock]$BeforeWrite)
    $config = Get-BfpSystemProxyConfig $Context $RegistrySubKey
    $mutex = Enter-BfpSystemProxyLock $config
    try {
        if ($null -eq $Status) { $Status = Get-BfpDesktopClientStatus -ProjectRoot $Context.ProjectRoot -InstanceId $Context.InstanceId }
        if ($Status.instance_id -cne $Context.InstanceId -or $Status.owner_id -cnotmatch '^[a-f0-9]{32}$' -or $Status.mode -cne 'proxy' -or
            $Status.running -isnot [bool] -or -not $Status.running -or $Status.owner_verified -isnot [bool] -or -not $Status.owner_verified -or
            $Status.proxy_owner_verified -isnot [bool] -or -not $Status.proxy_owner_verified) {
            return Get-BfpSystemProxySummary $config $null 'client_not_ready' $false $false
        }
        $lease = Read-BfpSystemProxyLease $config
        if ($null -ne $lease) {
            $summary = Get-BfpSystemProxyStatusCore $config
            if ($lease.Ours -and $lease.Claim.owner_id -ceq $Status.owner_id -and $summary.active) { return $summary }
            $summary.success = $false
            if ($lease.Ours -and $lease.Claim.owner_id -cne $Status.owner_id) { $summary.state = 'owner_changed' }
            return $summary
        }
        if (Test-Path -LiteralPath $config.BackupPath) { throw 'An unclaimed system proxy backup requires review before takeover.' }
        $backup = [pscustomobject][ordered]@{
            version = 1; instance_id = $Context.InstanceId; owner_id = $Status.owner_id; lease_id = [guid]::NewGuid().ToString('N')
            user_sid = $config.Sid; registry_subkey = $config.RegistrySubKey; phase = 'preparing'; created_utc = [DateTime]::UtcNow.ToString('o')
            original = (Get-BfpSystemProxyValues $config); applied = (Get-BfpSystemProxyAppliedValues)
        }
        Write-BfpSystemProxyBackup $config $backup
        $claim = [pscustomobject][ordered]@{
            version = 1; instance_id = $backup.instance_id; owner_id = $backup.owner_id; lease_id = $backup.lease_id
            user_sid = $config.Sid; registry_subkey = $config.RegistrySubKey; backup_path = $config.BackupPath
        }
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($config.ClaimSubKey)
        try { $key.SetValue('Lease', ($claim | ConvertTo-Json -Compress), [Microsoft.Win32.RegistryValueKind]::String); $key.Flush() }
        finally { $key.Dispose() }
        try {
            if (-not (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $backup.original)) { throw 'System proxy settings changed during takeover.' }
            Set-BfpSystemProxyValues $config $backup.applied $BeforeWrite
            Invoke-BfpSystemProxyNotify $Notify
            $backup.phase = 'applied'
            Write-BfpSystemProxyBackup $config $backup
            return Get-BfpSystemProxyStatusCore $config
        } catch {
            try { [void](Restore-BfpSystemProxyCore $config $backup.lease_id $Notify) } catch { }
            throw 'System proxy takeover failed. Saved settings were rolled back or retained for safe recovery.'
        }
    } finally { Exit-BfpSystemProxyLock $mutex }
}

function Restore-BfpSystemProxy {
    param([Parameter(Mandatory=$true)]$Context, $Status, [string]$ExpectedLeaseId = '',
        [string]$RegistrySubKey = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', [scriptblock]$Notify)
    if ($ExpectedLeaseId -ne '' -and $ExpectedLeaseId -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid expected system proxy lease.' }
    $config = Get-BfpSystemProxyConfig $Context $RegistrySubKey
    $mutex = Enter-BfpSystemProxyLock $config
    try { Restore-BfpSystemProxyCore $config $ExpectedLeaseId $Notify } finally { Exit-BfpSystemProxyLock $mutex }
}

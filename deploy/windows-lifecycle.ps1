# Windows client ownership and shutdown. This file never reads client credentials.
$script:BfpDesktopProjectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')

if ($null -eq ('BfpDesktopProcessV1.Lease' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace BfpDesktopProcessV1 {
    public sealed class Lease : IDisposable {
        const uint Query = 0x1000, Synchronize = 0x100000, TerminateRight = 1;
        [DllImport("kernel32.dll", SetLastError=true)] static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, System.Text.StringBuilder path, ref int size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
        [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, IntPtr info, int size, out int returned);
        [DllImport("ntdll.dll", EntryPoint="NtQueryInformationProcess")] static extern int NtQueryBasicInformation(SafeProcessHandle process, int infoClass, out BasicInformation info, int size, out int returned);
        [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string command, out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr ptr);
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct BasicInformation { public IntPtr Reserved1, Peb, Reserved2, Reserved3, Pid, ParentPid; }
        SafeProcessHandle handle;
        public int Id { get; private set; }
        public DateTime StartedUtc { get; private set; }
        public string Executable { get; private set; }
        public int ParentId { get; private set; }
        public bool Alive { get { return WaitForSingleObject(handle, 0) == 258; } }
        public static Lease Open(int pid, bool terminate) {
            SafeProcessHandle handle = OpenProcess(Query | Synchronize | (terminate ? TerminateRight : 0), false, pid);
            if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            Lease lease = new Lease(); lease.handle = handle; lease.Id = pid;
            try {
                long created, exited, kernel, user;
                if (!GetProcessTimes(handle, out created, out exited, out kernel, out user)) throw new Win32Exception(Marshal.GetLastWin32Error());
                lease.StartedUtc = DateTime.FromFileTimeUtc(created);
                BasicInformation basic; int returned;
                if (NtQueryBasicInformation(handle, 0, out basic, Marshal.SizeOf(typeof(BasicInformation)), out returned) < 0) throw new InvalidOperationException("Cannot verify process parent.");
                lease.ParentId = checked((int)basic.ParentPid.ToInt64());
                int size = 32768; System.Text.StringBuilder path = new System.Text.StringBuilder(size);
                if (!QueryFullProcessImageName(handle, 0, path, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                lease.Executable = path.ToString(); return lease;
            } catch { lease.Dispose(); throw; }
        }
        public string CommandLine() {
            int size; NtQueryInformationProcess(handle, 60, IntPtr.Zero, 0, out size);
            if (size < Marshal.SizeOf(typeof(UnicodeString)) || size > 1048576) throw new InvalidOperationException("Cannot verify launcher command.");
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                int returned; int status = NtQueryInformationProcess(handle, 60, buffer, size, out returned);
                if (status < 0) throw new InvalidOperationException("Cannot verify launcher command.");
                UnicodeString value = (UnicodeString)Marshal.PtrToStructure(buffer, typeof(UnicodeString));
                long start = buffer.ToInt64(), end = start + size, ptr = value.Buffer.ToInt64();
                if (value.Length % 2 != 0 || ptr < start || ptr + value.Length > end) throw new InvalidOperationException("Invalid launcher command metadata.");
                return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        public static string[] Arguments(string command) {
            int count; IntPtr argv = CommandLineToArgvW(command, out count);
            if (argv == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                string[] args = new string[count];
                for (int i=0; i<count; i++) args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size));
                return args;
            } finally { LocalFree(argv); }
        }
        public void Terminate() { if (!TerminateProcess(handle, 143)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public bool Wait(int milliseconds) { return WaitForSingleObject(handle, (uint)milliseconds) == 0; }
        public void Dispose() { if (handle != null) { handle.Dispose(); handle = null; } }
    }
}
'@
}

function Get-BfpDesktopHash([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Assert-BfpDesktopPath([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -ne $base -and -not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Desktop lifecycle path is outside the project.'
    }
    $probe = $full
    while ($probe.Length -ge $base.Length) {
        $item = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Desktop lifecycle paths may not contain a reparse point.'
        }
        if ($probe -eq $base) { break }
        $probe = [IO.Path]::GetDirectoryName($probe)
    }
    return $full
}

function Read-BfpDesktopPortableDescriptor([string]$ProjectRoot) {
    $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
    if ($root -ne $script:BfpDesktopProjectRoot) { throw 'Unexpected desktop project directory.' }
    $descriptorPath = Assert-BfpDesktopPath (Join-Path $root 'deploy\portable-client.json') $root
    if (-not (Test-Path -LiteralPath $descriptorPath)) { return $null }
    if (-not (Test-Path -LiteralPath $descriptorPath -PathType Leaf)) { throw 'Invalid portable client descriptor file.' }
    if ((Get-Item -LiteralPath $descriptorPath).Length -gt 4096) { throw 'Invalid portable client descriptor size.' }
    try {
        $json = [IO.File]::ReadAllText($descriptorPath)
        $descriptor = $json | ConvertFrom-Json -ErrorAction Stop
    } catch { throw 'Invalid portable client descriptor.' }
    $fields = @('version','instance_id','public_endpoint','expected_exit_ip')
    if ($descriptor -isnot [pscustomobject] -or @($descriptor.PSObject.Properties).Count -ne $fields.Count) {
        throw 'Invalid portable client descriptor fields.'
    }
    # Do not accept duplicate or escaped property names. The public descriptor
    # contains only primitive values and needs no nested objects or path fields.
    $keys = [regex]::Matches($json, '"(?<key>[^"\\]*)"\s*:')
    if ($keys.Count -ne $fields.Count) { throw 'Invalid portable client descriptor fields.' }
    foreach ($field in $fields) {
        if (@($descriptor.PSObject.Properties | Where-Object { $_.Name -ceq $field }).Count -ne 1 -or
            @($keys | Where-Object { $_.Groups['key'].Value -ceq $field }).Count -ne 1) {
            throw 'Invalid portable client descriptor fields.'
        }
    }
    if (($descriptor.version -isnot [int] -and $descriptor.version -isnot [long]) -or $descriptor.version -ne 1 -or
        $descriptor.instance_id -isnot [string] -or $descriptor.instance_id -cnotmatch '^[a-f0-9]{32}$' -or
        $descriptor.public_endpoint -isnot [string] -or $descriptor.expected_exit_ip -isnot [string]) {
        throw 'Invalid portable client descriptor values.'
    }
    $endpoint = [regex]::Match($descriptor.public_endpoint, '^(?<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?<port>[1-9][0-9]{0,4})$')
    $endpointIp = $null; $exitIp = $null
    if (-not $endpoint.Success -or [int]$endpoint.Groups['port'].Value -gt 65535 -or
        -not [Net.IPAddress]::TryParse($endpoint.Groups['ip'].Value, [ref]$endpointIp) -or
        $endpointIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $endpointIp.ToString() -cne $endpoint.Groups['ip'].Value -or
        -not [Net.IPAddress]::TryParse($descriptor.expected_exit_ip, [ref]$exitIp) -or
        $exitIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $exitIp.ToString() -cne $descriptor.expected_exit_ip) {
        throw 'Invalid portable client endpoint.'
    }
    return $descriptor
}

function Get-BfpDesktopPaths([string]$ProjectRoot, [string]$InstanceId) {
    $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
    if ($root -ne $script:BfpDesktopProjectRoot) { throw 'Unexpected desktop project directory.' }
    if ($InstanceId -notmatch '^[a-f0-9]{32}$') { throw 'Invalid deployment identity.' }
    $portable = Read-BfpDesktopPortableDescriptor $root
    if ($null -ne $portable -and $portable.instance_id -cne $InstanceId) { throw 'Portable client identity does not match its descriptor.' }
    $run = Assert-BfpDesktopPath (Join-Path $root ('deploy\runs\' + $InstanceId)) $root
    if ($null -ne $portable) { $native = Assert-BfpDesktopPath (Join-Path $root 'client') $root }
    else { $native = Assert-BfpDesktopPath (Join-Path $root ('credentials-pilot-' + $InstanceId + '\windows-client')) $root }
    return [pscustomobject]@{
        ProjectRoot = $root; InstanceId = $InstanceId; RunDirectory = $run; Portable = ($null -ne $portable)
        RecordPath = (Assert-BfpDesktopPath (Join-Path $run 'windows-client.json') $root)
        NativeDirectory = $native
        RuntimeDirectory = (Assert-BfpDesktopPath (Join-Path $native 'runtime') $root)
        LauncherScript = (Assert-BfpDesktopPath (Join-Path $root 'deploy\windows-client.ps1') $root)
    }
}

function Read-BfpDesktopOwnerRecord([string]$ProjectRoot, [string]$InstanceId) {
    $paths = Get-BfpDesktopPaths $ProjectRoot $InstanceId
    if (-not (Test-Path -LiteralPath $paths.RecordPath -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $paths.RecordPath).Length -gt 16384) { throw 'Invalid desktop owner record.' }
    try { $record = [IO.File]::ReadAllText($paths.RecordPath) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Invalid desktop owner record.' }
    $allowed = @('version','instance_id','owner_id','mode','launcher_pid','launcher_start_utc','launcher_executable','launcher_command_sha256','native_directory','created_utc')
    foreach ($property in $record.PSObject.Properties) {
        if ($property.Name -notin $allowed) { throw 'Invalid desktop owner record fields.' }
    }
    if ($record.version -notin @(1,2) -or $record.instance_id -cne $InstanceId -or
        $record.owner_id -notmatch '^[a-f0-9]{32}$' -or $record.mode -notin @('proxy','tun') -or
        $record.launcher_pid -isnot [ValueType] -or [long]$record.launcher_pid -lt 1 -or [long]$record.launcher_pid -gt [int]::MaxValue -or
        $record.launcher_command_sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Invalid desktop owner record.' }
    try {
        [void][DateTime]::ParseExact([string]$record.launcher_start_utc, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        [void][DateTime]::ParseExact([string]$record.created_utc, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $image = [IO.Path]::GetFullPath([string]$record.launcher_executable)
        if ($record.version -eq 2) {
            if (-not $paths.Portable -or $record.native_directory -cne 'client') { throw 'Invalid relative native directory.' }
        } else {
            $native = [IO.Path]::GetFullPath([string]$record.native_directory)
            if ($native -ne $record.native_directory -or (-not $paths.Portable -and $native -ne $paths.NativeDirectory)) {
                throw 'Invalid native directory.'
            }
        }
    } catch { throw 'Invalid desktop owner record.' }
    if ($image -ne $record.launcher_executable -or [IO.Path]::GetFileName($image) -notin @('powershell.exe','pwsh.exe')) {
        throw 'Invalid launcher executable in owner record.'
    }
    return $record
}

function Test-BfpDesktopProcessOwner($ProcessLease, $OwnerRecord, [string]$LauncherScript) {
    if (-not $ProcessLease.Alive) { return $false }
    if ($ProcessLease.StartedUtc.ToString('o') -cne $OwnerRecord.launcher_start_utc -or
        $ProcessLease.Executable -ne $OwnerRecord.launcher_executable) { return $false }
    $command = $ProcessLease.CommandLine()
    if ((Get-BfpDesktopHash $command) -cne $OwnerRecord.launcher_command_sha256) { return $false }
    $arguments = [BfpDesktopProcessV1.Lease]::Arguments($command)
    for ($index = 1; $index -lt $arguments.Count - 1; $index++) {
        if ($arguments[$index] -ieq '-File') {
            if ([IO.Path]::GetFullPath($arguments[$index + 1]) -ne $LauncherScript) { return $false }
            # The exact command hash binds all options; require the intended start action too.
            for ($actionIndex = $index + 2; $actionIndex -lt $arguments.Count - 1; $actionIndex++) {
                if ($arguments[$actionIndex] -ieq '-Action' -and $arguments[$actionIndex + 1] -ieq 'start') { return $true }
            }
            return $false
        }
    }
    return $false
}

function Test-BfpDesktopSupervisorBusy($Paths) {
    $lock = Assert-BfpDesktopPath (Join-Path $Paths.RuntimeDirectory 'native-supervisor.lock') $Paths.ProjectRoot
    if (-not (Test-Path -LiteralPath $lock)) { return $false }
    $stream = $null
    try { $stream = [IO.File]::Open($lock, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); return $false }
    catch [IO.IOException] { return $true }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Test-BfpDesktopProxyPort {
    foreach ($endpoint in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()) {
        if ($endpoint.Port -eq 17890 -and ($endpoint.Address.Equals([Net.IPAddress]::Loopback) -or $endpoint.Address.Equals([Net.IPAddress]::Any) -or
            $endpoint.Address.Equals([Net.IPAddress]::IPv6Loopback) -or $endpoint.Address.Equals([Net.IPAddress]::IPv6Any))) { return $true }
    }
    return $false
}

function Test-BfpDesktopArguments([string]$Command, [hashtable]$Options, [string]$Subcommand = '') {
    $arguments = [BfpDesktopProcessV1.Lease]::Arguments($Command)
    if ($Subcommand -ne '' -and ($arguments.Count -lt 2 -or $arguments[1] -cne $Subcommand)) { return $false }
    foreach ($option in $Options.Keys) {
        $found = $false
        for ($index = 1; $index -lt $arguments.Count - 1; $index++) {
            if ($arguments[$index] -ceq $option) {
                if ([IO.Path]::GetFullPath($arguments[$index + 1]) -ne $Options[$option]) { return $false }
                $found = $true; break
            }
        }
        if (-not $found) { return $false }
    }
    return $true
}

function Test-BfpDesktopProxyOwner($Paths, $OwnerRecord) {
    $child = $null; $supervisor = $null; $launcher = $null
    try {
        $listeners = @(Get-NetTCPConnection -LocalPort 17890 -State Listen -ErrorAction SilentlyContinue)
        if ($listeners.Count -eq 0) { return $false }
        $expectedChild = Assert-BfpDesktopPath (Join-Path $Paths.NativeDirectory 'bin\mihomo-bfp-windows-amd64.exe') $Paths.ProjectRoot
        $expectedSupervisor = Assert-BfpDesktopPath (Join-Path $Paths.NativeDirectory 'bin\bfp-windows-amd64.exe') $Paths.ProjectRoot
        $config = Assert-BfpDesktopPath (Join-Path $Paths.NativeDirectory ('configs\native-' + $OwnerRecord.mode + '.yaml')) $Paths.ProjectRoot
        if ($OwnerRecord.mode -eq 'tun') { $config = Assert-BfpDesktopPath (Join-Path $Paths.RuntimeDirectory 'native-tun.generated.yaml') $Paths.ProjectRoot }
        $launcher = [BfpDesktopProcessV1.Lease]::Open([int]$OwnerRecord.launcher_pid, $false)
        if (-not (Test-BfpDesktopProcessOwner $launcher $OwnerRecord $Paths.LauncherScript)) { return $false }
        foreach ($listener in $listeners) {
            try {
                $child = [BfpDesktopProcessV1.Lease]::Open([int]$listener.OwningProcess, $false)
                if (-not $child.Alive -or $child.Executable -ne $expectedChild -or $child.StartedUtc -lt $launcher.StartedUtc) { continue }
                $supervisor = [BfpDesktopProcessV1.Lease]::Open($child.ParentId, $false)
                if (-not $supervisor.Alive -or $supervisor.Executable -ne $expectedSupervisor -or $supervisor.ParentId -ne $launcher.Id -or
                    $supervisor.StartedUtc -lt $launcher.StartedUtc -or $child.StartedUtc -lt $supervisor.StartedUtc) { continue }
                if (-not (Test-BfpDesktopArguments ($supervisor.CommandLine()) @{ '-runtime' = $Paths.RuntimeDirectory; '-config' = $config } 'native-supervise')) { continue }
                if (-not (Test-BfpDesktopArguments ($child.CommandLine()) @{ '-d' = $Paths.RuntimeDirectory; '-f' = $config })) { continue }
                return $true
            } catch { continue }
            finally {
                if ($null -ne $child) { $child.Dispose(); $child = $null }
                if ($null -ne $supervisor) { $supervisor.Dispose(); $supervisor = $null }
            }
        }
        return $false
    } catch { return $false }
    finally { if ($null -ne $launcher) { $launcher.Dispose() } }
}

function Get-BfpDesktopTunStatus($Paths, $Status) {
    $summary = [pscustomobject]@{ ready = $false; phase = 'inactive'; needs_recovery = $false; device = $null }
    $support = Assert-BfpDesktopPath (Join-Path $Paths.NativeDirectory 'windows-tun-support.ps1') $Paths.ProjectRoot
    if (-not (Test-Path -LiteralPath $support -PathType Leaf)) { return $summary }
    try {
        . $support
        $summary = Get-BfpWindowsTunRuntimeStatus -Runtime $Paths.RuntimeDirectory -LauncherPid $(if ($Status.pid) { [int]$Status.pid } else { 0 })
        if (-not $Status.running -or -not $Status.owner_verified -or -not $Status.proxy_owner_verified -or $Status.mode -ne 'tun') { $summary.ready = $false }
        return $summary
    } catch { return [pscustomobject]@{ ready = $false; phase = 'unverifiable'; needs_recovery = $true; device = $null } }
}

function Get-BfpDesktopClientStatus([string]$ProjectRoot, [string]$InstanceId) {
    $paths = Get-BfpDesktopPaths $ProjectRoot $InstanceId
    $status = [ordered]@{ instance_id = $InstanceId; state = 'stopped'; running = $false; owner_verified = $false; pid = $null; owner_id = $null; launcher_start_utc = $null; mode = $null
        tun = [pscustomobject]@{ ready = $false; phase = 'inactive'; needs_recovery = $false; device = $null }; port_listening = (Test-BfpDesktopProxyPort); proxy_owner_verified = $false; supervisor_lock_held = (Test-BfpDesktopSupervisorBusy $paths); cleanup_pending = $false; supervisor_stopping = $false }
    $status.cleanup_pending = $status.supervisor_lock_held
    $status.supervisor_stopping = $status.cleanup_pending
    try { $record = Read-BfpDesktopOwnerRecord $ProjectRoot $InstanceId }
    catch { $status.state = 'invalid_record'; return [pscustomobject]$status }
    if ($null -eq $record) { if ($status.cleanup_pending) { $status.state = 'stopping' }; $status.tun = Get-BfpDesktopTunStatus $paths $status; return [pscustomobject]$status }
    $status.pid = [int]$record.launcher_pid; $status.mode = $record.mode
    $status.owner_id = $record.owner_id; $status.launcher_start_utc = $record.launcher_start_utc
    $process = $null
    try {
        $process = [BfpDesktopProcessV1.Lease]::Open([int]$record.launcher_pid, $false)
        if (-not $process.Alive) { $status.state = 'stopped' }
        # A copied or moved portable record may refer to a PID that Windows has
        # already reused. Discard only the stale metadata; never stop that PID.
        elseif ($paths.Portable -and $process.StartedUtc.ToString('o') -cne $record.launcher_start_utc) { $status.state = 'stale_record' }
        elseif ($record.version -eq 1 -and [string]$record.native_directory -ne $paths.NativeDirectory) { $status.state = 'owner_mismatch' }
        elseif (Test-BfpDesktopProcessOwner $process $record $paths.LauncherScript) {
            $status.running = $true; $status.owner_verified = $true; $status.state = 'running'
            $status.cleanup_pending = $false; $status.supervisor_stopping = $false
            if ($status.port_listening) { $status.proxy_owner_verified = Test-BfpDesktopProxyOwner $paths $record }
        } else { $status.state = 'owner_mismatch' }
    } catch [ComponentModel.Win32Exception] {
        if ($_.Exception.NativeErrorCode -eq 87) { $status.state = 'stopped' } else { $status.state = 'owner_unverifiable' }
    } catch { $status.state = 'owner_unverifiable' }
    finally { if ($null -ne $process) { $process.Dispose() } }
    if (-not $status.running -and $status.cleanup_pending -and $status.state -eq 'stopped') { $status.state = 'stopping' }
    $status.tun = Get-BfpDesktopTunStatus $paths $status
    return [pscustomobject]$status
}

function Write-BfpDesktopOwnerRecord([string]$ProjectRoot, [string]$InstanceId, [int]$LauncherPid = $PID,
    [ValidateSet('proxy','tun')][string]$Mode = 'proxy') {
    $paths = Get-BfpDesktopPaths $ProjectRoot $InstanceId
    $current = Get-BfpDesktopClientStatus $ProjectRoot $InstanceId
    if ($current.running) { throw 'The desktop client is already running.' }
    if ($current.cleanup_pending) { throw 'The native supervisor is still stopping.' }
    if ($current.state -in @('owner_mismatch','owner_unverifiable','invalid_record')) { throw 'The previous desktop owner record cannot be safely replaced.' }
    $process = $null; $temporary = $null
    try {
        $process = [BfpDesktopProcessV1.Lease]::Open($LauncherPid, $false)
        if (-not $process.Alive -or [IO.Path]::GetFileName($process.Executable) -notin @('powershell.exe','pwsh.exe')) {
            throw 'The launcher must be a running PowerShell process.'
        }
        $record = [pscustomobject][ordered]@{
            version = $(if ($paths.Portable) { 2 } else { 1 }); instance_id = $InstanceId; owner_id = [guid]::NewGuid().ToString('N'); mode = $Mode
            launcher_pid = $LauncherPid; launcher_start_utc = $process.StartedUtc.ToString('o'); launcher_executable = $process.Executable
            launcher_command_sha256 = (Get-BfpDesktopHash ($process.CommandLine())); native_directory = $(if ($paths.Portable) { 'client' } else { $paths.NativeDirectory }); created_utc = [DateTime]::UtcNow.ToString('o')
        }
        if (-not (Test-BfpDesktopProcessOwner $process $record $paths.LauncherScript)) { throw 'The launcher command does not belong to this desktop client.' }
        [void][IO.Directory]::CreateDirectory($paths.RunDirectory)
        $temporary = Assert-BfpDesktopPath (Join-Path $paths.RunDirectory ('windows-client.' + $record.owner_id + '.tmp')) $paths.ProjectRoot
        [IO.File]::WriteAllText($temporary, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        # PowerShell 5.1 coerces $null to an empty string for this .NET string
        # argument. NullString preserves File.Replace's no-backup behavior.
        if (Test-Path -LiteralPath $paths.RecordPath) { [IO.File]::Replace($temporary, $paths.RecordPath, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $paths.RecordPath) }
        return $record
    } finally {
        if ($null -ne $process) { $process.Dispose() }
        if ($null -ne $temporary -and (Test-Path -LiteralPath $temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Remove-BfpDesktopOwnerRecord([string]$ProjectRoot, [string]$InstanceId, $OwnerRecord) {
    $paths = Get-BfpDesktopPaths $ProjectRoot $InstanceId
    $mutex = [Threading.Mutex]::new($false, ('Local\BFP-Desktop-Control-' + $InstanceId))
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { return }
        $current = Read-BfpDesktopOwnerRecord $ProjectRoot $InstanceId
        if ($null -ne $current -and $current.owner_id -ceq $OwnerRecord.owner_id -and
            $current.launcher_pid -eq $OwnerRecord.launcher_pid -and $current.launcher_start_utc -ceq $OwnerRecord.launcher_start_utc) {
            [IO.File]::Delete($paths.RecordPath)
        }
    } finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Begin-BfpClientRecord([string]$ProjectRoot, [string]$InstanceId, [int]$LauncherPid = $PID,
    [ValidateSet('proxy','tun')][string]$Mode = 'proxy') {
    [void](Get-BfpDesktopPaths $ProjectRoot $InstanceId)
    $mutex = [Threading.Mutex]::new($false, ('Local\BFP-Desktop-Control-' + $InstanceId))
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Another desktop client is already running or starting.' }
        $record = Write-BfpDesktopOwnerRecord $ProjectRoot $InstanceId $LauncherPid $Mode
        return [pscustomobject]@{ ProjectRoot = $ProjectRoot; InstanceId = $InstanceId; OwnerRecord = $record; OwnerId = $record.owner_id; Mutex = $mutex; HasMutex = $true }
    } catch {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose(); throw
    }
}

function Complete-BfpClientRecord($Lease) {
    if ($null -eq $Lease -or -not $Lease.HasMutex) { return }
    try { Remove-BfpDesktopOwnerRecord $Lease.ProjectRoot $Lease.InstanceId $Lease.OwnerRecord }
    finally { $Lease.Mutex.ReleaseMutex(); $Lease.Mutex.Dispose(); $Lease.HasMutex = $false }
}

function Stop-BfpDesktopClient([string]$ProjectRoot, [string]$InstanceId, [ValidateRange(1,60)][int]$WaitSeconds = 15) {
    $paths = Get-BfpDesktopPaths $ProjectRoot $InstanceId
    $status = Get-BfpDesktopClientStatus $ProjectRoot $InstanceId
    $stopped = $false; $reason = $status.state; $process = $null
    try {
        if ($status.state -in @('invalid_record','owner_mismatch','owner_unverifiable')) {
            return [pscustomobject]@{ instance_id = $InstanceId; stopped = $false; cleanup_complete = $false; state = $status.state; reason = 'Launcher ownership could not be verified.'; pid = $status.pid }
        }
        $record = Read-BfpDesktopOwnerRecord $ProjectRoot $InstanceId
        if ($status.running) {
            if ($record.version -eq 1 -and [string]$record.native_directory -ne $paths.NativeDirectory) {
                return [pscustomobject]@{ instance_id = $InstanceId; stopped = $false; cleanup_complete = $false; state = 'owner_mismatch'; reason = 'Launcher layout changed before shutdown.'; pid = $record.launcher_pid }
            }
            $process = [BfpDesktopProcessV1.Lease]::Open([int]$record.launcher_pid, $true)
            if (-not (Test-BfpDesktopProcessOwner $process $record $paths.LauncherScript)) {
                return [pscustomobject]@{ instance_id = $InstanceId; stopped = $false; cleanup_complete = $false; state = 'owner_mismatch'; reason = 'Launcher identity changed before shutdown.'; pid = $record.launcher_pid }
            }
            if ($process.Id -eq $PID) { throw 'A desktop launcher cannot stop itself through this command.' }
            $process.Terminate()
            $stopped = $process.Wait(2000); $reason = 'stopped'
        } else { $stopped = $true; $reason = 'already_stopped' }
        # A launcher can die between spawn and the supervisor taking its file lock.
        # Let that child observe its dead parent before declaring cleanup complete.
        if ($status.running -and $stopped) { Start-Sleep -Milliseconds 500 }
        $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
        do {
            $busy = Test-BfpDesktopSupervisorBusy $paths
            if (-not $busy) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($stopped -and -not $busy -and $null -ne $record) { Remove-BfpDesktopOwnerRecord $ProjectRoot $InstanceId $record }
        return [pscustomobject]@{ instance_id = $InstanceId; stopped = $stopped; cleanup_complete = (-not $busy); state = $(if ($busy) { 'stopping' } else { 'stopped' }); reason = $reason; pid = $status.pid; port_listening = (Test-BfpDesktopProxyPort) }
    } finally { if ($null -ne $process) { $process.Dispose() } }
}

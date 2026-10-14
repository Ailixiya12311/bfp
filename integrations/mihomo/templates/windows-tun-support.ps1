# Windows PowerShell 5.1. Dot-source this file; importing it never changes networking.
$script:BfpTunPackageRoot = [IO.Path]::GetFullPath($PSScriptRoot)

function Assert-BfpTunAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'TUN 模式需要管理员 PowerShell；请手动以管理员身份启动。'
    }
}

function Resolve-BfpTunRuntime([string]$Runtime) {
    $root = $script:BfpTunPackageRoot.TrimEnd('\') + '\'
    $candidate = $Runtime
    if (-not [IO.Path]::IsPathRooted($candidate)) { $candidate = Join-Path $script:BfpTunPackageRoot $Runtime }
    $path = [IO.Path]::GetFullPath($candidate).TrimEnd('\')
    if (-not $path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'BFP runtime must be a directory inside this package.'
    }
    $cursor = $path
    while ($cursor.Length -ge $script:BfpTunPackageRoot.Length) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'BFP runtime ancestry may not contain a reparse point.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $path
}

function Assert-BfpTunPlainFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer)) {
        throw 'A BFP runtime file has an unsafe type.'
    }
}

function Write-BfpTunJson([string]$Path, $Value) {
    Assert-BfpTunPlainFile $Path
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding($true)))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Read-BfpTunJson([string]$Path) {
    Assert-BfpTunPlainFile $Path
    if ((Get-Item -LiteralPath $Path).Length -gt 131072) { throw 'BFP runtime state is too large.' }
    try { return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json) }
    catch { throw 'BFP runtime state is invalid; the record was retained.' }
}

function Get-BfpTunDeviceGuid([string]$Device) {
    if ($Device -notmatch '^bfp-tun-[0-9a-f]{8}$') { throw 'Invalid BFP TUN device identity.' }
    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        # sing-tun casts the raw MD5 bytes to Windows GUID, whose first fields are little endian.
        $bytes = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes('wintun' + $Device))
        return (New-Object Guid(,$bytes)).ToString('D')
    } finally { $md5.Dispose() }
}

function Get-BfpTunJournal([string]$Runtime) {
    $runtimePath = Resolve-BfpTunRuntime $Runtime
    $path = Join-Path $runtimePath 'bfp-windows-tun-journal.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $state = Read-BfpTunJson $path
    if ($state.version -ne 1 -or $state.package_root -ne $script:BfpTunPackageRoot -or
        $state.runtime -ne $runtimePath -or $state.interface_guid -ne (Get-BfpTunDeviceGuid ([string]$state.device)) -or
        [int]$state.launcher_pid -lt 1 -or [string]::IsNullOrWhiteSpace([string]$state.launcher_started_utc) -or
        @($state.carrier_exclusions).Count -lt 1 -or @($state.carrier_exclusions).Count -gt 2 -or
        [string]::IsNullOrWhiteSpace([string]$state.physical_interface.guid)) {
        throw 'BFP TUN journal identity is invalid; the record was retained.'
    }
    return $state
}

function Get-BfpNumericCarrier([string]$Endpoint) {
    $match = [regex]::Match($Endpoint, '^(?:\[([^\[\]%]+)\]|([^:\s]+)):(\d{1,5})$')
    if (-not $match.Success) { throw 'TUN requires numeric IPv4/IPv6 server and tcp_server endpoints with ports.' }
    $hostPart = $match.Groups[1].Value
    if ($hostPart -eq '') { $hostPart = $match.Groups[2].Value }
    $port = [int]$match.Groups[3].Value
    $address = $null
    if ($port -lt 1 -or $port -gt 65535 -or -not [Net.IPAddress]::TryParse($hostPart, [ref]$address)) {
        throw 'TUN requires numeric IPv4/IPv6 endpoints; resolve and pin a domain before starting TUN.'
    }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    $bytes = $address.GetAddressBytes()
    if ([Net.IPAddress]::IsLoopback($address) -or $address.Equals([Net.IPAddress]::Any) -or
        $address.Equals([Net.IPAddress]::IPv6Any) -or $address.IsIPv6Multicast -or $address.IsIPv6LinkLocal -or
        ($bytes.Length -eq 4 -and ($bytes[0] -ge 224 -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)))) {
        throw 'TUN carrier endpoints must be unicast addresses with a usable uplink route.'
    }
    $bits = 32
    if ($bytes.Length -eq 16) { $bits = 128 }
    return [pscustomobject]@{ address = $address.ToString(); prefix = $address.ToString() + '/' + $bits }
}

function Get-BfpTunExpectedPrefixes([string[]]$Exclusions, [bool]$IPv6) {
    $result = New-Object 'Collections.Generic.List[string]'
    foreach ($byteCount in @(4,16)) {
        if ($byteCount -eq 16 -and -not $IPv6) { continue }
        $excluded = @($Exclusions | ForEach-Object {
            $parsed = [Net.IPAddress]::Parse(($_ -split '/')[0])
            if ($parsed.GetAddressBytes().Length -eq $byteCount) { ,$parsed.GetAddressBytes() }
        })
        $stack = New-Object Collections.Stack
        $stack.Push([pscustomobject]@{ bytes = (New-Object byte[] $byteCount); bits = 0; excluded = $excluded })
        while ($stack.Count -gt 0) {
            $node = $stack.Pop()
            if (@($node.excluded).Count -eq 0) {
                $ip = New-Object Net.IPAddress(,$node.bytes)
                $result.Add($ip.ToString() + '/' + $node.bits)
                continue
            }
            if ($node.bits -eq $byteCount * 8) { continue }
            $index = [int][Math]::Floor($node.bits / 8)
            $mask = 1 -shl (7 - ($node.bits % 8))
            foreach ($side in @(0,1)) {
                [byte[]]$childBytes = $node.bytes.Clone()
                if ($side -eq 1) { $childBytes[$index] = $childBytes[$index] -bor $mask }
                $childExcluded = @($node.excluded | Where-Object { [int](($_[$index] -band $mask) -ne 0) -eq $side })
                $stack.Push([pscustomobject]@{ bytes = $childBytes; bits = $node.bits + 1; excluded = $childExcluded })
            }
        }
    }
    return $result.ToArray()
}

function Get-BfpTunBestRoute([string]$Address) {
    # Find-NetRoute emits both MSFT_NetIPAddress and MSFT_NetRoute. The former
    # has no DestinationPrefix; direct property access fails under StrictMode.
    $routes = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop | Where-Object {
        $property = $_.PSObject.Properties['DestinationPrefix']
        $null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)
    })
    if ($routes.Count -ne 1) { throw 'A carrier endpoint has no unambiguous uplink route.' }
    return $routes[0]
}

function Get-BfpTunAdapterByIndex([int]$Index) {
    # Enumerate for compatibility with Windows NetAdapter module versions.
    return @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $Index })
}

function Test-BfpTunEffectiveIPv6 {
    # Match fixed Mihomo config/utils.go verifyIP6, including ULA and its
    # documented override. IPv4-mapped IPv6 is unwrapped and is not IPv6.
    if ($env:SKIP_SYSTEM_IPV6_CHECK -match '^(?i:1|t|true)$') { return $true }
    $addresses = @(Get-NetIPAddress -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($item in $addresses) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse(([string]$item.IPAddress -split '%')[0], [ref]$address)) { continue }
        if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            -not $address.IsIPv4MappedToIPv6 -and -not [Net.IPAddress]::IsLoopback($address) -and
            -not $address.Equals([Net.IPAddress]::IPv6Any) -and -not $address.IsIPv6LinkLocal -and
            -not $address.IsIPv6Multicast) { return $true }
    }
    return $false
}

function Get-BfpTunOwnedAdapter($State) {
    # Query failures are errors, never evidence that an adapter disappeared.
    # A rename retains the GUID, so it must also be detected and refused.
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        $_.Name -eq $State.device -or ([guid]$_.InterfaceGuid).ToString('D') -eq $State.interface_guid
    })
    if ($adapters.Count -ne 0 -and ($adapters.Count -ne 1 -or $adapters[0].Name -ne $State.device -or
        ([guid]$adapters[0].InterfaceGuid).ToString('D') -ne $State.interface_guid)) {
        throw 'TUN adapter identity differs from this instance; cleanup was refused.'
    }
    return $adapters
}

function New-BfpWindowsTunState([string]$Runtime, [string]$Config, [string]$CredentialPath) {
    Assert-BfpTunAdministrator
    $runtimePath = Resolve-BfpTunRuntime $Runtime
    if (Test-Path -LiteralPath (Join-Path $runtimePath 'bfp-windows-tun-journal.json')) {
        throw 'An existing BFP TUN journal must be recovered before preparing TUN.'
    }
    Assert-BfpTunPlainFile $CredentialPath
    if ((Get-Item -LiteralPath $CredentialPath).Length -gt 65536) { throw 'Invalid BFP client configuration.' }
    try { $privateConfig = [IO.File]::ReadAllText($CredentialPath) | ConvertFrom-Json }
    catch { throw 'Invalid BFP client configuration.' }
    try {
        $udp = Get-BfpNumericCarrier ([string]$privateConfig.server)
        $tcpEndpoint = [string]$privateConfig.tcp_server
        if ([string]::IsNullOrWhiteSpace($tcpEndpoint)) { $tcpEndpoint = [string]$privateConfig.server }
        $tcp = Get-BfpNumericCarrier $tcpEndpoint
    } finally { $privateConfig = $null }
    $carriers = @(@($udp,$tcp) | Sort-Object -Property prefix -Unique)
    $routes = @($carriers | ForEach-Object { Get-BfpTunBestRoute $_.address })
    $indexes = @($routes.InterfaceIndex | Sort-Object -Unique)
    if ($indexes.Count -ne 1) { throw 'UDP and TCP carrier endpoints must use the same uplink interface.' }
    $uplink = @(Get-BfpTunAdapterByIndex $indexes[0])
    if ($uplink.Count -ne 1 -or $uplink[0].Status -ne 'Up' -or $uplink[0].Name -match '^bfp-tun-') {
        throw 'Carrier endpoints need one active uplink interface outside BFP TUN.'
    }
    Assert-BfpTunPlainFile $Config
    $yaml = [IO.File]::ReadAllText($Config)
    if ($yaml.Length -gt 131072 -or [regex]::Matches($yaml, '(?m)^tun:\s*(?:#.*)?$').Count -ne 1 -or
        [regex]::Matches($yaml, '(?m)^\s{2}device:\s*bfp-tun\s*$').Count -ne 1 -or
        [regex]::Matches($yaml, '(?m)^\s*type:\s*bfp\s*$').Count -ne 1 -or
        [regex]::Matches($yaml, '(?m)^\s*client-config-file:\s*\./credentials/client\.json\s*$').Count -ne 1 -or
        $yaml -notmatch '(?m)^log-level:\s*(?:info|debug)\s*$' -or
        $yaml -notmatch '(?m)^\s{2}auto-route:\s*true\s*$' -or
        $yaml -notmatch '(?m)^\s{2}strict-route:\s*true\s*$' -or
        $yaml -match '(?m)^\s*(?:inet[46]-)?route-(?:address|exclude-address)(?:-set)?:' -or
        $yaml -match '(?m)^\s*inet[46]-address:' -or $yaml -match '(?m)^\s*dialer-proxy:') {
        throw 'TUN launcher requires the supplied native-tun template with one BFP outbound and standard routes.'
    }
    $ipv6 = ($yaml -match '(?m)^ipv6:\s*true\s*$') -and (Test-BfpTunEffectiveIPv6)
    # Pin the effective configuration so a new adapter appearing between
    # preparation and parser startup cannot change the expected route family.
    if (-not $ipv6) { $yaml = [regex]::Replace($yaml, '(?m)^ipv6:\s*true\s*$', 'ipv6: false') }
    $fakeMatch = [regex]::Match($yaml, '(?m)^\s{2}fake-ip-range:\s*([0-9.]+)/\d+\s*$')
    $fakeAddress = $null
    if (-not $fakeMatch.Success -or -not [Net.IPAddress]::TryParse($fakeMatch.Groups[1].Value, [ref]$fakeAddress) -or
        $fakeAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'TUN needs a numeric fake-ip-range.' }
    $dnsBytes = $fakeAddress.GetAddressBytes()
    if ($dnsBytes[3] -eq 255) { throw 'TUN fake-ip-range cannot supply its interface DNS address.' }
    $dnsBytes[3]++
    $dns = @((New-Object Net.IPAddress(,$dnsBytes)).ToString())
    if ($ipv6) { $dns += 'fdfe:dcba:9876::2' }
    do { $device = 'bfp-tun-' + ([guid]::NewGuid().ToString('N').Substring(0,8)) }
    while (@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -eq $device }).Count -ne 0)
    $exclusions = @($carriers.prefix)
    $yaml = [regex]::Replace($yaml, '(?m)^(\s{2}device:)\s*bfp-tun\s*$', ('$1 ' + $device))
    $yaml = [regex]::Replace($yaml, '(?m)^interface-name:.*\r?\n?', '')
    $yaml = "interface-name: '" + $uplink[0].Name.Replace("'", "''") + "'`r`n" + $yaml
    $tunAt = [regex]::Match($yaml, '(?m)^tun:\s*(?:#.*)?$')
    $yaml = $yaml.Insert($tunAt.Index + $tunAt.Length, "`r`n  route-exclude-address: [" + ($exclusions -join ', ') + ']')
    $generated = Join-Path $runtimePath 'native-tun.generated.yaml'
    Assert-BfpTunPlainFile $generated
    $state = [pscustomobject][ordered]@{
        version = 1; package_root = $script:BfpTunPackageRoot; runtime = $runtimePath
        phase = 'prepared'; device = $device; interface_guid = Get-BfpTunDeviceGuid $device
        launcher_pid = $PID; launcher_started_utc = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
        supervisor_pid = 0; supervisor_started_utc = ''; mihomo_pid = 0; mihomo_started_utc = ''
        # System.Array has an Address() method; project each endpoint explicitly.
        carrier_exclusions = $exclusions; carrier_addresses = @($carriers | ForEach-Object { [string]$_.address })
        physical_interface = [pscustomobject]@{ name = $uplink[0].Name; index = [int]$uplink[0].InterfaceIndex; guid = ([guid]$uplink[0].InterfaceGuid).ToString('D') }
        baseline_routes = @($routes | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
        expected_prefixes = @(Get-BfpTunExpectedPrefixes $exclusions $ipv6); expected_dns = $dns
        ipv6 = $ipv6; interface_index = 0; initialized = $false; ready = $false; started_utc = [DateTime]::UtcNow.ToString('o')
    }
    Write-BfpTunJson (Join-Path $runtimePath 'bfp-windows-tun-journal.json') $state
    [IO.File]::WriteAllText($generated, $yaml, (New-Object Text.UTF8Encoding($false)))
    Write-BfpTunMarker $state
    return $state
}

function Write-BfpTunMarker($State) {
    Write-BfpTunJson (Join-Path $State.runtime 'bfp-tun-supervisor.json') ([ordered]@{
        version = 2; mode = 'tun'; pid = [int]$State.launcher_pid; launcher_started_utc = $State.launcher_started_utc
        device = $State.device; interface_guid = $State.interface_guid; interface_index = [int]$State.interface_index
        supervisor_pid = [int]$State.supervisor_pid; mihomo_pid = [int]$State.mihomo_pid
        carrier_exclusions = @($State.carrier_exclusions); physical_interface = $State.physical_interface
        phase = $State.phase; initialized = [bool]$State.initialized; ready = [bool]$State.ready; started_utc = $State.started_utc
    })
}

function Test-BfpTunProcess([int]$ProcessId, [string]$StartedUtc) {
    if ($ProcessId -lt 1 -or [string]::IsNullOrWhiteSpace($StartedUtc)) { return $false }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    return ($null -ne $process -and $process.StartTime.ToUniversalTime().ToString('o') -eq $StartedUtc)
}

function Get-BfpWindowsTunRuntimeStatus([string]$Runtime, [int]$LauncherPid) {
    $status = [pscustomobject][ordered]@{
        ready = $false; needs_recovery = $false; phase = 'absent'; stage = 'journal'; device = ''
        interface_index = 0; interface_guid = ''; carrier_exclusions = @(); physical_interface = $null
        reason = 'TUN is not prepared.'; error_id = ''; error_type = ''; error_line = 0; error_message = ''
    }
    try {
        $state = Get-BfpTunJournal $Runtime
        if ($null -eq $state) {
            if (Test-Path -LiteralPath (Join-Path (Resolve-BfpTunRuntime $Runtime) 'bfp-tun-supervisor.json')) {
                $status.needs_recovery = $true; $status.phase = 'legacy'; $status.reason = 'A legacy TUN marker requires recovery.'
            }
            return $status
        }
        $status.needs_recovery = $true
        $status.phase = [string]$state.phase; $status.device = [string]$state.device
        $status.interface_guid = [string]$state.interface_guid; $status.carrier_exclusions = @($state.carrier_exclusions)
        $status.physical_interface = $state.physical_interface
        $status.stage = 'process-identity'
        if ($LauncherPid -lt 1 -or $state.launcher_pid -ne $LauncherPid -or
            -not (Test-BfpTunProcess $LauncherPid $state.launcher_started_utc) -or
            -not (Test-BfpTunProcess $state.supervisor_pid $state.supervisor_started_utc) -or
            -not (Test-BfpTunProcess $state.mihomo_pid $state.mihomo_started_utc)) {
            $status.reason = 'TUN owner or native process has exited.'; return $status
        }
        $status.stage = 'runtime-marker'
        $marker = Read-BfpTunJson (Join-Path $state.runtime 'bfp-tun-supervisor.json')
        if ($marker.version -ne 2 -or $marker.pid -ne $LauncherPid -or $marker.device -ne $state.device -or
            $marker.interface_guid -ne $state.interface_guid -or -not $state.initialized) {
            $status.reason = 'Mihomo runtime initialization has not been confirmed.'; return $status
        }
        $status.stage = 'owned-adapter'
        $adapters = @(Get-BfpTunOwnedAdapter $state)
        if ($adapters.Count -ne 1 -or $adapters[0].Status -ne 'Up' -or
            ([guid]$adapters[0].InterfaceGuid).ToString('D') -ne $state.interface_guid) {
            $status.reason = 'The owned TUN adapter is not up.'; return $status
        }
        $status.interface_index = [int]$adapters[0].InterfaceIndex
        $status.stage = 'owned-routes'
        $routes = @(Get-NetRoute -InterfaceIndex $status.interface_index -PolicyStore ActiveStore -ErrorAction Stop)
        $prefixes = @($routes.DestinationPrefix)
        foreach ($prefix in $state.expected_prefixes) {
            if ($prefixes -notcontains $prefix) { $status.reason = 'Owned TUN auto-route initialization is incomplete.'; return $status }
        }
        $status.stage = 'owned-dns'
        $dns = @(Get-DnsClientServerAddress -InterfaceIndex $status.interface_index -ErrorAction Stop | ForEach-Object { $_.ServerAddresses })
        foreach ($server in $state.expected_dns) {
            if ($dns -notcontains $server) { $status.reason = 'Owned TUN DNS initialization is incomplete.'; return $status }
        }
        $status.stage = 'uplink-adapter'
        $uplink = @(Get-BfpTunAdapterByIndex $state.physical_interface.index)
        if ($uplink.Count -ne 1 -or $uplink[0].Status -ne 'Up' -or
            ([guid]$uplink[0].InterfaceGuid).ToString('D') -ne $state.physical_interface.guid) {
            $status.reason = 'The saved uplink interface is unavailable.'; return $status
        }
        $status.stage = 'carrier-routes'
        foreach ($address in $state.carrier_addresses) {
            $route = Get-BfpTunBestRoute $address
            if ($route.InterfaceIndex -ne $state.physical_interface.index) {
                $status.reason = 'A BFP carrier endpoint is no longer routed through its saved uplink.'; return $status
            }
        }
        $status.ready = $true; $status.needs_recovery = $false; $status.phase = 'ready'; $status.stage = 'complete'; $status.reason = 'Local TUN, routes, DNS and carrier exclusions are ready.'
    } catch {
        $status.needs_recovery = $true; $status.phase = 'error'
        # Getter reads public process/network metadata and the non-secret
        # journal only. Do not render ErrorRecord, TargetObject, raw exception
        # messages or script source: a damaged journal may contain arbitrary
        # supplied text. Keep identifiers bounded and allow-listed.
        $errorId = [string]$_.FullyQualifiedErrorId
        if ($errorId -match '^[A-Za-z0-9_.:, -]{1,180}$') { $status.error_id = $errorId }
        else { $status.error_id = 'BFP_TUN_STATUS_QUERY_FAILED' }
        $status.error_type = $_.Exception.GetType().FullName
        $status.error_line = [int]$_.InvocationInfo.ScriptLineNumber
        $status.error_message = 'Windows process or network metadata could not be verified.'
        if ($status.error_id -like 'PropertyNotFound*') { $status.error_message = 'A Windows API result does not contain the required property.' }
        elseif ($status.error_id -like 'ParameterBinding*') { $status.error_message = 'A Windows API argument could not be bound.' }
        elseif ($status.error_id -like '*CmdletizationQuery_NotFound*') { $status.error_message = 'The requested Windows network object was not found.' }
        elseif ($_.Exception.Message -eq 'TUN adapter identity differs from this instance; cleanup was refused.') { $status.error_message = 'The observed TUN adapter name and GUID do not match this instance.' }
        $status.reason = 'TUN verification failed at ' + $status.stage + ' [' + $status.error_id + ']: ' + $status.error_message
    }
    return $status
}

function Remove-BfpWindowsTunState([string]$Runtime) {
    $runtimePath = Resolve-BfpTunRuntime $Runtime
    $state = Get-BfpTunJournal $runtimePath
    if ($null -eq $state) {
        if (Test-Path -LiteralPath (Join-Path $runtimePath 'bfp-tun-supervisor.json')) {
            throw 'A legacy or unowned TUN marker requires manual recovery; it was retained.'
        }
        return
    }
    Assert-BfpTunAdministrator
    # The Go supervisor calls this while holding its runtime lock after child.Wait.
    # Do not require the supervisor/launcher to have exited; do require no live
    # Mihomo from this package, including a child not yet recorded in the journal.
    $childPath = Join-Path $script:BfpTunPackageRoot 'bin\mihomo-bfp-windows-amd64.exe'
    $liveChildren = @(Get-CimInstance Win32_Process -Filter "Name='mihomo-bfp-windows-amd64.exe'" -ErrorAction Stop |
        Where-Object { $_.ExecutablePath -eq $childPath })
    if ($liveChildren.Count -ne 0 -or (Test-BfpTunProcess $state.mihomo_pid $state.mihomo_started_utc)) {
        throw 'The owned Mihomo process must stop before TUN cleanup.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    do {
        $adapters = @(Get-BfpTunOwnedAdapter $state)
        if ($adapters.Count -eq 0) { break }
        if ($adapters.Count -ne 1 -or ([guid]$adapters[0].InterfaceGuid).ToString('D') -ne $state.interface_guid) {
            throw 'TUN adapter identity differs from this instance; cleanup was refused.'
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($adapters.Count -ne 0) {
        $pnp = @(Get-CimInstance Win32_NetworkAdapter -Filter ("GUID='{{{0}}}'" -f $state.interface_guid) -ErrorAction Stop)
        $expectedPnp = 'SWD\WINTUN\{' + $state.interface_guid + '}'
        if ($pnp.Count -ne 1 -or $pnp[0].NetConnectionID -ne $state.device -or
            $pnp[0].PNPDeviceID -ne $expectedPnp) { throw 'Owned Wintun PnP identity could not be verified; the journal was retained.' }
        # Remove exactly this device. Never uninstall the shared Wintun driver.
        $pnpOut = Join-Path $runtimePath 'tun-cleanup-pnp.stdout.log'
        $pnpErr = Join-Path $runtimePath 'tun-cleanup-pnp.stderr.log'
        Assert-BfpTunPlainFile $pnpOut
        Assert-BfpTunPlainFile $pnpErr
        $removal = Start-Process -FilePath "$env:SystemRoot\System32\pnputil.exe" -ArgumentList @('/remove-device',([string]$pnp[0].PNPDeviceID)) -WindowStyle Hidden -PassThru -RedirectStandardOutput $pnpOut -RedirectStandardError $pnpErr
        try {
            if (-not $removal.WaitForExit(5000)) {
                Stop-Process -Id $removal.Id -Force -ErrorAction SilentlyContinue
                throw 'Owned Wintun device removal timed out; the journal was retained.'
            }
            $removal.Refresh()
            if ($removal.ExitCode -ne 0) { throw 'Owned Wintun device removal failed; the journal was retained.' }
        } finally { $removal.Dispose() }
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $adapters = @(Get-BfpTunOwnedAdapter $state)
            if ($adapters.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($adapters.Count -ne 0) { throw 'Owned Wintun device remains after removal; the journal was retained.' }
    }
    # DNS was set only on the new adapter. WFP strict-route uses a dynamic
    # process session. Removing this adapter and ending Mihomo releases both;
    # restoring global DNS/firewall snapshots would overwrite other software.
    foreach ($name in @('bfp-tun-supervisor.json','native-tun.generated.yaml','bfp-windows-tun-journal.json')) {
        $path = Join-Path $runtimePath $name
        Assert-BfpTunPlainFile $path
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
    }
}

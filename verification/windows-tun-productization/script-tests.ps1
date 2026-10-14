param([string]$Workspace = 'C:\Users\developer\Desktop\bfp')
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path $Workspace ('.test-tmp\windows-tun-script-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot,(Join-Path $testRoot 'configs'),(Join-Path $testRoot 'credentials'),(Join-Path $testRoot 'runtime') | Out-Null
$source = Join-Path $Workspace 'integrations\mihomo\templates'
Copy-Item -LiteralPath (Join-Path $source 'windows-tun-support.ps1') -Destination $testRoot
Copy-Item -LiteralPath (Join-Path $source 'configs\native-tun.yaml') -Destination (Join-Path $testRoot 'configs\native-tun.yaml')
. (Join-Path $testRoot 'windows-tun-support.ps1')
$script:checks = New-Object 'Collections.Generic.List[string]'
function Check([string]$Name,[bool]$Pass) { if(-not $Pass){throw ('FAIL: '+$Name)}; $script:checks.Add($Name) }
function MustFail([scriptblock]$Action) { try { & $Action | Out-Null; return $false } catch { return $true } }
$realAdmin = $false
try { Assert-BfpTunAdministrator; $realAdmin = $true } catch {}
Check 'non-admin fails clearly' (-not $realAdmin)
function Assert-BfpTunAdministrator {}
Check 'deterministic Windows GUID byte order' ((Get-BfpTunDeviceGuid 'bfp-tun-12345678') -eq '181dc3da-56e9-1e4c-d6d8-28471f4863b4')
Check 'IPv4 numeric endpoint' ((Get-BfpNumericCarrier '192.0.2.10:51880').prefix -eq '192.0.2.10/32')
Check 'IPv6 numeric endpoint' ((Get-BfpNumericCarrier '[2001:db8::9]:51880').prefix -eq '2001:db8::9/128')
foreach($bad in @('server.example:51880','0.0.0.0:51880','127.0.0.1:80','[fe80::1]:80','224.0.0.1:80','192.0.2.10:0')) {
    Check ('reject endpoint '+$bad) (MustFail { Get-BfpNumericCarrier $bad })
}
Check 'runtime cannot escape package' (MustFail { Resolve-BfpTunRuntime '..\outside' })
$script:uplink = [pscustomobject]@{Name="Fixture uplink's name";InterfaceIndex=14;InterfaceGuid='11111111-2222-3333-4444-555555555555';Status='Up'}
$script:tunAdapter = $null
$script:routeSwallowed = $false
$script:splitUplink = $false
$script:failAdapterQuery = $false
$script:liveMihomo = $false
$script:missingRoute = $false
$script:missingDns = $false
$script:fakePnp = $null
$script:pnpInvocations = 0
$script:pnpFailure = $false
function Get-NetAdapter {
    param([switch]$IncludeHidden,[string]$ErrorAction)
    if($script:failAdapterQuery){throw 'mock adapter API unavailable'}
    $script:uplink
    if($null -ne $script:tunAdapter){$script:tunAdapter}
}
function Find-NetRoute {
    param([string]$RemoteIPAddress,[string]$ErrorAction)
    # Match the real API: numeric input and mixed address/route output.
    [void][Net.IPAddress]::Parse($RemoteIPAddress)
    $index=14
    if($script:routeSwallowed){$index=99}
    if($script:splitUplink -and $RemoteIPAddress -eq '192.0.2.11'){$index=15}
    [pscustomobject]@{InterfaceIndex=$index;IPAddress='192.168.1.2'}
    [pscustomobject]@{InterfaceIndex=$index;DestinationPrefix='0.0.0.0/0';NextHop='192.168.1.1';RouteMetric=10}
}
function Get-CimInstance {
    param([string]$ClassName,[string]$Filter,[string]$ErrorAction)
    if($ClassName -eq 'Win32_Process' -and $script:liveMihomo){[pscustomobject]@{ExecutablePath=(Join-Path $testRoot 'bin\mihomo-bfp-windows-amd64.exe')}}
    if($ClassName -eq 'Win32_NetworkAdapter' -and $null -ne $script:fakePnp){
        Check 'CIM query preserves GUID braces' ($Filter -eq ("GUID='{{{0}}}'" -f $script:state.interface_guid))
        $script:fakePnp
    }
}
function Get-NetRoute {
    param([int]$InterfaceIndex,[string]$PolicyStore,[string]$ErrorAction)
    $prefixes=@($script:state.expected_prefixes)
    if($script:missingRoute){$prefixes=$prefixes | Select-Object -Skip 1}
    foreach($prefix in $prefixes){[pscustomobject]@{DestinationPrefix=$prefix}}
}
function Get-DnsClientServerAddress {
    param([int]$InterfaceIndex,[string]$ErrorAction)
    $dns=@($script:state.expected_dns)
    if($script:missingDns){$dns=@()}
    [pscustomobject]@{ServerAddresses=$dns}
}
function Get-NetIPAddress {
    param([string]$AddressFamily,[string]$PolicyStore,[string]$ErrorAction)
    [pscustomobject]@{IPAddress='fd42:6266:7000::1'}
}
function Start-Process {
    param([string]$FilePath,[string[]]$ArgumentList,[string]$WindowStyle,[switch]$PassThru,[string]$RedirectStandardOutput,[string]$RedirectStandardError)
    Check 'PnP removal names only the exact device' ($ArgumentList.Count -eq 2 -and $ArgumentList[0] -eq '/remove-device' -and $ArgumentList[1] -eq $script:fakePnp.PNPDeviceID)
    $script:pnpInvocations++
    $fake=[pscustomobject]@{Id=100;ExitCode=0}
    if($script:pnpFailure){$fake.ExitCode=1}
    $fake | Add-Member ScriptMethod WaitForExit {param($Milliseconds); if(-not $script:pnpFailure){$script:tunAdapter=$null};return $true}
    $fake | Add-Member ScriptMethod Refresh {}
    $fake | Add-Member ScriptMethod Dispose {}
    return $fake
}
function Stop-Process {throw 'Host process mutation is forbidden in these tests.'}
function Remove-NetRoute {throw 'Host route mutation is forbidden in these tests.'}
function Set-DnsClientServerAddress {throw 'Host DNS mutation is forbidden in these tests.'}
$credentials=Join-Path $testRoot 'credentials\client.json'
$config=Join-Path $testRoot 'configs\native-tun.yaml'
function Prepare {
    [IO.File]::WriteAllText($credentials,'{"server":"192.0.2.10:51880","tcp_server":"192.0.2.11:51880","credentials":{"placeholder":"synthetic"}}')
    $script:state=New-BfpWindowsTunState -Runtime (Join-Path $testRoot 'runtime') -Config $config -CredentialPath $credentials
}
[IO.File]::WriteAllText($credentials,'{"server":"server.example:51880"}')
Check 'domain preparation fails before journal creation' (MustFail {New-BfpWindowsTunState -Runtime (Join-Path $testRoot 'runtime') -Config $config -CredentialPath $credentials})
Check 'no journal after rejected domain' (-not (Test-Path (Join-Path $testRoot 'runtime\bfp-windows-tun-journal.json')))
$script:splitUplink=$true
Check 'different UDP/TCP uplinks are refused' (MustFail {Prepare})
$script:splitUplink=$false
Prepare
Check 'both saved carrier addresses are numeric endpoints' ($state.carrier_addresses.Count -eq 2 -and $state.carrier_addresses[0] -ceq '192.0.2.10' -and $state.carrier_addresses[1] -ceq '192.0.2.11')
$yaml=[IO.File]::ReadAllText((Join-Path $testRoot 'runtime\native-tun.generated.yaml'))
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'generated-fixture.yaml'),$yaml,(New-Object Text.UTF8Encoding($false)))
Check 'generated YAML excludes both carriers' ($yaml -match 'route-exclude-address: \[192\.204\.33\.19/32, 192\.204\.33\.20/32\]')
Check 'generated YAML quotes the uplink alias' ($yaml.Contains("interface-name: 'Fixture uplink''s name'"))
Check 'complete expected route set includes IPv6 default' ($state.expected_prefixes -contains '::/0' -and $state.expected_prefixes.Count -gt 32)
Check 'journal contains no credential subtree' (-not ([IO.File]::ReadAllText((Join-Path $testRoot 'runtime\bfp-windows-tun-journal.json')).Contains('credentials')))
function Test-BfpTunProcess {param([int]$ProcessId,[string]$StartedUtc);return $true}
$state.supervisor_pid=10;$state.supervisor_started_utc='synthetic';$state.mihomo_pid=11;$state.mihomo_started_utc='synthetic';$state.initialized=$true
$script:tunAdapter=[pscustomobject]@{Name=$state.device;InterfaceIndex=99;InterfaceGuid=$state.interface_guid;Status='Up'}
function SaveState {Write-BfpTunJson (Join-Path $state.runtime 'bfp-windows-tun-journal.json') $state; Write-BfpTunMarker $state}
SaveState
$status=Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid $PID
Check ('ready requires all owned resources: '+$status.reason) ($status.ready -and -not $status.needs_recovery)
$script:missingRoute=$true
$status=Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid $PID
Check 'one missing TUN route blocks ready' (-not $status.ready -and $status.needs_recovery)
$script:missingRoute=$false;$script:missingDns=$true
Check 'missing owned DNS blocks ready' (-not (Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid $PID).ready)
$script:missingDns=$false;$script:routeSwallowed=$true
Check 'carrier swallowed by TUN blocks ready' (-not (Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid $PID).ready)
$script:routeSwallowed=$false
Check 'wrong launcher cannot claim ready' (-not (Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid ($PID+1)).ready)
$state.initialized=$false;SaveState
Check 'port and adapter readiness cannot substitute runtime init' (-not (Get-BfpWindowsTunRuntimeStatus -Runtime $state.runtime -LauncherPid $PID).ready)
$state.initialized=$true;SaveState
function Test-BfpTunProcess {param([int]$ProcessId,[string]$StartedUtc);return $false}
$script:liveMihomo=$true
Check 'cleanup refuses a live package child' (MustFail {Remove-BfpWindowsTunState $state.runtime})
$script:liveMihomo=$false
$script:tunAdapter.Name='renamed-foreign'
Check 'renamed adapter retains journal and is not removed' (MustFail {Remove-BfpWindowsTunState $state.runtime})
Check 'ownership failures preserve journal' (Test-Path (Join-Path $state.runtime 'bfp-windows-tun-journal.json'))
$script:tunAdapter.Name=$state.device;$script:failAdapterQuery=$true
Check 'adapter API failure is not absence' (MustFail {Remove-BfpWindowsTunState $state.runtime})
$script:failAdapterQuery=$false
$script:fakePnp=[pscustomobject]@{NetConnectionID=$state.device;PNPDeviceID=('SWD\WINTUN\{'+$state.interface_guid+'}')}
$script:pnpFailure=$true
Check 'failed exact PnP removal preserves journal' (MustFail {Remove-BfpWindowsTunState $state.runtime})
Check 'failed PnP removal preserves recovery record' (Test-Path (Join-Path $state.runtime 'bfp-windows-tun-journal.json'))
$script:pnpFailure=$false
Remove-BfpWindowsTunState $state.runtime
Check 'verified removal clears only owned runtime state' (-not (Test-Path (Join-Path $state.runtime 'bfp-windows-tun-journal.json')) -and (Test-Path $credentials))
Remove-BfpWindowsTunState $state.runtime
Check 'repeat cleanup is idempotent' ($script:pnpInvocations -eq 2)
Write-BfpTunJson (Join-Path $state.runtime 'bfp-tun-supervisor.json') @{version=1;device='bfp-tun-deadbeef'}
Check 'legacy marker is not blindly deleted' (MustFail {Remove-BfpWindowsTunState $state.runtime})
$summary=[pscustomobject]@{passed=$script:checks.Count;failed=0;host_network_mutated=$false;host_tun_started=$false;fixture=$testRoot;checks=$script:checks.ToArray()}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'script-tests-result.json') -Encoding UTF8
$summary | Select-Object passed,failed,host_network_mutated,host_tun_started | Format-List

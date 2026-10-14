$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\integrations\mihomo\templates\windows-tun-support.ps1')
$script:ipv6Fixture=@()
function Get-NetIPAddress {param([string]$AddressFamily,[string]$PolicyStore,[string]$ErrorAction); $script:ipv6Fixture}
$savedOverride=$env:SKIP_SYSTEM_IPV6_CHECK
try {
    $env:SKIP_SYSTEM_IPV6_CHECK=$null
    $script:ipv6Fixture=@([pscustomobject]@{IPAddress='::1'},[pscustomobject]@{IPAddress='fe80::1%14'},[pscustomobject]@{IPAddress='ff02::1'})
    if(Test-BfpTunEffectiveIPv6){throw 'IPv4-only host must not expect IPv6 TUN routes.'}
    $script:ipv6Fixture+= [pscustomobject]@{IPAddress='fd42:6266:7000::1'}
    if(-not (Test-BfpTunEffectiveIPv6)){throw 'Mihomo accepts ULA as usable IPv6.'}
    $script:ipv6Fixture=@()
    $env:SKIP_SYSTEM_IPV6_CHECK='true'
    if(-not (Test-BfpTunEffectiveIPv6)){throw 'Mihomo IPv6 override must be respected.'}
    [ordered]@{passed=3;failed=0;ipv4_only_verified=$true;ula_verified=$true;override_verified=$true;host_network_mutated=$false} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'effective-ipv6-tests-result.json') -Encoding UTF8
    'Effective IPv6: 3/3 PASS'
} finally { $env:SKIP_SYSTEM_IPV6_CHECK=$savedOverride }

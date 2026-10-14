function Get-BfpDesktopContext {
    param([Parameter(Mandatory=$true)][string]$DeployRoot)
    $projectRoot = Split-Path -Parent ([IO.Path]::GetFullPath($DeployRoot))
    $portable = Read-BfpDesktopPortableDescriptor -ProjectRoot $projectRoot
    if ($null -ne $portable) {
        $paths = Get-BfpDesktopPaths -ProjectRoot $projectRoot -InstanceId $portable.instance_id
        [void][IO.Directory]::CreateDirectory($paths.RunDirectory)
        return [pscustomobject]@{
            ProjectRoot = $projectRoot
            InstanceId = [string]$portable.instance_id
            NativeDirectory = $paths.NativeDirectory
            RunDirectory = $paths.RunDirectory
            PublicEndpoint = [string]$portable.public_endpoint
            ProxyAddress = '127.0.0.1:17890'
            ExpectedExitIp = [string]$portable.expected_exit_ip
            Layout = 'portable'
        }
    }
    $pointer = Get-Content -Raw -LiteralPath (Join-Path $DeployRoot 'current.json') | ConvertFrom-Json
    $statePath = [IO.Path]::GetFullPath($pointer.state)
    $runsRoot = [IO.Path]::GetFullPath((Join-Path $DeployRoot 'runs')).TrimEnd('\') + '\'
    if (-not $statePath.StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Deployment state must be inside deploy/runs.'
    }
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.instance_id -notmatch '^[a-f0-9]{32}$') { throw 'Invalid deployment identity.' }
    $runDirectory = Join-Path (Join-Path $DeployRoot 'runs') $state.instance_id
    if ($statePath -ne [IO.Path]::GetFullPath((Join-Path $runDirectory 'state.json'))) {
        throw 'Deployment state does not match its instance.'
    }
    $nativeDirectory = [IO.Path]::GetFullPath((Join-Path $projectRoot ('credentials-pilot-' + $state.instance_id + '\windows-client')))
    if ([IO.Path]::GetFullPath($state.windows_client) -ne $nativeDirectory) {
        throw 'Unexpected Windows client directory.'
    }
    $expectedExitIp = [string]$state.expected_exit_ip
    if (-not $expectedExitIp) {
        # Older private pilot state predates expected_exit_ip. Derive it from
        # that instance's own endpoint instead of any public source default.
        $endpoint = [regex]::Match([string]$state.public_endpoint, '^(?<ip>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[1-9][0-9]{0,4}$')
        if (-not $endpoint.Success) { throw 'Pilot state requires an explicit expected_exit_ip for this endpoint.' }
        $expectedExitIp = $endpoint.Groups['ip'].Value
    }
    $exitIp = $null
    if (-not [Net.IPAddress]::TryParse($expectedExitIp, [ref]$exitIp) -or
        $exitIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $exitIp.ToString() -cne $expectedExitIp) { throw 'Invalid pilot expected exit IP.' }
    [pscustomobject]@{
        ProjectRoot = $projectRoot
        InstanceId = [string]$state.instance_id
        NativeDirectory = $nativeDirectory
        RunDirectory = $runDirectory
        PublicEndpoint = [string]$state.public_endpoint
        ProxyAddress = '127.0.0.1:17890'
        ExpectedExitIp = $expectedExitIp
        Layout = 'pilot'
    }
}

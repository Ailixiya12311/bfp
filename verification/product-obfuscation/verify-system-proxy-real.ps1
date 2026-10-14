$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$deploy = Join-Path $project 'deploy'
. (Join-Path $deploy 'windows-context.ps1')
. (Join-Path $deploy 'windows-lifecycle.ps1')
. (Join-Path $deploy 'windows-system-proxy.ps1')
$context = Get-BfpDesktopContext -DeployRoot $deploy
$wrapper = Join-Path $deploy 'windows-client.ps1'
$config = Get-BfpSystemProxyConfig $context 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$baseline = Get-BfpSystemProxyValues $config
$initial = Get-BfpSystemProxyStatus -Context $context
if ($initial.state -ne 'inactive') { throw 'Existing BFP system proxy lease must be recovered before this check.' }
$result = [ordered]@{ time_utc = [DateTime]::UtcNow.ToString('o'); cases = @(); baseline_values_public = $false }
$launcher = $null
function Invoke-ClientAction([string]$Action) {
    $output = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $wrapper -Action $Action -Json
    $code = $LASTEXITCODE
    $value = $output | ConvertFrom-Json
    if ($code -ne 0) { throw ('Client action failed: ' + $Action) }
    return $value
}
function Start-OwnedClient {
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $context.RunDirectory ('proxy-live-' + [guid]::NewGuid().ToString('N') + '.out.log')) -RedirectStandardError (Join-Path $context.RunDirectory ('proxy-live-' + [guid]::NewGuid().ToString('N') + '.err.log'))
    $script:launcher = $process
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $status = Get-BfpDesktopClientStatus $context.ProjectRoot $context.InstanceId
        if ($status.proxy_owner_verified) { return $process }
        if ($process.HasExited) { throw 'Client exited during startup.' }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Owned client was not ready.'
}
try {
    $launcher = Start-OwnedClient
    $takeover = Invoke-ClientAction 'enable-system-proxy'
    if (-not $takeover.active -or -not $takeover.owned) { throw 'System proxy did not become active.' }
    # A fresh PowerShell/.NET process resolves the Windows system proxy. No
    # explicit proxy address is supplied to this request.
    $networkSource = @'
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$uri = [uri]'https://www.cloudflare.com/cdn-cgi/trace'
$systemProxy = [Net.WebRequest]::DefaultWebProxy.GetProxy($uri)
if ($systemProxy.Host -ne '127.0.0.1' -or $systemProxy.Port -ne 17890) { throw 'Windows default proxy is not BFP.' }
$request = [Net.WebRequest]::Create($uri)
$request.Timeout = 20000
$response = $request.GetResponse()
try {
    $reader = New-Object IO.StreamReader($response.GetResponseStream())
    try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($body.Length -gt 32768) { throw 'Response exceeded the bounded check.' }
    $matches = @($body -split "`n" | Where-Object { $_ -match '^ip=' })
    $exitIp = if ($matches.Count -eq 1) { $matches[0].Substring(3).Trim() } else { '' }
    [ordered]@{ pass = ($exitIp -eq '192.0.2.10'); exit_ip = $exitIp; body_bytes = [Text.Encoding]::UTF8.GetByteCount($body); proxy_from_windows_settings = $true } | ConvertTo-Json -Compress
} finally { $response.Dispose() }
'@
    $networkPath = Join-Path $context.RunDirectory 'system-proxy-https.ps1'
    [IO.File]::WriteAllText($networkPath, $networkSource, [Text.UTF8Encoding]::new($true))
    $networkOutput = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $networkPath
    $networkCode = $LASTEXITCODE
    $network = $networkOutput | ConvertFrom-Json
    if ($networkCode -ne 0 -or -not $network.pass) { throw 'HTTPS using the Windows default proxy failed.' }
    $stop = Invoke-ClientAction 'stop'
    $normalRestored = Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $baseline
    if (-not $stop.cleanup_complete -or -not $normalRestored) { throw 'Normal stop failed to restore the exact original settings.' }
    $result.cases += [ordered]@{ name = 'windows_default_proxy_https_and_normal_stop'; pass = $true; network = $network; original_values_exactly_restored = $normalRestored }
    $launcher.Dispose()
    $launcher = Start-OwnedClient
    [void](Invoke-ClientAction 'enable-system-proxy')
    $launcher.Kill()
    $launcher.WaitForExit()
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $proxy = Get-BfpSystemProxyStatus -Context $context
        if (-not $proxy.owned -and (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $baseline)) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $crashRestored = -not $proxy.owned -and (Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $baseline)
    if (-not $crashRestored) { throw 'Independent watcher failed to restore after launcher termination.' }
    $result.cases += [ordered]@{ name = 'launcher_forced_exit_without_control_window'; pass = $true; original_values_exactly_restored = $true; recovery_budget_seconds = 15 }
} catch { $result.error = $_.Exception.Message }
finally {
    try { $result.final_stop = Invoke-ClientAction 'stop' } catch { $result.cleanup_error = $_.Exception.Message }
    $result.original_values_exactly_restored = Test-BfpSystemProxyValuesEqual (Get-BfpSystemProxyValues $config) $baseline
    $result.final_client_status = Get-BfpDesktopClientStatus $context.ProjectRoot $context.InstanceId
    $result.pass = -not $result.Contains('error') -and -not $result.Contains('cleanup_error') -and $result.original_values_exactly_restored -and -not $result.final_client_status.port_listening -and -not $result.final_client_status.supervisor_lock_held
    [IO.File]::WriteAllText((Join-Path $context.RunDirectory 'system-proxy-real.json'), ($result | ConvertTo-Json -Depth 9), [Text.UTF8Encoding]::new($false))
    if ($null -ne $launcher) { $launcher.Dispose() }
}
$result | ConvertTo-Json -Depth 9
if (-not $result.pass) { exit 1 }

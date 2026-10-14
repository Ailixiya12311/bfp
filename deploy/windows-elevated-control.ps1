param(
    [Parameter(Mandatory=$true)][ValidateSet('start','stop')][string]$Action,
    [ValidateSet('proxy','tun')][string]$Mode = 'tun',
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$RequestId,
    [Parameter(Mandatory=$true)][ValidatePattern('^S-1-[0-9-]{1,96}$')][string]$ExpectedUserSid
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
. (Join-Path $PSScriptRoot 'windows-context.ps1')
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
$context = Get-BfpDesktopContext -DeployRoot $PSScriptRoot
$resultPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory ('elevated-' + $RequestId + '.result.json')) $context.ProjectRoot
$temporaryPath = Assert-BfpDesktopPath ($resultPath + '.tmp') $context.ProjectRoot
$stdoutName = 'desktop-' + $RequestId + '.out.log'
$stderrName = 'desktop-' + $RequestId + '.err.log'
$stdoutPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory $stdoutName) $context.ProjectRoot
$stderrPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory $stderrName) $context.ProjectRoot
$reply = [ordered]@{
    version = 1; request_id = $RequestId; helper_pid = $PID; action = $Action; mode = $Mode
    success = $false; launched = $false; pid = $null; start_utc = $null
    stdout = $stdoutName; stderr = $stderrName; result = $null; error = $null
}
$operation = $null
try {
    if ((Test-Path -LiteralPath $resultPath) -or (Test-Path -LiteralPath $temporaryPath) -or
        (Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) {
        throw 'This elevated request already has output. Use a fresh request identity.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne $ExpectedUserSid) {
        throw 'Use the current Windows account to confirm UAC. A different administrator account cannot use this client profile.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator approval is required for this TUN operation.'
    }
    $wrapper = Assert-BfpDesktopPath (Join-Path $PSScriptRoot 'windows-client.ps1') $context.ProjectRoot
    $powershell = Join-Path $PSHOME 'powershell.exe'
    if ($Action -eq 'start') {
        # The real wrapper is the launcher. Calling it inside this helper would
        # leave -File pointing to the helper and fail lifecycle ownership checks.
        $operation = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start','-Mode',$Mode) -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
        $reply.pid = $operation.Id
        $reply.start_utc = $operation.StartTime.ToUniversalTime().ToString('o')
        $reply.launched = $true
        $reply.success = $true
    } else {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $powershell
        $info.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $wrapper + '" -Action stop -Mode ' + $Mode + ' -Json'
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
        $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
        $operation = [Diagnostics.Process]::Start($info)
        $outputTask = $operation.StandardOutput.ReadToEndAsync()
        $errorTask = $operation.StandardError.ReadToEndAsync()
        $operation.WaitForExit()
        $output = $outputTask.GetAwaiter().GetResult()
        $errorOutput = $errorTask.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($stdoutPath, $output, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($stderrPath, $errorOutput, [Text.UTF8Encoding]::new($false))
        $result = $output | ConvertFrom-Json -ErrorAction Stop
        $summary = [ordered]@{}
        foreach ($field in @('instance_id','stopped','cleanup_complete','state','reason','pid','port_listening','mode')) {
            if ($null -ne $result.PSObject.Properties[$field]) { $summary[$field] = $result.$field }
        }
        $reply.result = [pscustomobject]$summary
        $reply.success = $operation.ExitCode -eq 0 -and $result.cleanup_complete -eq $true
        if (-not $reply.success) {
            $failure = if ($result.error) { [string]$result.error } elseif ($result.reason) { [string]$result.reason } else { 'The elevated stop operation did not complete. Check its logs.' }
            $reply.error = $failure
        }
    }
} catch {
    $reply.success = $false
    $reply.error = $_.Exception.Message
    if ($reply.error.Length -gt 1200) { $reply.error = $reply.error.Substring(0, 1200) }
    if (-not (Test-Path -LiteralPath $stderrPath)) {
        [IO.File]::WriteAllText($stderrPath, $reply.error, [Text.UTF8Encoding]::new($false))
    }
} finally {
    if ($null -ne $operation) { $operation.Dispose() }
    if ($reply.error -and $reply.error.Length -gt 1200) { $reply.error = $reply.error.Substring(0, 1200) }
    $json = $reply | ConvertTo-Json -Depth 5 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 4096) {
        $reply.success = $false
        $reply.result = $null
        $reply.error = 'The elevated operation returned an oversized result. Check its logs.'
        $json = $reply | ConvertTo-Json -Depth 5 -Compress
    }
    [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporaryPath, $resultPath)
}
if ($reply.success) { exit 0 }
exit 1

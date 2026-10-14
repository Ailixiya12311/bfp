param(
    [Parameter(Mandatory = $true)][string]$Package
)

$ErrorActionPreference = 'Stop'
$packagePath = [IO.Path]::GetFullPath($Package)
if (-not (Test-Path -LiteralPath $packagePath -PathType Container)) {
    throw "Package directory does not exist: $packagePath"
}

# Run from a disposable copy so the check never writes credentials, runtime
# state or logs into a published package.
$testRoot = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\.test-tmp'))) ('windows-mutex-' + [guid]::NewGuid().ToString('N'))
$first = $null
$supervisorPath = $null
$nativePath = $null
try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'bin') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'configs') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $packagePath 'start-native.ps1') -Destination $testRoot
    Copy-Item -LiteralPath (Join-Path $packagePath 'bin\bfp-windows-amd64.exe') -Destination (Join-Path $testRoot 'bin')
    Copy-Item -LiteralPath (Join-Path $packagePath 'bin\mihomo-bfp-windows-amd64.exe') -Destination (Join-Path $testRoot 'bin')
    Copy-Item -LiteralPath (Join-Path $packagePath 'configs\native-proxy.yaml') -Destination (Join-Path $testRoot 'configs')
    Copy-Item -LiteralPath (Join-Path $packagePath 'configs\native-tun.yaml') -Destination (Join-Path $testRoot 'configs')

    $bfp = Join-Path $testRoot 'bin\bfp-windows-amd64.exe'
    $supervisorPath = [IO.Path]::GetFullPath($bfp)
    & $bfp keygen -out (Join-Path $testRoot 'credentials') -server-listen '127.0.0.1:51880' -server '127.0.0.1:51880' -tcp-server '127.0.0.1:51880' -socks '127.0.0.1:1080' | Out-Null
    $runtime = Join-Path $testRoot 'runtime'
    New-Item -ItemType Directory -Path $runtime -Force | Out-Null
    $stdout = Join-Path $runtime 'proxy.stdout.log'
    $stderr = Join-Path $runtime 'proxy.stderr.log'
    $nativePath = [IO.Path]::GetFullPath((Join-Path $testRoot 'bin\mihomo-bfp-windows-amd64.exe'))
    $first = Start-Process -FilePath 'pwsh' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $testRoot 'start-native.ps1'), '-Mode', 'proxy') -WorkingDirectory $testRoot -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 250
        if (Test-Path -LiteralPath $stdout -PathType Leaf) {
            $text = [string](Get-Content -Raw -LiteralPath $stdout)
            if ($text -like '*mihomo_started*') { $ready = $true; break }
        }
        $first.Refresh()
        if ($first.HasExited) { break }
    }
    if (-not $ready) {
        throw "first proxy launcher did not start: $((Get-Content -Raw -LiteralPath $stderr -ErrorAction SilentlyContinue))"
    }

    $secondOutput = @(& pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $testRoot 'start-native.ps1') -Mode tun 2>&1 | ForEach-Object { [string]$_ })
    $secondExit = $LASTEXITCODE
    $secondText = $secondOutput -join "`n"
    if ($secondExit -eq 0 -or $secondText -notlike '*Another BFP Mihomo tun instance is already running.*') {
        throw "TUN launcher was not blocked by the proxy instance lock (exit=$secondExit output=$secondText)"
    }

    # Kill only the PowerShell launcher. The Go supervisor must observe its
    # parent exit and terminate Mihomo itself; the verifier must not clean the
    # child before checking that handoff.
    Stop-Process -Id $first.Id -Force -ErrorAction Stop
    $first = $null
    $remaining = @()
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 200
        $remaining = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -eq $nativePath -or ($_.ExecutablePath -eq $supervisorPath -and $_.CommandLine -like '*native-supervise*') })
        if ($remaining.Count -eq 0) { break }
    }
    if ($remaining.Count -ne 0) {
        throw "native child/supervisor remained after launcher termination: $($remaining | Select-Object ProcessId,ExecutablePath,CommandLine | Out-String)"
    }

    [ordered]@{
        pass = $true
        package = $packagePath
        first_mode = 'proxy'
        second_mode = 'tun'
        second_exit = $secondExit
        blocked_by_shared_mutex = $true
        launcher_termination_reaped_child = $true
    } | ConvertTo-Json -Depth 4
}
finally {
    if ($null -ne $first) {
        Stop-Process -Id $first.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $nativePath) {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ExecutablePath -eq $nativePath } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

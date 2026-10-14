param(
    [string]$Version = "0.1.0-preview.5",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "Version must contain only letters, numbers, dots, underscores and hyphens."
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $root "dist" }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$out = Join-Path $OutputRoot ("BFP-" + $Version)
$zip = $out + ".zip"
if ((Test-Path -LiteralPath $out) -or (Test-Path -LiteralPath $zip)) {
    throw "Output already exists. Choose a new -Version or -OutputRoot to preserve the existing package."
}
$stageName = ".bfp-package-" + [Guid]::NewGuid().ToString("N")
$stage = Join-Path $OutputRoot $stageName
$stageZip = Join-Path $OutputRoot ($stageName + ".zip")
$envNames = @("GOCACHE", "GOMODCACHE", "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK")
$savedEnv = @{}
foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process") }

function Get-ModuleSourceFiles([string]$ModuleRoot) {
    $excluded = @("bin", "dist", "docs", "lab", "verification", "third_party", "vendor")
    $pending = [Collections.Generic.Stack[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $pending.Push($ModuleRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            $linked = ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            if ($item.PSIsContainer) {
                if ($linked -or $item.Name.StartsWith(".") -or $item.Name.StartsWith("_") -or
                    $item.Name -in $excluded -or (Test-Path -LiteralPath (Join-Path $item.FullName "go.mod"))) { continue }
                $pending.Push($item.FullName)
            } elseif ($item.Extension -eq ".go" -or
                ($directory -eq $ModuleRoot -and $item.Name -in @("go.mod", "go.sum"))) {
                if ($linked) { throw "Linked source file is not supported: $($item.FullName)" }
                $files.Add($item.FullName)
            }
        }
    }
    return $files | Sort-Object
}

function Get-PayloadEntry([string]$Path, [string]$Base) {
    $item = Get-Item -LiteralPath $Path
    return [ordered]@{
        path = $item.FullName.Substring($Base.Length + 1).Replace('\', '/')
        bytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    }
}

try {
    New-Item -ItemType Directory -Path $stage | Out-Null
    $source = Join-Path $stage "source"
    New-Item -ItemType Directory -Path $source | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage "bin") | Out-Null
    $sourceFiles = @(Get-ModuleSourceFiles $root)
    foreach ($file in $sourceFiles) {
        $relative = $file.Substring($root.Length + 1)
        $destination = Join-Path $source $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath $file -Destination $destination
    }
    foreach ($base in @($stage, $source)) {
        Copy-Item -LiteralPath (Join-Path $root "PRODUCT.md") -Destination (Join-Path $base "PRODUCT.md")
        Copy-Item -LiteralPath (Join-Path $root "PRODUCT.md") -Destination (Join-Path $base "README.md")
        New-Item -ItemType Directory -Path (Join-Path $base "docs") | Out-Null
        Copy-Item -LiteralPath (Join-Path $root "docs\成品运行与部署-v0.1.md") -Destination (Join-Path $base "docs\成品运行与部署-v0.1.md")
    }
    Copy-Item -LiteralPath (Join-Path $root "build.ps1") -Destination (Join-Path $source "build.ps1")
    $sourceEntries = @($sourceFiles | ForEach-Object {
        Get-PayloadEntry (Join-Path $source $_.Substring($root.Length + 1)) $source
    })
    $sourceEntries | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage "source-manifest.json") -Encoding UTF8

    # Use the configured Go caches. Switching to a private module cache here
    # redownloads already available dependencies on every fresh checkout.
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    $env:GOFLAGS = ""
    $env:GOWORK = "off"
    $date = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $commit = "uncommitted"
    $ldflags = "-s -w -X main.buildVersion=$Version -X main.buildCommit=$commit -X main.buildDate=$date"
    Push-Location $source
    try {
        foreach ($platform in @("windows", "linux")) {
            $env:GOOS = $platform
            $binaryName = if ($platform -eq "windows") { "bfp-windows-amd64.exe" } else { "bfp-linux-amd64" }
            & go build -trimpath -ldflags $ldflags -o (Join-Path $stage ("bin\" + $binaryName)) ./cmd/bfp
            if ($LASTEXITCODE -ne 0) { throw "Go build failed for $platform with exit code $LASTEXITCODE." }
        }
    } finally { Pop-Location }

    $entries = @(Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
        Get-PayloadEntry $_.FullName $stage
    })
    $binaries = @(Get-ChildItem -LiteralPath (Join-Path $stage "bin") -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; size = $_.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant() }
    })
    $manifest = [ordered]@{
        product = "bfp"
        version = $Version
        commit = $commit
        built_utc = $date
        scope = "runnable preview; root Go module and Windows/Linux amd64 binaries"
        acceptance_complete = $false
        production_ready = $false
        released = $false
        binaries = $binaries
        source_manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stage "source-manifest.json")).Hash.ToLowerInvariant()
        files = $entries
        credentials_included = $false
    }
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stage "release-manifest.json") -Encoding UTF8
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $stageZip
    # Both outputs are published only after both builds and the ZIP succeed.
    if ((Split-Path -Parent ([IO.Path]::GetFullPath($stage))) -ne $OutputRoot -or
        (Split-Path -Parent ([IO.Path]::GetFullPath($out))) -ne $OutputRoot) { throw "Package paths escaped the output directory." }
    Move-Item -LiteralPath $stage -Destination $out
    Move-Item -LiteralPath $stageZip -Destination $zip
    Write-Output ("package=" + $out)
    Write-Output ("zip=" + $zip)
    Write-Output ("zip_sha256=" + (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant())
} finally {
    foreach ($name in $envNames) {
        if ($null -eq $savedEnv[$name]) {
            Remove-Item -LiteralPath ("Env:\" + $name) -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], "Process")
        }
    }
    # Only this invocation's checked staging paths can be removed.
    foreach ($temporary in @($stage, $stageZip)) {
        $resolved = [IO.Path]::GetFullPath($temporary)
        if ((Split-Path -Parent $resolved) -ne $OutputRoot -or
            -not (Split-Path -Leaf $resolved).StartsWith($stageName)) { throw "Unsafe staging cleanup path." }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
}


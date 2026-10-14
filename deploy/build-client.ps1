param(
    [string]$Version = '0.1.0-preview.4',
    [string]$NativePackage = '',
    [string]$OutputRoot = '',
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PublicEndpoint,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ExpectedExitIp,
    [switch]$IncludeCurrentProfile
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$project = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'windows-context.ps1')
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
if ($Version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') { throw 'Invalid client package version.' }
if (-not $NativePackage) { $NativePackage = Join-Path $project 'dist\BFP-Mihomo-0.1.0-preview.33' }
if (-not $OutputRoot) { $OutputRoot = Join-Path $project 'dist' }
$NativePackage = [IO.Path]::GetFullPath($NativePackage).TrimEnd('\')
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
$bundleName = 'BFP-Client-Windows-' + $Version
$bundle = Join-Path $OutputRoot $bundleName
$zip = $bundle + '.zip'
if ((Test-Path -LiteralPath $bundle) -or (Test-Path -LiteralPath $zip)) { throw 'The client package already exists. Preserve it and choose a new output directory.' }
$instanceId = [guid]::NewGuid().ToString('N')
$descriptor = [ordered]@{ version = 1; instance_id = $instanceId; public_endpoint = $PublicEndpoint; expected_exit_ip = $ExpectedExitIp }
$stageName = '.bfp-client-' + [guid]::NewGuid().ToString('N')
$stage = Join-Path $OutputRoot $stageName
$stageZip = $stage + '.zip'
$ready = $null
$manifest = Get-Content -Raw -LiteralPath (Join-Path $NativePackage 'release-manifest.json') | ConvertFrom-Json
$frozen = @{}
foreach ($entry in $manifest.files) { $frozen[$entry.path] = $entry.sha256 }

function Copy-BfpFrozenFile([string]$Relative, [string]$Destination) {
    $source = [IO.Path]::GetFullPath((Join-Path $NativePackage $Relative))
    if (-not $source.StartsWith($NativePackage + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $source -PathType Leaf) -or
        (Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Invalid native package input.' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $frozen[$Relative]) { throw 'Native payload differs from its frozen manifest.' }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Destination))
    [IO.File]::Copy($source, $Destination, $false)
}
function Write-BfpClientText([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($true))
}
function Protect-BfpPrivateDirectory([string]$Path) {
    $bfpUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Path /inheritance:r /grant:r ('*' + $bfpUserSid + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the private client directory.' }
}

try {
    [void][IO.Directory]::CreateDirectory($OutputRoot)
    [void][IO.Directory]::CreateDirectory($stage)
    [void][IO.Directory]::CreateDirectory((Join-Path $stage 'deploy'))
    [void][IO.Directory]::CreateDirectory((Join-Path $stage 'client\credentials'))
    Write-BfpClientText (Join-Path $stage 'deploy\portable-client.json') ($descriptor | ConvertTo-Json)
    $scripts = @('desktop-client.ps1','windows-client.ps1','windows-context.ps1','windows-lifecycle.ps1','windows-system-proxy.ps1','windows-proxy-watch.ps1','windows-elevated-control.ps1')
    $commands = @('BFP客户端.cmd','启动BFP.cmd','停止BFP.cmd','状态BFP.cmd','检查BFP.cmd')
    foreach ($name in $scripts) { [IO.File]::Copy((Join-Path $PSScriptRoot $name), (Join-Path $stage ('deploy\' + $name))) }
    foreach ($name in $commands) { [IO.File]::Copy((Join-Path $project $name), (Join-Path $stage $name)) }
    # Validate under the staged script's own root, keeping the runtime root
    # check intact instead of changing its process-wide ownership context.
    $validator = Join-Path $stage 'deploy\validate-descriptor.ps1'
    Write-BfpClientText $validator @'
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
[void](Read-BfpDesktopPortableDescriptor -ProjectRoot (Split-Path -Parent $PSScriptRoot))
'@
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $validator
    if ($LASTEXITCODE -ne 0) { throw 'Staged portable descriptor validation failed.' }
    [IO.File]::Delete($validator)
    foreach ($relative in @('bin/bfp-windows-amd64.exe','bin/mihomo-bfp-windows-amd64.exe','configs/native-proxy.yaml','configs/native-tun.yaml','start-native.ps1','windows-tun-support.ps1','windows-tun-cleanup.ps1')) {
        Copy-BfpFrozenFile $relative (Join-Path $stage ('client\' + $relative))
    }
    Copy-BfpFrozenFile 'licenses/Mihomo-GPL-3.0.txt' (Join-Path $stage 'licenses\Mihomo-GPL-3.0.txt')
    Copy-BfpFrozenFile 'source-manifest.json' (Join-Path $stage 'native-source-manifest.json')
    # Preserve the corresponding frozen native sources and rebuild entrypoint.
    foreach ($relative in @($frozen.Keys | Where-Object { $_.StartsWith('source/', [StringComparison]::Ordinal) })) {
        Copy-BfpFrozenFile $relative (Join-Path $stage $relative)
    }
    [void][IO.Directory]::CreateDirectory((Join-Path $stage 'source\desktop\deploy'))
    foreach ($name in ($scripts + @('build-client.ps1'))) { [IO.File]::Copy((Join-Path $PSScriptRoot $name), (Join-Path $stage ('source\desktop\deploy\' + $name))) }
    foreach ($name in $commands) { [IO.File]::Copy((Join-Path $project $name), (Join-Path $stage ('source\desktop\' + $name))) }
    $readme = @'
# BFP Windows 独立客户端

双击 BFP客户端.cmd，选择“应用代理”或“全局 TUN”，点击“启动”。应用代理模式可以接管 Windows 系统代理，也可以在应用中手动填写 HTTP 或 SOCKS5 127.0.0.1:17890。全局 TUN 会请求当前 Windows 账户的管理员授权，接管系统路由与普通 DNS 请求；检查出口在该模式下直接发送请求，不使用显式代理。关闭控制窗口后客户端继续运行，重新打开可以停止。

“恢复原代理设置”可单独撤销接管，保留客户端运行。停止客户端会恢复接管前的设置；独立监控进程处理启动器异常退出。若你或其他软件修改了系统代理，BFP会保留当前设置。该功能只管理当前用户代理，不等于全局 TUN。

程序无需 Python、Go 或安装服务。Windows PowerShell 5.1 和 curl 使用 Windows 自带版本。当前为客户端预览版。全局 TUN 启动和恢复需要管理员授权；实际 Windows 网卡、路由、DNS和异常退出验收范围见本次交付记录。

## 全局 TUN

先停止正在运行的应用代理，再选择全局 TUN。临时网卡、路由和 DNS 就绪后才允许检查出口；UDP与TCP服务器地址会从接管路由中排除，承载绑定启动前的物理出口。停止时等待子进程退出并清理本实例网卡；失败时保留恢复记录，可再次点击停止或重新启动全局 TUN 继续恢复。不要删除 runtime 中的恢复记录来绕过错误。

全局 TUN 会影响本机网络。Windows UAC必须使用当前账户确认；换用其他管理员账户会被拒绝。强制关闭整个进程组时，下一次管理员启动/停止会依据本实例记录恢复。strict-route只在TUN运行期间生效，不是客户端退出后的持久断网保护。

## 配置

公共 ZIP 不包含任何密钥。使用已有、获服务端授权的 BFP 客户端 client.json，放入 client/credentials/client.json。不要放入 server.json、SSH 凭据或服务器清单。需要更换服务器时修改 deploy/portable-client.json 中 public_endpoint 和 expected_exit_ip，并使用匹配的 client.json。

本机已经配置好的私有副本可直接运行；整个私有目录包含客户端密钥，只供本人使用。不要把私有副本当作公共软件包分享。

## 搬动与停止

先点击“停止”，确认代理资源释放，再移动整个目录。目录内部使用固定的相对布局，搬动后无需修改绝对路径。请勿在程序运行中移动目录。

停止BFP.cmd、状态BFP.cmd、检查BFP.cmd 也可直接使用；启动BFP.cmd 使用需要保持打开的命令窗口方式。日志与运行记录在 deploy/runs/<实例编号>，程序状态和出口检查结果不包含密钥。

## 源码与校验

client-manifest.json 记录程序、脚本和冻结源码的 SHA-256。source/bfp、source/mihomo、source/templates 和 source/build-mihomo.py 是对应原生程序的冻结源码及构建入口；source/desktop 是本客户端入口源码。Mihomo 的 GPL-3.0 许可在 licenses/ 中。程序复用原生 preview.31，不改变其协议二进制。

公开包的清单不包含私有配置；私有副本增加的 client/credentials/client.json 不属于公开包的文件清单。公开软件包禁止出现客户端配置、服务器配置、SSH 凭据、部署状态、运行记录或运行日志。
'@
    $readme = $readme.Replace('程序复用原生 preview.31，不改变其协议二进制。', ('程序来自原生 ' + $manifest.version + '，包内冻结源码对应本包协议二进制。'))
    $readme += "`r`n全局 TUN 的网络接管和异常恢复说明见 docs/Windows全局TUN-v0.1.md。`r`n"
    Write-BfpClientText (Join-Path $stage 'README.md') $readme
    [void][IO.Directory]::CreateDirectory((Join-Path $stage 'docs'))
    [IO.File]::Copy((Join-Path $project 'docs\Windows全局TUN-v0.1.md'), (Join-Path $stage 'docs\Windows全局TUN-v0.1.md'))
    $entries = @(Get-ChildItem -LiteralPath $stage -File -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length + 1).Replace('\','/')
        if ($relative -match '(^|/)(credentials|runs|runtime)(/|$)' -or $_.Name -in @('client.json','server.json','current.json')) { throw 'Private or runtime files entered the public client package.' }
        [ordered]@{ path = $relative; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    $clientManifest = [ordered]@{ version = $Version; product = 'BFP Windows portable client'; native_version = $manifest.version; built_utc = [DateTime]::UtcNow.ToString('o'); operator_credentials_included = $false; production_ready = $false; files = $entries }
    Write-BfpClientText (Join-Path $stage 'client-manifest.json') ($clientManifest | ConvertTo-Json -Depth 6)
    # ZipFile preserves frozen hidden source files as well as ordinary files.
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $stageZip, [IO.Compression.CompressionLevel]::Optimal, $false)
    [IO.Directory]::Move($stage, $bundle)
    [IO.File]::Move($stageZip, $zip)

    if ($IncludeCurrentProfile) {
        $context = Get-BfpDesktopContext -DeployRoot $PSScriptRoot
        if ($context.PublicEndpoint -ne $PublicEndpoint -or $context.ExpectedExitIp -ne $ExpectedExitIp) { throw 'Current desktop profile does not match the portable descriptor.' }
        $profile = Join-Path $context.NativeDirectory 'credentials\client.json'
        if (-not (Test-Path -LiteralPath $profile -PathType Leaf) -or (Get-Item -LiteralPath $profile).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Current desktop client profile is missing or linked.' }
        $ready = Join-Path $project ('credentials-client-' + $instanceId)
        if (Test-Path -LiteralPath $ready) { throw 'Private client output already exists.' }
        [void][IO.Directory]::CreateDirectory($ready)
        Protect-BfpPrivateDirectory $ready
        foreach ($item in Get-ChildItem -LiteralPath $bundle -Force) { Copy-Item -LiteralPath $item.FullName -Destination $ready -Recurse }
        [void][IO.Directory]::CreateDirectory((Join-Path $ready 'client\credentials'))
        [IO.File]::Copy($profile, (Join-Path $ready 'client\credentials\client.json'))
    }
    [ordered]@{ public_directory = $bundle; public_zip = $zip; public_zip_sha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant(); private_ready_directory = $ready; client_instance_id = $instanceId; native_version = $manifest.version; credentials_in_public_zip = $false } | ConvertTo-Json
} finally {
    # A failed stage contains public inputs only. Check the exact resolved target
    # before recursive removal, and use PowerShell throughout the operation.
    if (Test-Path -LiteralPath $stage) {
        $resolvedStage = (Resolve-Path -LiteralPath $stage).Path
        if ($resolvedStage -ne [IO.Path]::GetFullPath($stage) -or -not $resolvedStage.StartsWith($OutputRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedStage) -ne $stageName) { throw 'Refusing unsafe stage cleanup.' }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
    if (Test-Path -LiteralPath $stageZip) { Remove-Item -LiteralPath $stageZip -Force }
}

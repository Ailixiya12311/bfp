param([string]$RenderTo = '')
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'windows-context.ps1')
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
. (Join-Path $PSScriptRoot 'windows-system-proxy.ps1')
$context = Get-BfpDesktopContext -DeployRoot $PSScriptRoot
$wrapper = Join-Path $PSScriptRoot 'windows-client.ps1'
[Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object Windows.Forms.Form
$form.Text = 'BFP 客户端'
$form.ClientSize = New-Object Drawing.Size(760, 625)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.BackColor = [Drawing.Color]::FromArgb(245, 247, 251)
$form.Font = New-Object Drawing.Font('Microsoft YaHei UI', 10)

function New-BfpLabel([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height) {
    $control = New-Object Windows.Forms.Label
    $control.Text = $Text
    $control.Location = New-Object Drawing.Point($X, $Y)
    $control.Size = New-Object Drawing.Size($Width, $Height)
    $control.ForeColor = [Drawing.Color]::FromArgb(36, 48, 68)
    $form.Controls.Add($control)
    return $control
}
function New-BfpButton([string]$Text, [int]$X, [int]$Width) {
    $control = New-Object Windows.Forms.Button
    $control.Text = $Text
    $control.Location = New-Object Drawing.Point($X, 258)
    $control.Size = New-Object Drawing.Size($Width, 43)
    $control.FlatStyle = 'Flat'
    $control.BackColor = [Drawing.Color]::White
    $control.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(213, 220, 232)
    $form.Controls.Add($control)
    return $control
}
$title = New-BfpLabel 'BFP' 28 23 170 44
$title.Font = New-Object Drawing.Font('Microsoft YaHei UI', 25, [Drawing.FontStyle]::Bold)
$null = New-BfpLabel '独立会话协议 · UDP 优先 / TCP 回退' 29 76 650 30
$null = New-BfpLabel '运行模式' 30 111 95 28
$modeSelector = New-Object Windows.Forms.ComboBox
$modeSelector.Location = New-Object Drawing.Point(126, 108)
$modeSelector.Size = New-Object Drawing.Size(280, 30)
$modeSelector.DropDownStyle = 'DropDownList'
[void]$modeSelector.Items.Add('应用代理')
[void]$modeSelector.Items.Add('全局 TUN（需要管理员授权）')
$modeSelector.SelectedIndex = 0
$form.Controls.Add($modeSelector)
$stateLabel = New-BfpLabel '正在读取本机状态…' 29 156 650 31
$stateLabel.Font = New-Object Drawing.Font('Microsoft YaHei UI', 13, [Drawing.FontStyle]::Bold)
$detailLabel = New-BfpLabel ('出口服务器  ' + $context.PublicEndpoint) 30 198 690 28
$null = New-BfpLabel ('应用代理  HTTP / SOCKS5  ' + $context.ProxyAddress) 30 228 690 25
$startButton = New-BfpButton '启动' 28 110
$startButton.BackColor = [Drawing.Color]::FromArgb(37, 99, 235)
$startButton.ForeColor = [Drawing.Color]::White
$stopButton = New-BfpButton '停止' 151 110
$checkButton = New-BfpButton '检查出口' 274 135
$copyButton = New-BfpButton '复制代理地址' 422 150
$logButton = New-BfpButton '查看启动日志' 585 147
$systemOnButton = New-BfpButton '接管 Windows 系统代理' 28 226
$systemOnButton.Location = New-Object Drawing.Point(28, 317)
$systemOffButton = New-BfpButton '恢复原代理设置' 267 192
$systemOffButton.Location = New-Object Drawing.Point(267, 317)
$systemLabel = New-BfpLabel 'Windows 系统代理尚未接管' 30 373 703 25

$message = New-Object Windows.Forms.TextBox
$message.Location = New-Object Drawing.Point(29, 409)
$message.Size = New-Object Drawing.Size(703, 120)
$message.Multiline = $true
$message.ReadOnly = $true
$message.ScrollBars = 'Vertical'
$message.BorderStyle = 'FixedSingle'
$message.BackColor = [Drawing.Color]::White
$message.Font = New-Object Drawing.Font('Microsoft YaHei UI', 9)
$message.Text = '应用代理可接管 Windows 代理；全局 TUN 需要启动和停止时确认管理员授权。' + "`r`n" + '切换模式前先停止客户端。关闭本窗口后客户端继续运行。'
$form.Controls.Add($message)
$null = New-BfpLabel '全局 TUN 通过临时网卡转发；停止时回收本次网卡、路由及 DNS 资源。' 29 546 703 25
$null = New-BfpLabel '检查出口只发送一次小型 HTTPS 请求；应用代理与 TUN 使用各自的路径。' 29 575 703 24

$script:job = $null
$script:jobAction = ''
$script:jobKind = 'direct'
$script:jobRequestId = ''
$script:jobResultPath = ''
$script:launcher = $null
$script:startingUntil = [DateTime]::MinValue
$script:verifiedOwner = $null
$script:verifiedIp = ''
$script:latestStdout = ''
$script:latestStderr = ''
$previousLog = Get-ChildItem -LiteralPath $context.RunDirectory -Filter 'desktop-*.out.log' -File | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -ne $previousLog) {
    $script:latestStdout = $previousLog.FullName
    $script:latestStderr = $previousLog.FullName -replace '\.out\.log$', '.err.log'
}

function Show-BfpMessage([string]$Text) { $message.Text = $Text }
function Get-BfpSelectedMode { if ($modeSelector.SelectedIndex -eq 1) { return 'tun' }; return 'proxy' }
function Test-BfpUiAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-BfpFriendlyError([string]$Text) {
    if ($Text -match 'cancelled|canceled|cancel|1223|取消') { return '你取消了管理员授权，本次 TUN 操作未执行。' }
    if ($Text -match 'current Windows account|different administrator') { return '请使用当前 Windows 账户确认 UAC；更换管理员账户不能读取本账户的客户端配置。' }
    if ($Text -match 'another|already running|Another') { return '客户端已在运行，或上次停止仍在收尾。请稍后刷新。' }
    if ($Text -match 'Start the BFP client') { return '请先启动客户端，再检查公网出口。' }
    if ($Text -match 'ownership|owner|identity|mismatch') { return '进程身份校验未通过。为避免结束其他程序，本次操作已停止。' }
    return $Text
}
function Refresh-BfpStatus {
    try {
        $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $systemProxy = Get-BfpSystemProxyStatus -Context $context -Status $status
        $busy = $null -ne $script:job
        $starting = -not $status.running -and [DateTime]::UtcNow -lt $script:startingUntil -and ($null -eq $script:launcher -or -not $script:launcher.HasExited)
        $tunMode = $status.mode -eq 'tun'
        if ($status.running -or $status.cleanup_pending) { $modeSelector.SelectedIndex = $(if ($tunMode) { 1 } else { 0 }) }
        $ready = $status.proxy_owner_verified -and (-not $tunMode -or $status.tun.ready)
        if ($status.running -and $status.owner_verified) {
            $script:startingUntil = [DateTime]::MinValue
            if ($ready) {
                if ($script:verifiedOwner -and $script:verifiedOwner -eq $status.owner_id) {
                    $stateLabel.Text = $(if ($tunMode) { '全局 TUN 运行中 · 最近出口检查通过' } else { '应用代理运行中 · 最近出口检查通过' })
                    $detailLabel.Text = '出口地址  ' + $script:verifiedIp + '    代理  ' + $context.ProxyAddress
                } else {
                    $stateLabel.Text = $(if ($tunMode) { '全局 TUN 已就绪 · 等待检查公网出口' } else { '应用代理运行中 · 等待检查公网出口' })
                    $detailLabel.Text = $(if ($tunMode) { '临时网卡与路由已就绪；检查出口将直接经过 TUN。' } else { '本机代理已监听；点击“检查出口”确认实际联网。' })
                }
                $stateLabel.ForeColor = [Drawing.Color]::FromArgb(22, 125, 82)
            } else {
                $stateLabel.Text = $(if ($tunMode) { '正在启动全局 TUN…' } else { '正在启动应用代理…' })
                $detailLabel.Text = $(if ($tunMode) { '正在等待临时网卡、路由与本机代理资源就绪。' } else { '正在等待本机代理端口就绪。' })
                $stateLabel.ForeColor = [Drawing.Color]::FromArgb(37, 99, 235)
            }
        } elseif ($status.state -in @('invalid_record','owner_mismatch','owner_unverifiable')) {
            $stateLabel.Text = '客户端进程身份无法确认'
            $detailLabel.Text = '查看启动日志和本机状态；当前停止操作会保留其他进程。'
            $stateLabel.ForeColor = [Drawing.Color]::FromArgb(180, 83, 9)
        } elseif ($status.supervisor_lock_held -and -not $status.owner_id) {
            $stateLabel.Text = '检测到其他入口的客户端'
            $detailLabel.Text = '请先关闭原启动窗口，再使用本控制窗口。'
            $stateLabel.ForeColor = [Drawing.Color]::FromArgb(180, 83, 9)
        } elseif ($status.cleanup_pending) {
            $stateLabel.Text = '正在停止…'
            $detailLabel.Text = '正在等待子进程释放代理资源。'
        } elseif ($starting) {
            $stateLabel.Text = '正在启动…'
            $detailLabel.Text = '正在建立本机客户端进程。'
        } elseif ($status.port_listening) {
            $stateLabel.Text = '代理端口被其他进程占用'
            $detailLabel.Text = '当前没有属于本实例的运行记录。'
            $stateLabel.ForeColor = [Drawing.Color]::FromArgb(180, 83, 9)
        } else {
            $stateLabel.Text = '已停止'
            $detailLabel.Text = '出口服务器  ' + $context.PublicEndpoint
            $stateLabel.ForeColor = [Drawing.Color]::FromArgb(86, 101, 122)
            $script:verifiedOwner = $null
            if ($null -ne $script:launcher -and $script:launcher.HasExited) {
                if ($script:launcher.ExitCode -ne 0) { Show-BfpStartupLog }
                $script:launcher.Dispose()
                $script:launcher = $null
            }
        }
        $startButton.Enabled = $status.state -in @('stopped','stale_record') -and -not $status.running -and -not $status.cleanup_pending -and -not $status.port_listening -and -not $busy -and -not $starting
        $stopButton.Enabled = ($status.running -and $status.owner_verified -or $status.cleanup_pending -and $status.owner_id) -and -not $busy
        if ($status.tun.needs_recovery -and -not $busy) { $stopButton.Enabled = $true }
        # A medium-integrity window may need an elevated stop helper to query
        # its own high-integrity launcher. The helper revalidates ownership.
        if ($tunMode -and $status.state -eq 'owner_unverifiable' -and $status.owner_id -and -not $busy) { $stopButton.Enabled = $true }
        $checkButton.Enabled = $status.running -and $status.owner_verified -and $ready -and -not $busy
        $modeSelector.Enabled = -not $status.running -and -not $status.cleanup_pending -and -not $busy -and -not $starting
        $systemOnButton.Enabled = $checkButton.Enabled -and -not $tunMode -and -not $systemProxy.active -and -not $systemProxy.needs_restore
        $systemOffButton.Enabled = $systemProxy.owned -and -not $busy
        if ($systemProxy.owned -and $systemProxy.active) { $systemLabel.Text = 'Windows 系统代理已接管 · 停止客户端时恢复原设置' }
        elseif ($systemProxy.external_change) { $systemLabel.Text = '系统代理已被其他操作更改 · 保留当前设置' }
        elseif ($systemProxy.owned -and $systemProxy.needs_restore) { $systemLabel.Text = '上次接管等待恢复 · 点击“恢复原代理设置”' }
        else { $systemLabel.Text = 'Windows 系统代理尚未接管' }
    } catch {
        $stateLabel.Text = '无法读取客户端状态'
        $startButton.Enabled = $false
        $stopButton.Enabled = $false
        $checkButton.Enabled = $false
        $systemOnButton.Enabled = $false
        $systemOffButton.Enabled = $false
        $modeSelector.Enabled = $false
        Show-BfpMessage (Get-BfpFriendlyError $_.Exception.Message)
    }
}

function Show-BfpStartupLog {
    $paths = @($script:latestStdout, $script:latestStderr, (Join-Path $context.NativeDirectory 'runtime\native-supervisor.stdout.log'), (Join-Path $context.NativeDirectory 'runtime\native-supervisor.stderr.log')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if ($paths.Count -eq 0) { Show-BfpMessage '本次尚无启动日志。启动后可在此查看错误。'; return }
    $lines = foreach ($path in $paths) { Get-Content -LiteralPath $path -Encoding UTF8 -Tail 35 }
    $text = ($lines | Out-String).Trim()
    if ($text.Length -gt 12000) { $text = $text.Substring($text.Length - 12000) }
    Show-BfpMessage $text
}
function Start-BfpElevatedJob([ValidateSet('start','stop')][string]$Action) {
    if ($null -ne $script:job) { return }
    $requestId = [guid]::NewGuid().ToString('N')
    $helper = Assert-BfpDesktopPath (Join-Path $PSScriptRoot 'windows-elevated-control.ps1') $context.ProjectRoot
    $resultPath = Assert-BfpDesktopPath (Join-Path $context.RunDirectory ('elevated-' + $requestId + '.result.json')) $context.ProjectRoot
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:latestStdout = Join-Path $context.RunDirectory ('desktop-' + $requestId + '.out.log')
    $script:latestStderr = Join-Path $context.RunDirectory ('desktop-' + $requestId + '.err.log')
    # ShellExecute/UAC cannot redirect streams. The constrained helper returns
    # a bounded, atomic result and owns the separate wrapper's log files.
    try {
        $script:job = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $helper + '"'),'-Action',$Action,'-Mode','tun','-RequestId',$requestId,'-ExpectedUserSid',$userSid) -WindowStyle Hidden -PassThru
    } catch {
        $failure = $_.Exception
        while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
        if ($failure -is [ComponentModel.Win32Exception] -and $failure.NativeErrorCode -eq 1223) {
            throw 'UAC was cancelled. The TUN operation was not performed.'
        }
        throw
    }
    $script:jobKind = 'elevated'
    $script:jobAction = $Action
    $script:jobRequestId = $requestId
    $script:jobResultPath = $resultPath
    if ($Action -eq 'start') { $script:startingUntil = [DateTime]::UtcNow.AddSeconds(30) }
    Show-BfpMessage $(if ($Action -eq 'start') { '正在启动全局 TUN，等待管理员进程返回结果…' } else { '正在通过管理员进程停止全局 TUN 并回收本次网络资源…' })
    Refresh-BfpStatus
}
function Read-BfpElevatedResult {
    $path = Assert-BfpDesktopPath $script:jobResultPath $context.ProjectRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw '管理员操作未返回结果。请使用当前 Windows 账户确认 UAC；更换账户或启动失败时请查看日志。'
    }
    if ((Get-Item -LiteralPath $path).Length -gt 4096) { throw 'The elevated result is too large.' }
    $reply = [IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
    $allowed = @('version','request_id','helper_pid','action','mode','success','launched','pid','start_utc','stdout','stderr','result','error')
    if ($reply -isnot [pscustomobject] -or @($reply.PSObject.Properties).Count -ne $allowed.Count) { throw 'Invalid elevated result fields.' }
    foreach ($property in $reply.PSObject.Properties) {
        if ($property.Name -cnotin $allowed) { throw 'Invalid elevated result fields.' }
    }
    if ($reply.version -isnot [int] -or $reply.version -ne 1 -or $reply.request_id -cne $script:jobRequestId -or
        $reply.helper_pid -isnot [ValueType] -or $reply.helper_pid -ne $script:job.Id -or
        $reply.action -cne $script:jobAction -or $reply.mode -cne 'tun' -or
        $reply.success -isnot [bool] -or $reply.launched -isnot [bool] -or
        $reply.stdout -cne ('desktop-' + $script:jobRequestId + '.out.log') -or
        $reply.stderr -cne ('desktop-' + $script:jobRequestId + '.err.log')) { throw 'The elevated result does not match this operation.' }
    if ($null -ne $reply.error -and ($reply.error -isnot [string] -or $reply.error.Length -gt 1200)) { throw 'Invalid elevated error result.' }
    if ($reply.action -eq 'stop' -and $reply.success) {
        if ($reply.launched -or $reply.result -isnot [pscustomobject] -or
            $reply.result.cleanup_complete -isnot [bool] -or -not $reply.result.cleanup_complete) { throw 'Invalid elevated stop result.' }
    }
    if ($reply.success -and $reply.action -eq 'start') {
        if ($reply.pid -isnot [ValueType] -or [long]$reply.pid -lt 1 -or [long]$reply.pid -gt [int]::MaxValue -or -not $reply.launched) { throw 'Invalid elevated launcher identity.' }
        [void][DateTime]::ParseExact([string]$reply.start_utc, 'o', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
    }
    return $reply
}
function Start-BfpControlJob([string]$Action) {
    if ($null -ne $script:job) { return }
    $current = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
    if ($Action -eq 'stop' -and ($current.mode -eq 'tun' -or $current.tun.needs_recovery) -and -not (Test-BfpUiAdministrator)) {
        Start-BfpElevatedJob 'stop'
        return
    }
    $mode = if ($Action -eq 'stop' -and $current.tun.needs_recovery) { 'tun' } elseif ($current.mode -in @('proxy','tun')) { $current.mode } else { Get-BfpSelectedMode }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $PSHOME 'powershell.exe'
    $info.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $wrapper + '" -Action ' + $Action + ' -Mode ' + $mode + ' -Json'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $info.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $script:job = [Diagnostics.Process]::Start($info)
    $script:jobKind = 'direct'
    $script:jobAction = $Action
    $jobMessages = @{ check = '正在通过 BFP 检查公网出口…'; stop = '正在恢复原代理设置并停止客户端…'; 'enable-system-proxy' = '正在保存原设置并接管 Windows 系统代理…'; 'restore-system-proxy' = '正在恢复接管前的 Windows 代理设置…' }
    Show-BfpMessage $jobMessages[$Action]
    Refresh-BfpStatus
}

$startButton.Add_Click({
    try {
        $mode = Get-BfpSelectedMode
        if ($mode -eq 'tun' -and -not (Test-BfpUiAdministrator)) {
            Start-BfpElevatedJob 'start'
            return
        }
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
        $script:latestStdout = Join-Path $context.RunDirectory ('desktop-' + $stamp + '.out.log')
        $script:latestStderr = Join-Path $context.RunDirectory ('desktop-' + $stamp + '.err.log')
        $script:launcher = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $wrapper + '"'),'-Action','start','-Mode',$mode) -WindowStyle Hidden -RedirectStandardOutput $script:latestStdout -RedirectStandardError $script:latestStderr -PassThru
        $script:startingUntil = [DateTime]::UtcNow.AddSeconds(20)
        Show-BfpMessage $(if ($mode -eq 'tun') { '正在启动全局 TUN。网络资源就绪后，可检查实际出口。' } else { '正在启动应用代理。就绪后可检查出口或接管 Windows 代理。' })
        Refresh-BfpStatus
    } catch { Show-BfpMessage (Get-BfpFriendlyError $_.Exception.Message) }
})
$stopButton.Add_Click({ try { Start-BfpControlJob 'stop' } catch { Show-BfpMessage $_.Exception.Message } })
$checkButton.Add_Click({ try { Start-BfpControlJob 'check' } catch { Show-BfpMessage $_.Exception.Message } })
$copyButton.Add_Click({ [Windows.Forms.Clipboard]::SetText($context.ProxyAddress); Show-BfpMessage ('已复制 ' + $context.ProxyAddress + '。在应用中选择 HTTP 或 SOCKS5 代理后粘贴。') })
$logButton.Add_Click({ Show-BfpStartupLog })
$systemOnButton.Add_Click({ try { Start-BfpControlJob 'enable-system-proxy' } catch { Show-BfpMessage $_.Exception.Message } })
$systemOffButton.Add_Click({ try { Start-BfpControlJob 'restore-system-proxy' } catch { Show-BfpMessage $_.Exception.Message } })

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1600
$timer.Add_Tick({
    if ($null -ne $script:job -and $script:job.HasExited) {
        $output = ''
        $errorOutput = ''
        $code = $script:job.ExitCode
        try {
            if ($script:jobKind -eq 'elevated') {
                $ack = Read-BfpElevatedResult
                if (-not $ack.success) { throw $(if ($ack.error) { [string]$ack.error } else { 'The elevated operation did not complete. Check its logs.' }) }
                $result = if ($script:jobAction -eq 'start') { $ack } else { $ack.result }
            } else {
                $output = $script:job.StandardOutput.ReadToEnd()
                $errorOutput = $script:job.StandardError.ReadToEnd()
                $result = $output | ConvertFrom-Json
            }
            if ($code -eq 0 -and $script:jobAction -eq 'start' -and $result.success -and $result.launched) {
                $script:startingUntil = [DateTime]::UtcNow.AddSeconds(30)
                Show-BfpMessage ('管理员启动进程已创建（PID ' + $result.pid + '），正在等待全局 TUN 就绪。')
            } elseif ($code -eq 0 -and $script:jobAction -eq 'check' -and $result.success) {
                $status = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
                $script:verifiedOwner = $result.owner_id
                $script:verifiedIp = $result.exit_ip
                Show-BfpMessage ('公网 HTTPS 检查通过。出口地址：' + $result.exit_ip + "`r`n应用代理：" + $context.ProxyAddress)
            } elseif ($code -eq 0 -and $script:jobAction -eq 'stop') {
                Show-BfpMessage '客户端已停止，本次代理与 TUN 网络资源已回收。服务器仍保留运行。'
            } elseif ($code -eq 0 -and $script:jobAction -eq 'enable-system-proxy' -and $result.success) {
                Show-BfpMessage 'Windows 系统代理已接管。支持系统代理的应用可直接使用；停止客户端会恢复原设置。'
            } elseif ($code -eq 0 -and $script:jobAction -eq 'restore-system-proxy') {
                Show-BfpMessage $(if ($result.external_change) { '检测到你或其他程序修改了系统代理，BFP保留当前设置。' } else { '已恢复接管前的代理设置，BFP客户端仍可通过应用代理使用。' })
            } else {
                $script:verifiedOwner = $null
                Show-BfpMessage (Get-BfpFriendlyError $(if ($result.error) { $result.error } else { $output + $errorOutput }))
            }
        } catch {
            $script:startingUntil = [DateTime]::MinValue
            $failure = ($output + $errorOutput).Trim()
            if (-not $failure) { $failure = $_.Exception.Message }
            Show-BfpMessage (Get-BfpFriendlyError $failure)
        }
        $script:job.Dispose()
        $script:job = $null
        $script:jobKind = 'direct'
        $script:jobRequestId = ''
        $script:jobResultPath = ''
    }
    Refresh-BfpStatus
})

$uiMutex = [Threading.Mutex]::new($false, ('Local\BFP-Desktop-Window-' + $context.InstanceId))
$uiOwned = $false
try {
    try { $uiOwned = $uiMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $uiOwned = $true }
    if (-not $uiOwned) { throw 'BFP client window is already open.' }
    if (-not $RenderTo) {
        $initialStatus = Get-BfpDesktopClientStatus -ProjectRoot $context.ProjectRoot -InstanceId $context.InstanceId
        $previousProxy = Get-BfpSystemProxyStatus -Context $context -Status $initialStatus
        if ($previousProxy.owned -and $previousProxy.needs_restore -and $initialStatus.state -in @('stopped','stale_record','stopping')) {
            [void](Restore-BfpSystemProxy -Context $context -ExpectedLeaseId $previousProxy.lease_id)
        }
    }
    Refresh-BfpStatus
    if ($RenderTo) {
        # Render the client area without opening or focusing a desktop window.
        $preview = New-Object Windows.Forms.Panel
        $preview.Size = $form.ClientSize
        $preview.BackColor = $form.BackColor
        $preview.Font = $form.Font
        $children = @($form.Controls)
        foreach ($child in $children) { $preview.Controls.Add($child) }
        $preview.CreateControl()
        $bitmap = New-Object Drawing.Bitmap($preview.Width, $preview.Height)
        try {
            $preview.DrawToBitmap($bitmap, (New-Object Drawing.Rectangle(0, 0, $preview.Width, $preview.Height)))
            $bitmap.Save([IO.Path]::GetFullPath($RenderTo), [Drawing.Imaging.ImageFormat]::Png)
        } finally { $bitmap.Dispose(); $preview.Dispose() }
    } else {
        $timer.Start()
        [void]$form.ShowDialog()
    }
} finally {
    $timer.Stop()
    $timer.Dispose()
    if ($null -ne $script:job) {
        # Registry transactions finish independently when the window closes.
        # Interrupting them could leave a partially applied system proxy.
        if (-not $script:job.HasExited -and $script:jobAction -eq 'check') { $script:job.Kill() }
        $script:job.Dispose()
    }
    if ($null -ne $script:launcher) { $script:launcher.Dispose() }
    $form.Dispose()
    if ($uiOwned) { $uiMutex.ReleaseMutex() }
    $uiMutex.Dispose()
}

param([Parameter(Mandatory=$true)][string]$Runtime)
$ErrorActionPreference = 'Stop'
try {
    . (Join-Path $PSScriptRoot 'windows-tun-support.ps1')
    Remove-BfpWindowsTunState -Runtime $Runtime
    exit 0
} catch {
    # State and private YAML/credentials must never be included in diagnostics.
    Write-Error ('BFP TUN 清理未完成，恢复记录已保留：' + $_.Exception.Message) -ErrorAction Continue
    exit 1
}

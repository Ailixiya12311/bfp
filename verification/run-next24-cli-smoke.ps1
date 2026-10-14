$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$candidate = Join-Path $root '.staging\r9-next24'
$outDir = Join-Path $candidate 'verification\r9-next24\cli-smoke-attempt01'
$tmp = Join-Path $outDir 'runtime'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$exe = Join-Path $outDir 'bfp.exe'
Push-Location $candidate
try { go build -o $exe ./cmd/bfp } finally { Pop-Location }
$keygenOut = Join-Path $tmp 'credentials'
$keygen = Start-Process -FilePath $exe -ArgumentList @('keygen','-out',$keygenOut) -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $outDir 'keygen.jsonl') -RedirectStandardError (Join-Path $outDir 'keygen.err')
if ($keygen.ExitCode -ne 0) { throw "keygen failed $($keygen.ExitCode): $(Get-Content (Join-Path $outDir 'keygen.err') -Raw)" }
$serverPath = Join-Path $keygenOut 'server.json'
$clientPath = Join-Path $keygenOut 'client.json'
$sc = Get-Content $serverPath -Raw | ConvertFrom-Json
$sc.Listen = '127.0.0.1:51890'
$sc.Policy.AllowPrivate = $true
$sc.Policy.AllowedCIDRs = @('127.0.0.0/8')
$sc.Policy.AllowedPorts = @(19190)
$sc.max_sessions = 4
$sc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $serverPath -Encoding utf8
$cc = Get-Content $clientPath -Raw | ConvertFrom-Json
$cc.Server = '127.0.0.1:51890'
$cc.tcp_server = '127.0.0.1:51890'
$cc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $clientPath -Encoding utf8
$fixtureLog = Join-Path $outDir 'fixture.jsonl'
$fixtureErr = Join-Path $outDir 'fixture.err'
$serverLog = Join-Path $outDir 'server.jsonl'
$serverErr = Join-Path $outDir 'server.err'
$probeLog = Join-Path $outDir 'probe.jsonl'
$probeErr = Join-Path $outDir 'probe.err'
$fixture = Start-Process -FilePath $exe -ArgumentList @('fixture','-listen','127.0.0.1:19190') -NoNewWindow -PassThru -RedirectStandardOutput $fixtureLog -RedirectStandardError $fixtureErr
$server = Start-Process -FilePath $exe -ArgumentList @('server','-config',$serverPath,'-stats','250ms') -NoNewWindow -PassThru -RedirectStandardOutput $serverLog -RedirectStandardError $serverErr
$summary = [ordered]@{ candidate = 'r9-next24'; build_exit = 0; keygen_exit = $keygen.ExitCode; probe_exit = $null; probe_result = $null; no_remote = $true; cleanup_verified = $false }
try {
  $ready = $false
  for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 100; if ((Test-Path $fixtureLog) -and (Test-Path $serverLog) -and ((Get-Content $fixtureLog -Raw) -match 'fixture') -and ((Get-Content $serverLog -Raw) -match 'listening')) { $ready = $true; break } }
  if (-not $ready) { throw 'services did not become ready' }
  $probe = Start-Process -FilePath $exe -ArgumentList @('probe','-config',$clientPath,'-target','127.0.0.1:19190','-udp-target','127.0.0.1:19190','-count','3','-size','128','-interval','50ms','-duration','8s','-result',(Join-Path $outDir 'probe-result.json')) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $probeLog -RedirectStandardError $probeErr
  $summary.probe_exit = $probe.ExitCode
  $summary.probe_result = Get-Content (Join-Path $outDir 'probe-result.json') -Raw | ConvertFrom-Json
} finally {
  foreach ($p in @($fixture, $server)) { if ($null -ne $p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
  Start-Sleep -Milliseconds 200
  $summary.cleanup_verified = (($null -eq $fixture -or $fixture.HasExited) -and ($null -eq $server -or $server.HasExited))
  $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $outDir 'summary.json') -Encoding utf8
}
if ($summary.probe_exit -ne 0) { throw "probe failed $($summary.probe_exit): $(Get-Content $probeErr -Raw)" }
Get-Content (Join-Path $outDir 'summary.json') -Raw

param(
    [string]$ProxyExe = "C:\egrio\bin\socks5_validation_proxy.exe",
    [string]$ProbeExe = "C:\egrio\bin\udp_socks5_probe.exe",
    [string]$ListenAddr = "127.0.0.1:19080",
    [string]$NtpServer = "162.159.200.1",
    [int]$NtpPort = 123,
    [string]$ReportDir = ""
)

$ErrorActionPreference = "Stop"
if ($ReportDir -eq "") {
    $ReportDir = Join-Path ([System.IO.Path]::GetTempPath()) ("egrio-udp-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$hostName, $portText = $ListenAddr -split ":", 2
$port = [int]$portText
$proxyStdout = Join-Path $ReportDir "socks5-validation-proxy.stdout.log"
$proxyStderr = Join-Path $ReportDir "socks5-validation-proxy.stderr.log"
$probeStdout = Join-Path $ReportDir "udp-socks5-probe.stdout.log"
$probeStderr = Join-Path $ReportDir "udp-socks5-probe.stderr.log"
$proxy = Start-Process -FilePath $ProxyExe -ArgumentList @($ListenAddr) -WindowStyle Hidden -PassThru -RedirectStandardOutput $proxyStdout -RedirectStandardError $proxyStderr
$probeExitCode = 1
try {
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($proxy.HasExited) {
            throw "SOCKS5 validation proxy exited before it became ready"
        }
        if (Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet) {
            break
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not (Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet)) {
        throw "SOCKS5 validation proxy did not listen on $ListenAddr"
    }

    & $ProbeExe $hostName $port ntp $NtpServer $NtpPort 1> $probeStdout 2> $probeStderr
    $probeExitCode = $LASTEXITCODE
}
finally {
    if (-not $proxy.HasExited) {
        Stop-Process -Id $proxy.Id -Force
        $proxy.WaitForExit()
    }
}

$summary = [ordered]@{
    probe = "production Core SOCKS5 UDP ASSOCIATE to real NTP server"
    proxy = $ListenAddr
    ntp_server = $NtpServer
    ntp_port = $NtpPort
    probe_exit_code = $probeExitCode
    probe_stdout = if (Test-Path $probeStdout) { [string](Get-Content -Raw $probeStdout) } else { "" }
    probe_stderr = if (Test-Path $probeStderr) { [string](Get-Content -Raw $probeStderr) } else { "" }
    pass = ($probeExitCode -eq 0)
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $ReportDir "summary.json")
$summary | ConvertTo-Json -Depth 4
if ($probeExitCode -ne 0) {
    exit $probeExitCode
}

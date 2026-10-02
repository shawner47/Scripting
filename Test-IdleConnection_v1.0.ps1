# ============================================================
# Test-IdleConnection_v1.0.ps1
# Version 1.0
#
# Opens a raw, idle TCP connection to a target host/port and
# monitors it until it drops or is stopped with Ctrl+C.
#
# PURPOSE:
#   No data is ever sent after the initial connect. This tests
#   whether something in the network path (firewall, VPN gateway,
#   NAT) silently drops a genuinely idle TCP session after a
#   period of inactivity.
#
#   Run this alongside Test-ActiveConnection_v1.0.ps1 at roughly
#   the same start time (each in its own PowerShell window):
#     - Idle drops, Active survives  -> idle-timeout mechanism
#     - Both drop at roughly the same time -> hard session limit
#     - Neither drops                -> no timeout in this window
#
# TARGET / PORT:
#   Default target is a domain controller on LDAP port 389.
#   LDAP is a good choice: the DC accepts the TCP connection and
#   holds it open waiting for a bind request, producing a stable
#   idle socket with no application-layer chatter. Any TCP
#   service that accepts connections without immediately sending
#   data works equally well. Change TargetHost/TargetPort to
#   match your environment.
#
# PARAMETERS:
#   -TargetHost              IP or hostname to connect to.
#                            Default: 192.168.10.13
#   -TargetPort              TCP port. Default: 389 (LDAP)
#   -CheckIntervalSeconds    How often to poll status.
#                            Default: 20
#   -LogPath                 CSV log file path. Defaults to a
#                            timestamped file in C:\Temp so
#                            multiple runs do not overwrite each
#                            other.
#
# OUTPUT (CSV columns):
#   Timestamp, ElapsedSeconds, ConnectedFlag, LocalPort, TCPState
#
#   TCPState is read from the OS TCP table via Get-NetTCPConnection
#   and cross-checked against the .NET socket Connected property.
#   Both must agree for a connection to be considered healthy.
#
# INTERPRETING RESULTS:
#   A healthy row shows:  ConnectedFlag=True  TCPState=Established
#   A dropped row shows:  ConnectedFlag=False  TCPState=NOT FOUND
#   The script logs the elapsed time at drop and exits. Compare
#   that time with Test-ActiveConnection_v1.0.ps1 to determine
#   whether a keepalive prevents the drop.
#
# EXAMPLES:
#   Default target (192.168.10.13:389):
#     .\Test-IdleConnection_v1.0.ps1
#
#   Custom target:
#     .\Test-IdleConnection_v1.0.ps1 -TargetHost "10.1.1.5" -TargetPort 443
#
#   Custom log path:
#     .\Test-IdleConnection_v1.0.ps1 -LogPath "D:\Logs\idle-test.csv"
#
# v1.0: Initial release.
# ============================================================

param(
    [string]$TargetHost = "192.168.10.13",
    [int]$TargetPort = 389,
    [int]$CheckIntervalSeconds = 20,
    [string]$LogPath = "C:\Temp\$(Get-Date -Format 'yyyy.MM.dd.HHmmss').idle-connection-log.csv"
)

if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
}

"Timestamp,ElapsedSeconds,ConnectedFlag,LocalPort,TCPState" | Out-File -FilePath $LogPath -Encoding UTF8

Write-Host "Connecting to ${TargetHost}:$TargetPort ..." -ForegroundColor Cyan

$client = New-Object System.Net.Sockets.TcpClient
try {
    $client.Connect($TargetHost, $TargetPort)
} catch {
    Write-Host "FAILED to connect: $_" -ForegroundColor Red
    exit 1
}

if (-not $client.Connected) {
    Write-Host "Connect() returned but socket is not connected. Aborting." -ForegroundColor Red
    exit 1
}

$localPort = $client.Client.LocalEndPoint.Port
$startTime = Get-Date

Write-Host "Connected. Local port: $localPort. Start time: $startTime" -ForegroundColor Green
Write-Host "Monitoring every $CheckIntervalSeconds seconds. Press Ctrl+C to stop.`n" -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Seconds $CheckIntervalSeconds

    $now     = Get-Date
    $elapsed = [math]::Round(($now - $startTime).TotalSeconds, 0)

    $connectedFlag = $client.Connected

    $tcpState = $null
    try {
        $conn     = Get-NetTCPConnection -LocalPort $localPort -RemoteAddress $TargetHost -ErrorAction Stop
        $tcpState = $conn.State
    } catch {
        $tcpState = "NOT FOUND"
    }

    "$now,$elapsed,$connectedFlag,$localPort,$tcpState" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8

    $color = if ($tcpState -eq "Established" -and $connectedFlag) { "Green" } else { "Red" }
    Write-Host "$now  |  Elapsed: ${elapsed}s  |  .NET Connected: $connectedFlag  |  OS TCP State: $tcpState" -ForegroundColor $color

    if ($tcpState -eq "NOT FOUND" -or -not $connectedFlag) {
        Write-Host "`n*** CONNECTION LOST at $now (elapsed ${elapsed}s) -- no FIN/RST was sent by this script. ***" -ForegroundColor Yellow
        Write-Host "Log saved to $LogPath" -ForegroundColor Yellow
        break
    }
}

$client.Close()

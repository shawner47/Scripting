# ============================================================
# Test-ActiveConnection_v1.0.ps1
# Version 1.0
#
# Opens a raw TCP connection to a target host/port and sends a
# single null byte every 5 minutes to keep the connection active,
# polling status every 20 seconds.
#
# PURPOSE:
#   This is the comparison pair to Test-IdleConnection_v1.0.ps1.
#   Run both at the same time in separate PowerShell windows.
#   If the idle connection drops and this one survives, that
#   confirms an idle-timeout mechanism somewhere in the network
#   path (firewall, VPN gateway, NAT), not a hard session-duration
#   limit.
#
#   Interpretation:
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
#   Note: the keepalive byte sent is 0x0A (a line feed). This is
#   not a valid LDAP PDU and will not be interpreted by the server
#   as a bind or any other operation. It is sent purely to produce
#   TCP-level activity. No application-layer protocol is involved.
#
# PARAMETERS:
#   -TargetHost                  IP or hostname to connect to.
#                                Default: 192.168.10.13
#   -TargetPort                  TCP port. Default: 389 (LDAP)
#   -CheckIntervalSeconds        How often to poll status.
#                                Default: 20
#   -KeepaliveIntervalSeconds    How often to send the keepalive
#                                byte. Default: 300 (5 minutes)
#   -LogPath                     CSV log file path. Defaults to a
#                                timestamped file in C:\Temp so
#                                multiple runs do not overwrite
#                                each other.
#
# OUTPUT (CSV columns):
#   Timestamp, ElapsedSeconds, ConnectedFlag, LocalPort,
#   TCPState, KeepaliveSentThisCycle
#
#   KeepaliveSentThisCycle is True in any row where the keepalive
#   byte was transmitted. Use this column to correlate keepalive
#   timing with connection state changes.
#
# INTERPRETING RESULTS:
#   A healthy row shows:  ConnectedFlag=True  TCPState=Established
#   A dropped row shows:  ConnectedFlag=False  TCPState=NOT FOUND
#   Compare drop time (if any) with Test-IdleConnection_v1.0.ps1
#   to determine whether a keepalive prevents the drop.
#
# EXAMPLES:
#   Default target (192.168.10.13:389):
#     .\Test-ActiveConnection_v1.0.ps1
#
#   Custom target:
#     .\Test-ActiveConnection_v1.0.ps1 -TargetHost "10.1.1.5" -TargetPort 443
#
#   Keepalive every 2 minutes instead of 5:
#     .\Test-ActiveConnection_v1.0.ps1 -KeepaliveIntervalSeconds 120
#
# v1.0: Initial release.
# ============================================================

param(
    [string]$TargetHost = "192.168.10.13",
    [int]$TargetPort = 389,
    [int]$CheckIntervalSeconds = 20,
    [int]$KeepaliveIntervalSeconds = 300,
    [string]$LogPath = "C:\Temp\$(Get-Date -Format 'yyyy.MM.dd.HHmmss').active-connection-log.csv"
)

if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
}

"Timestamp,ElapsedSeconds,ConnectedFlag,LocalPort,TCPState,KeepaliveSentThisCycle" |
    Out-File -FilePath $LogPath -Encoding UTF8

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

$stream        = $client.GetStream()
$localPort     = $client.Client.LocalEndPoint.Port
$startTime     = Get-Date
$lastKeepalive = $startTime

Write-Host "Connected. Local port: $localPort. Start time: $startTime" -ForegroundColor Green
Write-Host "Monitoring every $CheckIntervalSeconds seconds, keepalive every $KeepaliveIntervalSeconds seconds. Press Ctrl+C to stop.`n" -ForegroundColor Cyan

while ($true) {
    Start-Sleep -Seconds $CheckIntervalSeconds

    $now           = Get-Date
    $elapsed       = [math]::Round(($now - $startTime).TotalSeconds, 0)
    $keepaliveSent = $false

    if (($now - $lastKeepalive).TotalSeconds -ge $KeepaliveIntervalSeconds) {
        try {
            $stream.Write([byte[]](0x0A), 0, 1)
            $stream.Flush()
            $keepaliveSent = $true
            $lastKeepalive = $now
        } catch {
            Write-Host "Keepalive write FAILED at $now : $_" -ForegroundColor Red
        }
    }

    $connectedFlag = $client.Connected

    $tcpState = $null
    try {
        $conn     = Get-NetTCPConnection -LocalPort $localPort -RemoteAddress $TargetHost -ErrorAction Stop
        $tcpState = $conn.State
    } catch {
        $tcpState = "NOT FOUND"
    }

    "$now,$elapsed,$connectedFlag,$localPort,$tcpState,$keepaliveSent" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8

    $color   = if ($tcpState -eq "Established" -and $connectedFlag) { "Green" } else { "Red" }
    $kaLabel = if ($keepaliveSent) { " [KEEPALIVE SENT]" } else { "" }
    Write-Host "$now  |  Elapsed: ${elapsed}s  |  .NET Connected: $connectedFlag  |  OS TCP State: $tcpState$kaLabel" -ForegroundColor $color

    if ($tcpState -eq "NOT FOUND" -or -not $connectedFlag) {
        Write-Host "`n*** CONNECTION LOST at $now (elapsed ${elapsed}s) -- no FIN/RST was sent by this script. ***" -ForegroundColor Yellow
        Write-Host "Log saved to $LogPath" -ForegroundColor Yellow
        break
    }
}

$client.Close()

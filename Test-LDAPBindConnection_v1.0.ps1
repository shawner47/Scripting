# ============================================================
# Test-LDAPBindConnection_v1.0.ps1
# Version 1.0
#
# Opens an LDAP connection using System.DirectoryServices.Protocols,
# performs a real bind with current Windows credentials
# (Negotiate/Kerberos -- no plaintext credentials), then holds
# the session idle and monitors it every 20 seconds.
#
# PURPOSE:
#   Third test in the TCP idle-timeout diagnostic set. Whereas
#   Test-IdleConnection and Test-ActiveConnection use raw TCP
#   sockets, this script produces a protocol-conforming LDAP
#   session. If a raw socket dies in a few minutes but this
#   session survives much longer, that confirms the path is
#   specifically evaluating LDAP protocol state rather than
#   applying a flat idle-timeout to all port-389 traffic.
#
#   Three-script interpretation guide:
#     Raw idle drops quickly        -> idle-timeout on raw TCP
#     Raw active survives           -> keepalives defeat the timeout
#     LDAP bound survives longest   -> path inspects LDAP state
#     All three drop at same time   -> hard session-duration limit
#     None drop in the test window  -> no timeout at this duration
#
# USES System.DirectoryServices.Protocols:
#   The same library used internally by repadmin, nltest, and
#   other AD tools. AuthType Negotiate means Kerberos is used
#   when available, NTLM as fallback. No password is supplied
#   or required -- the bind uses your current Windows login token.
#   After the bind succeeds, no further LDAP operations are sent;
#   the session is held open idle.
#
# LOCAL PORT DETECTION:
#   Because System.DirectoryServices.Protocols does not expose
#   the underlying socket, the script identifies the local port
#   by querying the OS TCP table immediately after binding. If
#   multiple connections to the same host/port exist, it takes
#   the most recently created one. If none is found, monitoring
#   continues but reports UNKNOWN for TCPState -- the script will
#   run until Ctrl+C since it cannot detect a drop from the
#   OS side. Run this script before opening other connections
#   to the same DC to avoid ambiguity.
#
# PARAMETERS:
#   -TargetHost              IP or hostname to connect to.
#                            Default: 192.168.10.13
#   -TargetPort              TCP port. Default: 389 (LDAP)
#   -CheckIntervalSeconds    How often to poll status.
#                            Default: 20
#   -LogPath                 CSV log file path. Defaults to a
#                            timestamped file in C:\Temp so
#                            multiple runs do not overwrite
#                            each other.
#
# OUTPUT (CSV columns):
#   Timestamp, ElapsedSeconds, TCPState
#
#   TCPState is read from the OS TCP table. Unlike the raw socket
#   scripts, there is no .NET Connected flag to cross-check since
#   LdapConnection does not expose the underlying socket.
#
# INTERPRETING RESULTS:
#   A healthy row shows:  TCPState=Established
#   A dropped row shows:  TCPState=NOT FOUND  (script then exits)
#   UNKNOWN means the local port was not identified -- the script
#   cannot detect a drop and will run until Ctrl+C.
#   Compare drop time with the other two scripts to determine
#   what the network path is enforcing.
#
# EXAMPLES:
#   Default target (192.168.10.13:389):
#     .\Test-LDAPBindConnection_v1.0.ps1
#
#   Custom target:
#     .\Test-LDAPBindConnection_v1.0.ps1 -TargetHost "10.1.1.5"
#
#   Custom log path:
#     .\Test-LDAPBindConnection_v1.0.ps1 -LogPath "D:\Logs\ldap-test.csv"
#
# v1.0: Initial release.
# ============================================================

param(
    [string]$TargetHost = "192.168.10.13",
    [int]$TargetPort = 389,
    [int]$CheckIntervalSeconds = 20,
    [string]$LogPath = "C:\Temp\$(Get-Date -Format 'yyyy.MM.dd.HHmmss').ldap-bind-connection-log.csv"
)

if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
}

"Timestamp,ElapsedSeconds,TCPState" | Out-File -FilePath $LogPath -Encoding UTF8

Add-Type -AssemblyName System.DirectoryServices.Protocols

Write-Host "Connecting and binding to ${TargetHost}:$TargetPort ..." -ForegroundColor Cyan

try {
    $identifier      = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($TargetHost, $TargetPort)
    $ldapConnection  = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $ldapConnection.SessionOptions.ProtocolVersion = 3
    $ldapConnection.Bind()
} catch {
    Write-Host "FAILED to bind: $_" -ForegroundColor Red
    exit 1
}

$startTime = Get-Date
Write-Host "Bind succeeded. Start time: $startTime" -ForegroundColor Green
Write-Host "Monitoring every $CheckIntervalSeconds seconds. Press Ctrl+C to stop.`n" -ForegroundColor Cyan

# Identify the local port by querying the OS TCP table immediately after bind.
# LdapConnection does not expose the underlying socket, so this is the only
# way to cross-check with the OS view. Takes the most recently created
# Established connection to the target in case multiple exist.
Start-Sleep -Seconds 1
$netTcpParams = @{
    RemoteAddress = $TargetHost
    RemotePort    = $TargetPort
    State         = "Established"
    ErrorAction   = "SilentlyContinue"
}
$initialConn = Get-NetTCPConnection @netTcpParams |
    Sort-Object -Property CreationTime -Descending |
    Select-Object -First 1

if (-not $initialConn) {
    Write-Host "Could not identify local port in the OS TCP table. TCPState will report UNKNOWN -- script will run until Ctrl+C." -ForegroundColor Yellow
    $localPort = $null
} else {
    $localPort = $initialConn.LocalPort
    Write-Host "Identified local port: $localPort" -ForegroundColor Cyan
}

while ($true) {
    Start-Sleep -Seconds $CheckIntervalSeconds

    $now     = Get-Date
    $elapsed = [math]::Round(($now - $startTime).TotalSeconds, 0)

    if ($localPort) {
        try {
            $conn     = Get-NetTCPConnection -LocalPort $localPort -RemoteAddress $TargetHost -ErrorAction Stop
            $tcpState = $conn.State
        } catch {
            $tcpState = "NOT FOUND"
        }
    } else {
        $tcpState = "UNKNOWN (local port not identified)"
    }

    "$now,$elapsed,$tcpState" | Out-File -FilePath $LogPath -Append -Encoding UTF8

    $color = if ($tcpState -eq "Established") { "Green" } else { "Red" }
    Write-Host "$now  |  Elapsed: ${elapsed}s  |  OS TCP State: $tcpState" -ForegroundColor $color

    if ($tcpState -eq "NOT FOUND") {
        Write-Host "`n*** CONNECTION LOST at $now (elapsed ${elapsed}s) -- no FIN/RST was sent by this script. ***" -ForegroundColor Yellow
        Write-Host "Log saved to $LogPath" -ForegroundColor Yellow
        break
    }
}

try { $ldapConnection.Dispose() } catch {}

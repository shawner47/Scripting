# ============================================================
# Test-LdapPeriodicActivity_v1.0.ps1
# Version 1.0
#
# Performs a real LDAP bind, then sends a genuine LDAP search
# (not a garbage byte) at a configurable interval, monitoring
# the connection every 20 seconds.
#
# PURPOSE:
#   Comparison test to Test-LdapBindConnection (single bind, then
#   silent -- dies ~921-962s) and the garbage-byte keepalive tests
#   on port 389 (appear to die AT or BEFORE the send, not after).
#
#   This script sends REAL, protocol-conforming LDAP traffic
#   (an actual search operation) at each interval, closer to what
#   genuine AD replication traffic looks like. This answers:
#   does legitimate, repeated protocol activity reset the idle
#   clock and keep the session alive past the ~921-962s mark seen
#   with a single payload, or does the connection still die on
#   the same schedule regardless of real activity?
#
#   Interpretation:
#     - Survives well past ~960s      -> real activity resets idle clock
#     - Dies at/near ~921-962s anyway -> fixed cap independent of activity
#     - Dies earlier than baseline    -> real search traffic itself
#                                         is being treated as suspicious
#                                         (unlikely for a well-formed
#                                         search, but worth ruling out)
#
# PARAMETERS:
#   -TargetHost                IP or hostname to connect to.
#                              Default: 192.168.10.13
#   -TargetPort                TCP port. Default: 389 (LDAP)
#   -CheckIntervalSeconds      How often to poll status. Default: 20
#   -SearchIntervalSeconds     How often to send a real LDAP search.
#                              Default: 120
#   -LogPath                   CSV log file path. Defaults to a
#                              timestamped file in C:\Temp.
#
# OUTPUT (CSV columns):
#   Timestamp, ElapsedSeconds, TCPState, SearchSentThisCycle,
#   SearchSucceeded
#
# EXAMPLES:
#   Default target, search every 2 minutes:
#     .\Test-LdapPeriodicActivity_v1.0.ps1
#
#   Custom target, search every 90 seconds:
#     .\Test-LdapPeriodicActivity_v1.0.ps1 -TargetHost "192.168.10.14" -SearchIntervalSeconds 90
#
# v1.0: Initial release.
# ============================================================

param(
    [string]$TargetHost = "192.168.10.13",
    [int]$TargetPort = 389,
    [int]$CheckIntervalSeconds = 20,
    [int]$SearchIntervalSeconds = 120,
    [string]$LogPath = "C:\Temp\$(Get-Date -Format 'yyyy.MM.dd.HHmmss').ldap-periodic-activity-log.csv"
)

if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
}

"Timestamp,ElapsedSeconds,TCPState,SearchSentThisCycle,SearchSucceeded" |
    Out-File -FilePath $LogPath -Encoding UTF8

Add-Type -AssemblyName System.DirectoryServices.Protocols

Write-Host "Connecting and binding to ${TargetHost}:$TargetPort ..." -ForegroundColor Cyan

try {
    $identifier     = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($TargetHost, $TargetPort)
    $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $ldapConnection.SessionOptions.ProtocolVersion = 3
    $ldapConnection.Bind()
} catch {
    Write-Host "FAILED to bind: $_" -ForegroundColor Red
    exit 1
}

$startTime      = Get-Date
$lastSearchTime = $startTime

Write-Host "Bind succeeded. Start time: $startTime" -ForegroundColor Green
Write-Host "Sending a real LDAP search every $SearchIntervalSeconds seconds. Monitoring every $CheckIntervalSeconds seconds. Press Ctrl+C to stop.`n" -ForegroundColor Cyan

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
    Write-Host "Could not identify local port in the OS TCP table. TCPState will report UNKNOWN." -ForegroundColor Yellow
    $localPort = $null
} else {
    $localPort = $initialConn.LocalPort
    Write-Host "Identified local port: $localPort" -ForegroundColor Cyan
}

while ($true) {
    Start-Sleep -Seconds $CheckIntervalSeconds

    $now             = Get-Date
    $elapsed         = [math]::Round(($now - $startTime).TotalSeconds, 0)
    $searchSent      = $false
    $searchSucceeded = $false

    if (($now - $lastSearchTime).TotalSeconds -ge $SearchIntervalSeconds) {
        $searchSent = $true
        try {
            # A trivial, harmless, well-formed LDAP operation: read the RootDSE.
            $request  = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $null, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base
            )
            $response = $ldapConnection.SendRequest($request)
            $searchSucceeded = $true
            $lastSearchTime  = $now
            Write-Host ">>> Real LDAP search sent and succeeded at ${elapsed}s <<<" -ForegroundColor Magenta
        } catch {
            Write-Host ">>> Real LDAP search FAILED at ${elapsed}s : $_ <<<" -ForegroundColor Red
            $lastSearchTime = $now  # don't hammer retries every check cycle
        }
    }

    $tcpState = $null
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

    "$now,$elapsed,$tcpState,$searchSent,$searchSucceeded" |
        Out-File -FilePath $LogPath -Append -Encoding UTF8

    $color = if ($tcpState -eq "Established") { "Green" } else { "Red" }
    $label = if ($searchSent) { if ($searchSucceeded) { " [SEARCH OK]" } else { " [SEARCH FAILED]" } } else { "" }
    Write-Host "$now  |  Elapsed: ${elapsed}s  |  OS TCP State: $tcpState$label" -ForegroundColor $color

    if ($tcpState -eq "NOT FOUND") {
        Write-Host "`n*** CONNECTION LOST at $now (elapsed ${elapsed}s) -- no FIN/RST was sent by this script. ***" -ForegroundColor Yellow
        Write-Host "Log saved to $LogPath" -ForegroundColor Yellow
        break
    }
}

try { $ldapConnection.Dispose() } catch {}

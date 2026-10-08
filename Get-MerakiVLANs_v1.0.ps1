# ============================================================
# Get-MerakiVLANs_v1.0.ps1
# Version 1.0
#
# Exports the VLAN subnets of every MX appliance network in every Meraki
# organization the API key can see, to one CSV. Networks that run a single
# LAN instead of VLANs are included, using their single-LAN subnet.
#
# WHAT THIS SCRIPT COLLECTS:
#   Organizations, networks, and each appliance network's VLAN list
#   (or single-LAN subnet) through GET calls to the Meraki Dashboard API.
#
# WHAT THIS SCRIPT CHANGES:
#   Meraki:          Nothing. Only GET calls are made.
#   Your PS session: Nothing.
#   Your computer:   Creates the log and output folders if missing. Writes
#                    one log file and one CSV file (see OUTPUT).
#
# HANDLE THE OUTPUT AS SENSITIVE:
#   The CSV lists your internal subnets and network names. Store and share
#   it like any other network inventory.
#
# WHAT THE RESULTS DO NOT SHOW:
#   Networks with no MX appliance (switch-only, wireless-only) have no
#   VLANs in this API and are listed as skipped in the log, not in the CSV.
#   A network that fails after the retries is logged as an ERROR and also
#   missing from the CSV. Check the run summary before relying on the file.
#
# PREREQUISITES:
#   - PowerShell 5.1 or 7 on Windows.
#   - Read access to the organizations in Meraki.
#   - A Meraki API key saved as an encrypted file (see FIRST-TIME SETUP).
#
# FIRST-TIME SETUP (once per Windows user, per computer):
#   1. Get your API key: Meraki Dashboard > click your name (top right) >
#      My profile > API access > Generate new API key. Copy it. Meraki
#      shows the key only once. If you were handed a key by someone else,
#      use that one instead.
#   2. Open PowerShell as the SAME Windows user that will run the script
#      (not as a different user, and not "Run as administrator" unless the
#      script will also run that way). Then run these commands:
#
#        $keyDir = Join-Path $env:USERPROFILE ".meraki"
#        New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
#        Read-Host "Paste Meraki API key" -AsSecureString |
#            Export-Clixml -Path (Join-Path $keyDir "secureApiKey.xml")
#
#      Paste the key when prompted (nothing shows as you type) and press
#      Enter. The key is never written to the screen or to a plain file.
#   3. Run the script (see EXAMPLES). With no parameters it reads
#      %USERPROFILE%\.meraki\secureApiKey.xml.
#
#   The file is encrypted with Windows DPAPI, so it opens only for the same
#   Windows user on the same computer that created it. Copying it to another
#   computer or user, or running the script as a different account (for
#   example a scheduled task running as SYSTEM), will fail with a "could not
#   read the API key file" error. Run those commands again as that account.
#   To rotate the key, generate a new one in Meraki and repeat step 2.
#   Never paste the key into the script, a chat or an e-mail.
#
# PARAMETERS:
#   -KeyPath          Path of the Clixml file holding the API key.
#                     Default: .meraki\secureApiKey.xml in the current
#                     user's profile folder.
#   -OutputDirectory  Folder for the CSV. Default: C:\Temp
#   -MaxRetries       Retries for HTTP 429, 5xx and connection failures.
#                     Default: 5
#
# OUTPUT:
#   <OutputDirectory>\<stamp>.Get-MerakiVLANs_v1.0.csv
#   C:\Logs\Azure\<stamp>.Get-MerakiVLANs_v1.0.log
#   CSV columns: OrganizationName, NetworkName, VLANID, VLANName,
#   VLANSubnet, Source (Vlan or SingleLan).
#
# EXAMPLES:
#   .\Get-MerakiVLANs_v1.0.ps1
#   .\Get-MerakiVLANs_v1.0.ps1 -KeyPath D:\keys\meraki.xml -OutputDirectory D:\Out
#
# v1.0: Initial release. Replaces an untracked script that read the key from
#       a hardcoded user path. Changes from that script, and why:
#       - Setup steps for creating the key file are in FIRST-TIME SETUP.
#       - Key: Get-StoredApiKey checks the file exists, checks it holds a
#         SecureString, and frees the BSTR in a finally block (STANDARDS
#         #50). The old script never freed it. The key now lives only in
#         the request headers.
#       - Networks on a single LAN (HTTP 400 on /appliance/vlans) were
#         silently skipped. They now use /appliance/singleLan, and networks
#         without an MX are logged as skipped.
#       - All calls go through Invoke-MerakiRequest, which retries 429, 5xx
#         and connection failures, and errors are logged per network
#         instead of looking like "no data" (#16, #17, #39, #44).
#       - Results use a List instead of += (#42); the CSV is timestamped and
#         written to -OutputDirectory (#21, #27, #46); an empty result keeps
#         its headers (#47).
# ============================================================

[CmdletBinding()]
param(
    [string]$KeyPath = "",
    [string]$OutputDirectory = "",
    [int]$MaxRetries = 5
)

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs\Azure"
$ScriptVersion = "1.0"
$BaseUrl       = "https://api.meraki.com/api/v1"   # Meraki Dashboard API v1
if ($KeyPath -eq "")         { $KeyPath = Join-Path $env:USERPROFILE ".meraki\secureApiKey.xml" }
if ($OutputDirectory -eq "") { $OutputDirectory = "C:\Temp" }
# ============================================================


# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
foreach ($folder in @($LogDir, $OutputDirectory)) {
    if (-not (Test-Path -Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
}
$scriptName = $MyInvocation.MyCommand.Name -replace '\.ps1$', ''
$logFile    = Join-Path $LogDir "$stamp.$scriptName.log"
$csvFile    = Join-Path $OutputDirectory "$stamp.$scriptName.csv"


function Write-Log {
    param([string]$Message = "", [string]$Level = "INFO")
    $logTs = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line  = "[$logTs] [$Level] $Message"
    $col   = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "SUCCESS" { "Green" }
        default   { "White" }
    }
    Write-Host $line -ForegroundColor $col
    Add-Content -Path $logFile -Value $line
}

function Write-LogTable {
    param($Rows, [string[]]$Properties, [string]$Level = "INFO")
    $text = $Rows | Format-Table -Property $Properties -AutoSize | Out-String -Width 250
    foreach ($tableLine in ($text -split '\r?\n')) {
        if ($tableLine.Trim().Length -gt 0) { Write-Log $tableLine -Level $Level }
    }
}


# -- Reads the API key from the DPAPI-protected Clixml file (#50).
# Returns the key as plain text. The temporary BSTR copy is zeroed and freed
# in the finally block; the caller keeps the result only in the headers.
function Get-StoredApiKey {
    param([string]$Path)
    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "API key file not found: $Path"
    }
    try {
        $secure = Import-Clixml -Path $Path -ErrorAction Stop
    } catch {
        throw "Could not read the API key file $Path. DPAPI files only open for the Windows user and computer that created them. $($_.Exception.Message)"
    }
    if ($secure -isnot [System.Security.SecureString]) {
        throw "API key file $Path does not contain a SecureString."
    }
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $secure.Dispose()
    }
}


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log "Mode: READ-ONLY (GET calls only)"
Write-Log "Key file: $KeyPath"
Write-Log "Output folder: $OutputDirectory"
Write-Log "Log file: $logFile"

try {
    $headers = @{
        "X-Cisco-Meraki-API-Key" = (Get-StoredApiKey -Path $KeyPath)
        "Content-Type"           = "application/json"
    }
} catch {
    Write-Log $_.Exception.Message -Level "ERROR"
    throw
}


# -- Meraki API call wrapper. Every API call goes through it (#16).
# Retries HTTP 429 (honors Retry-After), HTTP 5xx and connection-level
# failures with exponential backoff (#17). Other status codes (400, 404...)
# are rethrown at once so the caller can report them.
function Invoke-MerakiRequest {
    param([string]$Uri)
    $params = @{
        Uri             = $Uri
        Method          = "GET"
        Headers         = $headers
        UseBasicParsing = $true
        ErrorAction     = "Stop"
    }
    $attempt = 0
    while ($true) {
        try {
            return Invoke-WebRequest @params
        } catch {
            $err        = $_
            $response   = $err.Exception.Response
            $statusCode = $null
            if ($response) {
                try { $statusCode = [int]$response.StatusCode } catch { $statusCode = $null }
            }

            $isRateLimited = ($statusCode -eq 429)
            $isTransient   = ($null -ne $statusCode -and $statusCode -ge 500 -and $statusCode -lt 600)
            $isConnection  = ($null -eq $statusCode)

            if (($isRateLimited -or $isTransient -or $isConnection) -and $attempt -lt $MaxRetries) {
                $waitSeconds = 0
                if ($isRateLimited -and $response) {
                    try { $waitSeconds = [int]@($response.Headers.GetValues("Retry-After"))[0] } catch { $waitSeconds = 0 }
                }
                if ($waitSeconds -le 0) { $waitSeconds = [int][math]::Pow(2, $attempt) }

                $reason = "connection failure"
                if ($isRateLimited) { $reason = "rate limited (HTTP 429)" }
                if ($isTransient)   { $reason = "transient error (HTTP $statusCode)" }
                $attemptNumber = $attempt + 1
                Write-Log ("  [RETRY] {0}, waiting {1} sec (attempt {2}/{3})" -f $reason, $waitSeconds, $attemptNumber, $MaxRetries) -Level "WARN"
                Start-Sleep -Seconds $waitSeconds
                $attempt++
                continue
            }
            throw $err
        }
    }
}

# -- Gets a list endpoint, following the rel=next link in the Link header.
# Returns a List of the parsed items. JSON is loaded in three steps (#41).
function Get-MerakiPagedList {
    param([string]$Uri)
    $items    = New-Object System.Collections.Generic.List[object]
    $nextUri  = $Uri
    $pages    = 0
    $maxPages = 500   # safety stop
    while ($nextUri -ne "" -and $pages -lt $maxPages) {
        $resp   = Invoke-MerakiRequest -Uri $nextUri
        $pages++
        $raw    = $resp.Content
        $parsed = $raw | ConvertFrom-Json
        foreach ($entry in @($parsed)) {
            if ($null -ne $entry) { $items.Add($entry) }
        }
        $nextUri    = ""
        $linkHeader = [string]@($resp.Headers["Link"])[0]
        if ($linkHeader -match '<([^>]+)>\s*;\s*rel=next') { $nextUri = $Matches[1] }
    }
    return $items
}

# -- Gets a single object endpoint.
function Get-MerakiObject {
    param([string]$Uri)
    $resp   = Invoke-MerakiRequest -Uri $Uri
    $raw    = $resp.Content
    $parsed = $raw | ConvertFrom-Json
    return $parsed
}


$results = New-Object System.Collections.Generic.List[object]
$summary = New-Object System.Collections.Generic.List[object]

try {
    $organizations = @(Get-MerakiPagedList -Uri "$BaseUrl/organizations")
} catch {
    Write-Log "Could not list organizations (bad key or no access?): $($_.Exception.Message)" -Level "ERROR"
    throw
}
Write-Log ("Organizations found: {0}" -f $organizations.Count)

foreach ($org in $organizations) {
    $orgName = $org.name
    $orgId   = $org.id
    Write-Log "Organization: $orgName"

    try {
        $networks = @(Get-MerakiPagedList -Uri "$BaseUrl/organizations/$orgId/networks?perPage=1000")
    } catch {
        Write-Log "  Could not list networks for ${orgName}: $($_.Exception.Message)" -Level "ERROR"
        $summary.Add([PSCustomObject]@{ Organization = $orgName; Network = "(network list)"; Status = "Failed-NetworkList"; Rows = 0 })
        continue
    }
    Write-Log ("  Networks found: {0}" -f $networks.Count)

    foreach ($network in $networks) {
        $networkName = $network.name
        $networkId   = $network.id

        if (@($network.productTypes) -notcontains "appliance") {
            Write-Log "  Network: $networkName -- no MX appliance, skipped"
            $summary.Add([PSCustomObject]@{ Organization = $orgName; Network = $networkName; Status = "Skipped-NoAppliance"; Rows = 0 })
            continue
        }

        try {
            $vlanSettings = Get-MerakiObject -Uri "$BaseUrl/networks/$networkId/appliance/vlans/settings"
            $rowsBefore   = $results.Count

            if ($vlanSettings.vlansEnabled) {
                $vlans = @(Get-MerakiPagedList -Uri "$BaseUrl/networks/$networkId/appliance/vlans")
                foreach ($vlan in $vlans) {
                    $results.Add([PSCustomObject]@{
                        OrganizationName = $orgName
                        NetworkName      = $networkName
                        VLANID           = $vlan.id
                        VLANName         = $vlan.name
                        VLANSubnet       = $vlan.subnet
                        Source           = "Vlan"
                    })
                }
            } else {
                $lan = Get-MerakiObject -Uri "$BaseUrl/networks/$networkId/appliance/singleLan"
                $results.Add([PSCustomObject]@{
                    OrganizationName = $orgName
                    NetworkName      = $networkName
                    VLANID           = ""
                    VLANName         = "Single LAN"
                    VLANSubnet       = $lan.subnet
                    Source           = "SingleLan"
                })
            }

            $rowCount = $results.Count - $rowsBefore
            Write-Log ("  Network: {0} -- {1} subnet(s)" -f $networkName, $rowCount)
            $summary.Add([PSCustomObject]@{ Organization = $orgName; Network = $networkName; Status = "Success"; Rows = $rowCount })
        } catch {
            Write-Log ("  Network: {0} -- FAILED: {1}" -f $networkName, $_.Exception.Message) -Level "ERROR"
            $summary.Add([PSCustomObject]@{ Organization = $orgName; Network = $networkName; Status = "Failed-Api"; Rows = 0 })
        }
    }
}

Write-Log "Run summary:"
Write-LogTable -Rows $summary -Properties @("Organization", "Network", "Status", "Rows")

$failed = @($summary | Where-Object { $_.Status -like "Failed-*" })
if ($failed.Count -gt 0) {
    Write-Log ("{0} network(s) failed and are missing from the results." -f $failed.Count) -Level "ERROR"
}

if ($results.Count -eq 0) {
    Write-Log "No subnets found. No CSV was written." -Level "WARN"
    Write-Log "$scriptName finished"
    exit 0
}

$results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Log "Files written:" -Level "SUCCESS"
Write-Log "  $csvFile" -Level "SUCCESS"
Write-Log "  $logFile" -Level "SUCCESS"
Write-Log "$scriptName finished"

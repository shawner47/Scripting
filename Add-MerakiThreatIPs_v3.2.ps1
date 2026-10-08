# ============================================================
# Add-MerakiThreatIPs_v3.2.ps1
# Version 3.2
#
# Day-to-day operation: adds new threat IPs to Meraki as Policy
# Objects (one per CIDR) and adds them to the org-level Policy
# Object Group. Changes reach every network that has the deny
# rule installed by Initialize-MerakiThreatRule.ps1.
#
# WHAT THIS SCRIPT CHANGES:
#   Meraki:          Nothing with -Preview, -ListGroups or
#                    -ListObjects. Otherwise it creates one
#                    policy object per new IP, named
#                    Threat-<ip>-<mask> (dots become _), and
#                    adds the object IDs to the group set in
#                    CONFIGURATION. It only ever ADDS to the
#                    group. It never removes objects, and it
#                    never edits or deletes existing objects.
#   Your PS session: Nothing.
#   Your computer:   Creates the log folder if it does not
#                    exist, and writes one log file.
#
# HANDLE THE OUTPUT AS SENSITIVE:
#   The log lists every IP you submit and the Meraki object IDs
#   created for them. Treat it as you would the blocklist.
#
# PREREQUISITES:
#   - Windows PowerShell 5.1 or PowerShell 7
#   - A Meraki Dashboard API key with write access to the org
#   - Fill in the three your_xxx_here values in CONFIGURATION.
#     Run with -ListGroups first if you do not know the group ID.
#
# PARAMETERS:
#   -NewIPs        One or more IPs or CIDRs, for example
#                  "1.2.3.4","5.6.7.0/24". An IP with no mask gets
#                  /32. Default: none.
#   -IPFile        Path to a text file with one IP or CIDR per
#                  line. Blank lines and lines starting with #
#                  are ignored. Default: none.
#                  Give -NewIPs, -IPFile or both.
#   -ListGroups    Switch. Lists the policy object groups and
#                  their IDs, then stops.
#   -ListObjects   Switch. Lists the policy objects, then stops.
#   -Preview       Switch. Shows what would be created and added
#                  and makes no change. Without it, the changes
#                  are made.
#
# OUTPUT:
#   $LogDir\yyyy.MM.dd.HHmmss.Add-MerakiThreatIPs_v3.2.log
#   (no other files)
#
# EXAMPLES:
#   .\Add-MerakiThreatIPs_v3.2.ps1 -IPFile "C:\path\to\blocklist.txt" -Preview
#       Shows what would happen. Changes nothing.
#
#   .\Add-MerakiThreatIPs_v3.2.ps1 -IPFile "C:\path\to\blocklist.txt"
#       Adds every IP in the file.
#
#   .\Add-MerakiThreatIPs_v3.2.ps1 -NewIPs "1.2.3.4/32","5.6.7.8/32"
#       Adds the two IPs given on the command line.
#
#   .\Add-MerakiThreatIPs_v3.2.ps1 -IPFile "C:\path\to\blocklist.txt" -NewIPs "1.2.3.4/32"
#       Adds the file's IPs plus the one on the command line.
#
#   .\Add-MerakiThreatIPs_v3.2.ps1 -ListGroups
#   .\Add-MerakiThreatIPs_v3.2.ps1 -ListObjects
#       Read-only lists.
#
# v3.2 changes:
#   - Brought up to STANDARDS.md: [CmdletBinding()], a required-
#     parameter check (#13, #34), a CONFIGURATION block with
#     $ScriptVersion (#8, #35), the standard Write-Log and
#     Write-LogTable, so every line goes to the log in level
#     colors (#19, #22), run framing (#45), the log file named
#     <stamp>.<script>.log (#21), splatting instead of backtick
#     continuations (#12), List[object] in loops (#42),
#     Join-Path (#27), throw on fatal errors (#24), ASCII only
#     (#4), and file names/headers that match this version (#8,
#     #32, #33).
#   - Fixed: the callers passed -Headers to Invoke-MerakiRequest,
#     which has no such parameter. PowerShell dropped it into
#     $args without any message, so it did nothing. The wrapper
#     uses the script-level $headers, and the callers no longer
#     pass it.
#   - Fixed: the wrapper never retried a dropped connection.
#     A failed connection has no response, and [int] of nothing
#     is 0, so it matched neither the 429 nor the 5xx test.
#     Connection-level failures (no status code) are now
#     retried with the same backoff, as Standard 17 requires.
#   - Fixed: Retry-After is read with GetValues(), which works
#     on both PowerShell 5.1 and 7. The old indexer form could
#     fail on 7 and quietly fall back to the backoff time.
#   - Added -Preview (#23, #31). It fetches the current state
#     (read only) and reports what would be created and added.
#   - Added CIDR checking. An entry that is not a valid IPv4
#     address or CIDR is logged as a WARN and skipped, instead
#     of being sent to Meraki to fail. Lines starting with # in
#     the IP file are ignored.
#   - The policy object list request now asks for perPage=5000,
#     and logs a WARN if that many come back, because a full
#     page could mean objects were left out of the "already
#     exists" check. perPage is from Meraki's API documentation
#     as I know it, and has not been tested against a live org.
#     Run -Preview first. A 400 error on the object list means
#     the parameter needs adjusting.
#   - Verified by: static checks only (encoding, balanced
#     braces, ASCII). Not yet run against a Meraki org. Run
#     -Preview and read it before the first real run (#48).
#
# v3.1 changes:
#   - Added Invoke-MerakiRequest wrapper; all API calls now
#     retry on HTTP 429 / transient 5xx.
#
# v3.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string[]]$NewIPs = @(),
    [string]$IPFile = "",
    [switch]$ListGroups,
    [switch]$ListObjects,
    [switch]$Preview
)

$missing = @()
if (-not $ListGroups -and -not $ListObjects -and @($NewIPs).Count -eq 0 -and $IPFile -eq "") {
    $missing += "-NewIPs and/or -IPFile (or use -ListGroups / -ListObjects)"
}
if ($missing.Count -gt 0) { throw ("Missing required parameter(s): {0}" -f ($missing -join ", ")) }

# ============================================================
# CONFIGURATION -- placeholders only for secrets (#18)
# ============================================================
$ApiKey        = "your_api_key_here"
$OrgId         = "your_org_id_here"
$GroupId       = "your_group_id_here"   # run with -ListGroups to find it
$LogDir        = "C:\Logs\Meraki"       # kept from v3.0 so old and new logs stay together
$ScriptVersion = "3.2"
$MaxRetries    = 5                      # retries per API call on 429 / 5xx / dropped connection
$PerPage       = 5000                   # policy objects per request (Meraki maximum)
# ============================================================


# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
if (-not (Test-Path -Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$scriptName = $MyInvocation.MyCommand.Name -replace '\.ps1$', ''
$logFile    = Join-Path $LogDir "$stamp.$scriptName.log"


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


$headers = @{
    "X-Cisco-Meraki-API-Key" = $ApiKey
    "Content-Type"           = "application/json"
}
$baseUrl = "https://api.meraki.com/api/v1/organizations/$OrgId"


# -- Meraki API call wrapper. Every API call in this script goes through it (#16).
# Retries HTTP 429 (honors Retry-After), HTTP 5xx, and connection-level
# failures (no HTTP response at all) with exponential backoff (#17).
# Other status codes (400, 404, etc.) are rethrown at once so the
# caller's catch block reports them.
function Invoke-MerakiRequest {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [string]$Body = ""
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = "Stop"
    }
    if ($Body -ne "") { $params["Body"] = $Body }

    $attempt = 0
    while ($true) {
        try {
            return Invoke-RestMethod @params
        } catch {
            $err      = $_
            $response = $err.Exception.Response

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


function Test-ValidCidr {
    param([string]$Value)
    if ($Value -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $false }
    foreach ($octetIndex in 1..4) {
        if ([int]$Matches[$octetIndex] -gt 255) { return $false }
    }
    if ([int]$Matches[5] -gt 32) { return $false }
    return $true
}


Write-Log "$scriptName started (version $ScriptVersion)"
$modeText = "APPLY - changes will be made"
if ($Preview) { $modeText = "PREVIEW - no changes will be made" }
if ($ListGroups -or $ListObjects) { $modeText = "LIST - read only" }
Write-Log "Mode: $modeText"
Write-Log "Log file: $logFile"

# Stop early if a secret is still a placeholder
$placeholders = @()
if ($ApiKey -like "your_*_here") { $placeholders += "`$ApiKey" }
if ($OrgId -like "your_*_here") { $placeholders += "`$OrgId" }
if (-not $ListGroups -and -not $ListObjects -and $GroupId -like "your_*_here") { $placeholders += "`$GroupId" }
if ($placeholders.Count -gt 0) {
    $placeholderText = $placeholders -join ", "
    Write-Log "CONFIGURATION still has placeholder value(s): $placeholderText" -Level "ERROR"
    throw "Fill in CONFIGURATION before running: $placeholderText"
}


# -- List modes (read only)
if ($ListGroups -or $ListObjects) {

    if ($ListGroups) {
        Write-Log "Fetching Policy Object Groups..."
        try {
            $groups = @(Invoke-MerakiRequest -Uri "$baseUrl/policyObjects/groups")
        } catch {
            Write-Log "Error fetching groups: $_" -Level "ERROR"
            throw
        }
        if ($groups.Count -eq 0) {
            Write-Log "No policy object groups found." -Level "WARN"
        } else {
            $groupRows = foreach ($g in $groups) {
                [pscustomobject]@{ Id = $g.id; Name = $g.name; ObjectCount = @($g.objectIds).Count }
            }
            Write-LogTable -Rows $groupRows -Properties "Id", "Name", "ObjectCount"
        }
    }

    if ($ListObjects) {
        Write-Log "Fetching Policy Objects..."
        try {
            $objects = @(Invoke-MerakiRequest -Uri "$baseUrl/policyObjects?perPage=$PerPage")
        } catch {
            Write-Log "Error fetching objects: $_" -Level "ERROR"
            throw
        }
        if ($objects.Count -eq 0) {
            Write-Log "No policy objects found." -Level "WARN"
        } else {
            $objectRows = foreach ($o in $objects) {
                [pscustomobject]@{ Id = $o.id; Name = $o.name; Type = $o.type; Cidr = $o.cidr }
            }
            Write-LogTable -Rows $objectRows -Properties "Id", "Name", "Type", "Cidr"
            if ($objects.Count -ge $PerPage) {
                Write-Log "The list returned $($objects.Count) objects, the page size. There may be more." -Level "WARN"
            }
        }
    }

    Write-Log "$scriptName finished"
    exit 0
}


# -- Collect the IPs from -NewIPs and -IPFile
$rawIPs = New-Object System.Collections.Generic.List[string]

foreach ($item in $NewIPs) {
    if ($item -and $item.Trim() -ne "") { $rawIPs.Add($item.Trim()) }
}

if ($IPFile -ne "") {
    if (-not (Test-Path -Path $IPFile)) {
        Write-Log "File not found: $IPFile" -Level "ERROR"
        throw "File not found: $IPFile"
    }
    $fileCount = 0
    foreach ($fileLine in @(Get-Content -Path $IPFile -ErrorAction Stop)) {
        $entry = $fileLine.Trim()
        if ($entry -eq "" -or $entry.StartsWith("#")) { continue }
        $rawIPs.Add($entry)
        $fileCount++
    }
    Write-Log "Loaded $fileCount IP(s) from $IPFile"
}

# Add /32 where there is no mask, then check each entry
$validIPs     = New-Object System.Collections.Generic.List[string]
$skippedCount = 0
foreach ($entry in $rawIPs) {
    $cidrValue = $entry
    if ($cidrValue -notmatch '/') { $cidrValue = "$cidrValue/32" }
    if (Test-ValidCidr -Value $cidrValue) {
        $validIPs.Add($cidrValue)
    } else {
        Write-Log "  [SKIP]    '$entry' is not a valid IPv4 address or CIDR" -Level "WARN"
        $skippedCount++
    }
}

$NewIPs = @($validIPs | Sort-Object -Unique)
if ($NewIPs.Count -eq 0) {
    Write-Log "No valid IPs to process." -Level "ERROR"
    throw "No valid IPs to process."
}
Write-Log "Processing $($NewIPs.Count) unique IP(s) after checking and removing duplicates"


# -- Fetch all existing Policy Objects once, up front (read only)
Write-Log "Fetching existing Policy Objects from Meraki..."
try {
    $existingObjects = @(Invoke-MerakiRequest -Uri "$baseUrl/policyObjects?perPage=$PerPage")
} catch {
    Write-Log "Could not fetch existing policy objects: $_" -Level "ERROR"
    throw
}
$existingLookup = @{}
foreach ($obj in $existingObjects) {
    $existingLookup[$obj.name] = $obj.id
}
Write-Log "Found $($existingObjects.Count) existing policy object(s)."
if ($existingObjects.Count -ge $PerPage) {
    Write-Log "That is the page size, so some existing objects may not be in the list. Duplicates are possible." -Level "WARN"
}


# -- Create or reuse a Policy Object for each IP
$targetObjectIds = New-Object System.Collections.Generic.List[object]
$createdCount    = 0
$reusedCount     = 0
$failCount       = 0

Write-Log "Processing Policy Objects..."

foreach ($cidr in $NewIPs) {

    $objectName = "Threat-$($cidr -replace '/', '-' -replace '\.', '_')"

    if ($existingLookup.ContainsKey($objectName)) {
        $existingId = $existingLookup[$objectName]
        $targetObjectIds.Add($existingId)
        Write-Log "  [EXISTS]  $cidr  ->  ID: $existingId"
        $reusedCount++
        continue
    }

    if ($Preview) {
        Write-Log "  [WOULD CREATE]  $cidr  ->  $objectName" -Level "WARN"
        $createdCount++
        continue
    }

    $objectBody = @{
        name     = $objectName
        category = "network"
        type     = "cidr"
        cidr     = $cidr
    } | ConvertTo-Json

    try {
        $created = Invoke-MerakiRequest -Uri "$baseUrl/policyObjects" -Method "POST" -Body $objectBody
        $targetObjectIds.Add($created.id)
        Write-Log "  [CREATED] $cidr  ->  ID: $($created.id)" -Level "SUCCESS"
        $createdCount++
    } catch {
        Write-Log "  [FAIL]    $cidr  ->  $_" -Level "ERROR"
        $failCount++
    }
}


# -- Add the objects to the Policy Object Group
if ($targetObjectIds.Count -gt 0 -or $Preview) {

    Write-Log "Reading Policy Object Group $GroupId..."

    try {
        $group = Invoke-MerakiRequest -Uri "$baseUrl/policyObjects/groups/$GroupId"

        $existingIds = @($group.objectIds | Where-Object { $_ })
        $mergedIds   = @(@($existingIds) + $targetObjectIds.ToArray() | Sort-Object -Unique)

        Write-Log "  IDs already in group  : $($existingIds.Count)"
        Write-Log "  IDs being added       : $($targetObjectIds.Count)"
        Write-Log "  Total after merge     : $($mergedIds.Count)"

        if ($Preview) {
            Write-Log "  Objects marked WOULD CREATE are not counted above, because they have no ID until they are created." -Level "WARN"
        } else {
            $groupBody = [ordered]@{
                name      = $group.name
                objectIds = $mergedIds
            } | ConvertTo-Json -Depth 10

            Write-Log "Updating Policy Object Group $GroupId..."
            $result = Invoke-MerakiRequest -Uri "$baseUrl/policyObjects/groups/$GroupId" -Method "PUT" -Body $groupBody
            Write-Log "  [OK] Group updated. API confirms objects in group: $(@($result.objectIds).Count)" -Level "SUCCESS"
        }

    } catch {
        Write-Log "  [FAIL] Could not read or update the group: $_" -Level "ERROR"
    }
}


# -- Summary
Write-Log "------------------------------"
if ($Preview) {
    Write-Log "Preview only. No changes were made. Run again without -Preview to apply." -Level "WARN"
    Write-Log "  Would create : $createdCount"
} else {
    Write-Log "  Created  : $createdCount" -Level "SUCCESS"
}
Write-Log "  Reused   : $reusedCount"
Write-Log "  Skipped  : $skippedCount (not a valid IP or CIDR)"
$failLevel = "INFO"
if ($failCount -gt 0) { $failLevel = "ERROR" }
Write-Log "  Failed   : $failCount" -Level $failLevel
Write-Log "------------------------------"
Write-Log "$scriptName finished"

# ============================================================
# Add-MerakiThreatIPs_v3.5.ps1
# Version 3.5
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
#   $LogDir\yyyy.MM.dd.HHmmss.Add-MerakiThreatIPs_v3.5.log
#   (no other files)
#
# EXAMPLES:
#   .\Add-MerakiThreatIPs_v3.5.ps1 -IPFile "C:\path\to\blocklist.txt" -Preview
#       Shows what would happen. Changes nothing.
#
#   .\Add-MerakiThreatIPs_v3.5.ps1 -IPFile "C:\path\to\blocklist.txt"
#       Adds every IP in the file.
#
#   .\Add-MerakiThreatIPs_v3.5.ps1 -NewIPs "1.2.3.4/32","5.6.7.8/32"
#       Adds the two IPs given on the command line.
#
#   .\Add-MerakiThreatIPs_v3.5.ps1 -IPFile "C:\path\to\blocklist.txt" -NewIPs "1.2.3.4/32"
#       Adds the file's IPs plus the one on the command line.
#
#   .\Add-MerakiThreatIPs_v3.5.ps1 -ListGroups
#   .\Add-MerakiThreatIPs_v3.5.ps1 -ListObjects
#       Read-only lists.
#
# v3.5 changes:
#   - Fixed: the group update failed with HTTP 400. The v3.4 real
#     run on 2026-10-08 logged Meraki's reason: "One or more
#     specified policy objects have duplicate values". Meraki
#     does not allow a group to hold two policy objects with the
#     same value. The org has more objects than the blocklist
#     (9247 against 9037 IPs), so some objects share a value
#     under different names. The 2026-08-31 failure probably had
#     the same cause, but that log has no reason to confirm it.
#   - The script now checks the combined list before the group
#     update. When an object has the same value as one already in
#     the list, it is left out of the update and logged in a
#     table under WARN. Current group members are kept first, so
#     nothing is removed from the group. The IP stays covered by
#     the object that was kept.
#   - Only identical values are detected (the same CIDR text, the
#     same FQDN, or the same IP and mask). If Meraki still reports
#     duplicates after this, the script says so and the cause is
#     something it cannot see, such as the same network written
#     two ways.
#   - Verified by: static checks only (encoding, balanced
#     braces, ASCII). Not yet run against a Meraki org. Run
#     -Preview first, and read the duplicate table (#48).
#
# v3.4 changes:
#   - Fixed: the policy object list stopped at 5000 objects and
#     the script never asked for the next page. In the
#     2026-08-31 run log, "Found 5000 existing policy object(s)"
#     was followed by 1015 of 5877 IPs failing with HTTP 400 when
#     created, mixed in with successes all through the list. The
#     likely cause is that those IPs already existed past the
#     first 5000, so the "already exists" check missed them and
#     Meraki refused the duplicate names. That cause is NOT yet
#     confirmed, because the old script did not log Meraki's
#     reason (see v3.3). The list now follows the next-page
#     link in Meraki's Link header until there are no more
#     pages. -ListObjects uses it too.
#   - Removed the perPage=5000 request parameter added in v3.2.
#     It was untested, and the default page already returned
#     5000.
#   - The list logs how many items came back and in how many
#     pages. A WARN is logged if a single page returns the
#     suspect size set in CONFIGURATION (5000), because that
#     may mean the list is still cut short.
#   - Invoke-MerakiRequest has a -Raw switch that returns the
#     whole response (needed to read the Link header). It uses
#     Invoke-WebRequest, still inside the wrapper (#16).
#   - Not changed: the group update. In the same log it failed
#     with HTTP 400 (group at 145 members, 4862 being added).
#     The reason is not known. v3.3's error logging will show it.
#   - Verified by: static checks only (encoding, balanced
#     braces, ASCII). Not yet run against a Meraki org. Run
#     -Preview first (#48).
#
# v3.3 changes:
#   - Failed API calls now log Meraki's own error text. In
#     Windows PowerShell 5.1, "$_" for a failed call shows only
#     "The remote server returned an error: (400) Bad Request."
#     and Meraki's reason is in the response body, which v3.2 and
#     earlier never read. New Get-MerakiErrorText returns the
#     message, the HTTP status code and the response body, and
#     every error log line uses it. This was added to find out
#     why a few dozen IPs got HTTP 400 on the old script.
#   - Failed IPs are listed in a table at the end of the run
#     (Target and Reason), so the causes can be read in one place.
#   - Verified by: static checks only (encoding, balanced
#     braces, ASCII). Not yet run against a Meraki org. Run
#     -Preview first (#48).
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
$ScriptVersion = "3.5"
$MaxRetries    = 5                      # retries per API call on 429 / 5xx / dropped connection
$SuspectPageSize = 5000                 # the 2026-08-31 log showed the object list stopping at exactly this many
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
        [string]$Body = "",
        [switch]$Raw
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = "Stop"
    }
    if ($Body -ne "") { $params["Body"] = $Body }
    if ($Raw) { $params["UseBasicParsing"] = $true }

    $attempt = 0
    while ($true) {
        try {
            if ($Raw) { return Invoke-WebRequest @params }
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


# Gets every item of a list endpoint by following the rel=next link in
# Meraki's Link header. Returns a List of the parsed items.
function Get-MerakiPagedList {
    param([string]$Uri)
    $items    = New-Object System.Collections.Generic.List[object]
    $nextUri  = $Uri
    $pages    = 0
    $maxPages = 500   # safety stop

    while ($nextUri -ne "" -and $pages -lt $maxPages) {
        $resp = Invoke-MerakiRequest -Uri $nextUri -Raw
        $pages++

        $raw    = $resp.Content
        $parsed = $raw | ConvertFrom-Json
        foreach ($entry in @($parsed)) {
            if ($null -ne $entry) { $items.Add($entry) }
        }

        $nextUri    = ""
        $linkHeader = $resp.Headers["Link"]
        if ($linkHeader) {
            $linkText = @($linkHeader) -join ","
            if ($linkText -match '<([^>]+)>\s*;\s*rel="?next"?') { $nextUri = $Matches[1] }
        }
        # The API key goes with every request, so never follow a link to another host
        if ($nextUri -ne "" -and -not $nextUri.StartsWith("https://api.meraki.com/")) {
            Write-Log "Next-page link points outside api.meraki.com, so it was not followed: $nextUri" -Level "WARN"
            $nextUri = ""
        }
    }

    if ($nextUri -ne "") {
        Write-Log "Stopped after $maxPages pages. The list is incomplete." -Level "WARN"
    }
    Write-Log "  Fetched $($items.Count) item(s) in $pages page(s)"
    if ($pages -eq 1 -and $items.Count -ge $SuspectPageSize) {
        Write-Log "  One page returned $($items.Count) items and no next-page link. The list may be cut short." -Level "WARN"
    }
    return $items
}


# Returns the exception message plus the HTTP status code and Meraki's
# response body, which holds the real reason for a 400. PowerShell 5.1
# puts the body in ErrorDetails.Message only sometimes, so the response
# stream is read as a fallback.
function Get-MerakiErrorText {
    param($ErrorRecord)
    $text   = $ErrorRecord.Exception.Message
    $status = ""
    $detail = ""

    $response = $ErrorRecord.Exception.Response
    if ($response) {
        try { $status = [string][int]$response.StatusCode } catch { $status = "" }
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $detail = $ErrorRecord.ErrorDetails.Message
    }
    if ($detail -eq "" -and $response) {
        try {
            $stream = $response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $detail = $reader.ReadToEnd()
            $reader.Close()
        } catch { $detail = "" }
    }

    if ($status -ne "") { $text = "$text [HTTP $status]" }
    if ($detail -ne "") {
        $detail = ($detail -replace '\s+', ' ').Trim()
        $text   = "$text | Meraki says: $detail"
    }
    return $text
}


# Returns a text key for the value an object holds, so two objects with the
# same value get the same key. Meraki refuses a group that holds two of them.
function Get-ObjectValueKey {
    param($PolicyObject)
    if ($PolicyObject.cidr) { return ("cidr:" + ([string]$PolicyObject.cidr).Trim().ToLower()) }
    if ($PolicyObject.fqdn) { return ("fqdn:" + ([string]$PolicyObject.fqdn).Trim().ToLower()) }
    if ($PolicyObject.ip)   { return ("ip:" + ([string]$PolicyObject.ip).Trim() + "/" + [string]$PolicyObject.mask) }
    return ""
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
            Write-Log "Error fetching groups: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "ERROR"
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
            $objects = @(Get-MerakiPagedList -Uri "$baseUrl/policyObjects")
        } catch {
            Write-Log "Error fetching objects: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "ERROR"
            throw
        }
        if ($objects.Count -eq 0) {
            Write-Log "No policy objects found." -Level "WARN"
        } else {
            $objectRows = foreach ($o in $objects) {
                [pscustomobject]@{ Id = $o.id; Name = $o.name; Type = $o.type; Cidr = $o.cidr }
            }
            Write-LogTable -Rows $objectRows -Properties "Id", "Name", "Type", "Cidr"
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
    $existingObjects = @(Get-MerakiPagedList -Uri "$baseUrl/policyObjects")
} catch {
    Write-Log "Could not fetch existing policy objects: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "ERROR"
    throw
}
$existingLookup = @{}
$objectInfo     = @{}   # object ID -> Name and value key, used to find duplicate values
foreach ($obj in $existingObjects) {
    $existingLookup[$obj.name] = $obj.id
    $objectInfo[[string]$obj.id] = [pscustomobject]@{ Name = $obj.name; Key = (Get-ObjectValueKey -PolicyObject $obj) }
}
Write-Log "Found $($existingObjects.Count) existing policy object(s)."


# -- Create or reuse a Policy Object for each IP
$targetObjectIds = New-Object System.Collections.Generic.List[object]
$createdCount    = 0
$reusedCount     = 0
$failCount       = 0
$failures        = New-Object System.Collections.Generic.List[object]

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
        $objectInfo[[string]$created.id] = [pscustomobject]@{ Name = $objectName; Key = (Get-ObjectValueKey -PolicyObject $created) }
        Write-Log "  [CREATED] $cidr  ->  ID: $($created.id)" -Level "SUCCESS"
        $createdCount++
    } catch {
        $errText = Get-MerakiErrorText -ErrorRecord $_
        Write-Log "  [FAIL]    $cidr  ->  $errText" -Level "ERROR"
        $failures.Add([pscustomobject]@{ Target = $cidr; Reason = $errText })
        $failCount++
    }
}


# -- Add the objects to the Policy Object Group
if ($targetObjectIds.Count -gt 0 -or $Preview) {

    Write-Log "Reading Policy Object Group $GroupId..."

    try {
        $group = Invoke-MerakiRequest -Uri "$baseUrl/policyObjects/groups/$GroupId"

        $existingIds = @($group.objectIds | Where-Object { $_ })

        # Current members first, so a duplicate value never removes one of them.
        # Meraki refuses a group that holds two objects with the same value.
        $candidateIds = @(@($existingIds) + $targetObjectIds.ToArray() | Select-Object -Unique)
        $mergedIds    = New-Object System.Collections.Generic.List[object]
        $duplicates   = New-Object System.Collections.Generic.List[object]
        $seenValues   = @{}
        foreach ($candidateId in $candidateIds) {
            $info = $objectInfo[[string]$candidateId]
            if ($null -eq $info -or $info.Key -eq "") {
                $mergedIds.Add($candidateId)
                continue
            }
            if ($seenValues.ContainsKey($info.Key)) {
                $keptId = $seenValues[$info.Key]
                $duplicates.Add([pscustomobject]@{
                    SkippedId   = $candidateId
                    SkippedName = $info.Name
                    Value       = $info.Key
                    KeptId      = $keptId
                    KeptName    = $objectInfo[[string]$keptId].Name
                })
                continue
            }
            $seenValues[$info.Key] = $candidateId
            $mergedIds.Add($candidateId)
        }

        Write-Log "  IDs already in group  : $($existingIds.Count)"
        Write-Log "  IDs being added       : $($targetObjectIds.Count)"
        Write-Log "  Left out (same value as another object): $($duplicates.Count)"
        Write-Log "  Total after merge     : $($mergedIds.Count)"
        if ($duplicates.Count -gt 0) {
            Write-Log "  Objects left out of the group update because another object has the same value:" -Level "WARN"
            Write-LogTable -Rows $duplicates -Properties "SkippedId", "SkippedName", "Value", "KeptId", "KeptName" -Level "WARN"
        }

        if ($Preview) {
            Write-Log "  Objects marked WOULD CREATE are not counted above, because they have no ID until they are created." -Level "WARN"
        } else {
            $groupBody = [ordered]@{
                name      = $group.name
                objectIds = $mergedIds.ToArray()
            } | ConvertTo-Json -Depth 10

            Write-Log "Updating Policy Object Group $GroupId..."
            $result = Invoke-MerakiRequest -Uri "$baseUrl/policyObjects/groups/$GroupId" -Method "PUT" -Body $groupBody
            Write-Log "  [OK] Group updated. API confirms objects in group: $(@($result.objectIds).Count)" -Level "SUCCESS"
        }

    } catch {
        $errText = Get-MerakiErrorText -ErrorRecord $_
        Write-Log "  [FAIL] Could not read or update the group: $errText" -Level "ERROR"
        if ($errText -like "*duplicate*") {
            Write-Log "  Meraki still sees duplicate values that this script did not detect, for example the same network written two ways. Run -ListObjects and look for repeated Cidr values." -Level "WARN"
        }
        $failures.Add([pscustomobject]@{ Target = "group $GroupId"; Reason = $errText })
        $failCount++
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
if ($failures.Count -gt 0) {
    Write-Log "Failures:" -Level "ERROR"
    Write-LogTable -Rows $failures -Properties "Target", "Reason" -Level "ERROR"
}
Write-Log "$scriptName finished"

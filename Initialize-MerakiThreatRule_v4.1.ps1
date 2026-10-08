# ============================================================
# Initialize-MerakiThreatRule_v4.1.ps1
# Version 4.1
#
# Puts the threat deny rule on every MX network in the org (and
# on every MX configuration template) and keeps it up to date.
# The rule's destination lists ALL the threat groups, that is the
# group set in CONFIGURATION plus "<name> 002", "<name> 003" and
# so on, which Add-MerakiThreatIPs_v4.0.ps1 creates when a group
# reaches Meraki's limit of 150 objects.
#
# Run it:
#   - once, to protect every network,
#   - again whenever Add-MerakiThreatIPs creates new groups
#     (it tells you), and
#   - whenever a new network is added.
# A network that already has the correct rule is left alone.
#
# WHAT THIS SCRIPT CHANGES:
#   Meraki:          Nothing with -Preview or -AuditOnly.
#                    Otherwise, on each network whose threat rule
#                    is missing or out of date, it PUTs that
#                    network's layer 3 firewall rules: the threat
#                    deny rule(s) first, then every other rule the
#                    network already has, unchanged. It never
#                    edits other rules and never changes groups
#                    or policy objects.
#   Your PS session: Nothing.
#   Your computer:   Creates the log folder if it does not
#                    exist, and writes one log file.
#
# PREREQUISITES:
#   - Windows PowerShell 5.1 or PowerShell 7
#   - A Meraki Dashboard API key with write access to the org
#   - Fill in the three your_xxx_here values in CONFIGURATION.
#     $GroupId is the FIRST threat group. Run
#     Add-MerakiThreatIPs_v4.0.ps1 -ListGroups to find it.
#
# PARAMETERS:
#   -NetworkId         One or more network or template IDs to
#                      handle. Default: every MX network and MX
#                      template in the org.
#   -ExcludeNetworkId  One or more IDs to leave out, in addition to
#                      $ExcludedNetworkIds in CONFIGURATION. Default:
#                      none.
#   -Preview           Switch. Reports what would change on each
#                      network and changes nothing.
#   -AuditOnly         Switch. Reports which networks have the
#                      correct rule and changes nothing.
#
# HOW NETWORKS ARE FOUND:
#   The script lists the org's networks with the API. It handles
#   networks that have the "appliance" product type. A network
#   bound to a configuration template is skipped, because the
#   template supplies its rules. The MX templates themselves
#   are handled instead. There is no network list file.
#
# HOW THE RULE LOOKS:
#   One deny rule, any protocol, any source, any port, destination
#   GRP(id),GRP(id),... for each threat group, with syslog on.
#   $GroupsPerRule limits how many groups go in one rule. With
#   more groups than that, the script writes several rules.
#   Rules it manages have a comment starting with the text of
#   $RuleComment. The older single rule from v3.x has that
#   comment and is replaced.
#
# OUTPUT:
#   $LogDir\yyyy.MM.dd.HHmmss.Initialize-MerakiThreatRule_v4.1.log
#   (no other files)
#
# EXAMPLES:
#   .\Initialize-MerakiThreatRule_v4.1.ps1 -AuditOnly
#       Shows which networks have the correct rule. Changes nothing.
#
#   .\Initialize-MerakiThreatRule_v4.1.ps1 -Preview
#       Shows what would change on each network. Changes nothing.
#
#   .\Initialize-MerakiThreatRule_v4.1.ps1 -NetworkId "N_1234567890"
#       Applies the rule to ONE network. Do this first.
#
#   .\Initialize-MerakiThreatRule_v4.1.ps1
#       Applies the rule to every network that needs it.
#
# v4.1 changes:
#   - Added a permanent exclusion list, $ExcludedNetworkIds in
#     CONFIGURATION, for networks and templates this script must
#     never change. Before, the only way to skip a network was to
#     type -ExcludeNetworkId on every run, so one forgotten
#     parameter would have updated a network that should be left
#     alone. Excluded networks are still listed in the results
#     table with the status "Excluded" and are never read or
#     written. -ExcludeNetworkId still works and is added to the
#     list.
#   - Verified by: parse check on PowerShell 7.4 and a run
#     against a mock of the Meraki API that checked an excluded
#     network is reported and never changed. Not yet run against
#     a real Meraki org (#48).
#
# v4.0 changes:
#   - The rule now covers a SET of groups. Meraki allows only 150
#     objects per group (HTTP 400 "There can only be 150 network
#     objects per group", 2026-10-08), so the blocklist is split
#     over many groups and one group in the rule is no longer
#     enough. The script finds all the threat groups by name
#     (the first group plus "<name> 002", "<name> 003" ...) and
#     lists them all in the rule. A network whose rule lacks a
#     group is brought up to date; one that already has them all
#     is skipped.
#   - Networks are found through the API, including MX
#     configuration templates, instead of a text file. Networks
#     bound to a template are skipped. Use -NetworkId and
#     -ExcludeNetworkId to narrow the list.
#   - Brought up to STANDARDS.md. This also fixes the old calls
#     that passed -Headers to Invoke-MerakiRequest, which has no
#     such parameter. PowerShell ignored it without any message.
#   - The wrapper retries dropped connections (no HTTP status)
#     as well as 429 and 5xx. Failed calls log Meraki's own error
#     text.
#   - Protection against wiping a network's rules: a network
#     whose rule list cannot be read is reported as failed and
#     its rules are not touched.
#   - Not confirmed against a real org: whether Meraki accepts
#     the full group list in one rule's destination (the
#     dashboard did accept more than one group), whether the
#     firewall rules endpoint works on configuration templates,
#     and any limit on rules or destination length. Test with
#     -NetworkId on ONE network first. If Meraki rejects the
#     rule, lower $GroupsPerRule.
#   - Verified by: parse check on PowerShell 7.4 and a run
#     against a mock of the Meraki API. Not yet run against a
#     real Meraki org (#48).
#
# v3.1 changes:
#   - Added Invoke-MerakiRequest wrapper; all API calls
#     now retry on HTTP 429 / transient 5xx.
#   - Renamed -WhatIf to -Preview. -WhatIf is a reserved
#     PowerShell common parameter that silently conflicts
#     if [CmdletBinding(SupportsShouldProcess)] is ever added.
#
# v3.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string[]]$NetworkId = @(),
    [string[]]$ExcludeNetworkId = @(),
    [switch]$Preview,
    [switch]$AuditOnly
)

# ============================================================
# CONFIGURATION -- placeholders only for secrets (#18)
# ============================================================
$ApiKey          = "your_api_key_here"
$OrgId           = "your_org_id_here"
$GroupId         = "your_group_id_here"   # the FIRST threat group, same as in Add-MerakiThreatIPs
$LogDir          = "C:\Logs\Meraki"       # kept from v3.0 so old and new logs stay together
$ScriptVersion   = "4.1"
$MaxRetries      = 5                      # retries per API call on 429 / 5xx / dropped connection
$RuleComment     = "Threat Block List - SOC"   # kept from v3.x; rules starting with this text are managed by this script
$ExcludedNetworkIds = @(
    # Networks or templates this script must NEVER change. One ID per line,
    # in quotes, with a comma at the end of every line but the last. Find the
    # IDs in the Id column of the -AuditOnly table. Example:
    # "N_123456789012345678",   # Lab network, owner asked us to leave it
)
$GroupsPerRule   = 25                     # groups listed in one rule. Lower it if Meraki rejects a long destination
$SuspectPageSize = 5000                   # a single page this large may mean a list is cut short
$BaseUrlRoot     = "https://api.meraki.com/api/v1"
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
$orgUrl = "$BaseUrlRoot/organizations/$OrgId"


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
        if ($nextUri -ne "" -and -not $nextUri.StartsWith($BaseUrlRoot)) {
            Write-Log "Next-page link points outside $BaseUrlRoot, so it was not followed: $nextUri" -Level "WARN"
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


# The GRP(...) entries in a rule's destination text, sorted and without repeats
function Get-GroupTokens {
    param([string]$Destination)
    $tokens = New-Object System.Collections.Generic.List[string]
    foreach ($piece in ($Destination -split ',')) {
        $trimmed = $piece.Trim()
        if ($trimmed -match '^GRP\(.+\)$') { $tokens.Add($trimmed) }
    }
    return @($tokens | Sort-Object -Unique)
}


if ($Preview -and $AuditOnly) { throw "Use either -Preview or -AuditOnly, not both." }

Write-Log "$scriptName started (version $ScriptVersion)"
$modeText = "APPLY - changes will be made"
if ($Preview)   { $modeText = "PREVIEW - no changes will be made" }
if ($AuditOnly) { $modeText = "AUDIT ONLY - no changes will be made" }
Write-Log "Mode: $modeText"
Write-Log "Log file: $logFile"

# Stop early if a secret is still a placeholder
$placeholders = @()
if ($ApiKey -like "your_*_here")  { $placeholders += "`$ApiKey" }
if ($OrgId -like "your_*_here")   { $placeholders += "`$OrgId" }
if ($GroupId -like "your_*_here") { $placeholders += "`$GroupId" }
if ($placeholders.Count -gt 0) {
    $placeholderText = $placeholders -join ", "
    Write-Log "CONFIGURATION still has placeholder value(s): $placeholderText" -Level "ERROR"
    throw "Fill in CONFIGURATION before running: $placeholderText"
}


# -- Find the threat groups: the first group plus "<name> 002", "<name> 003" ...
Write-Log "Reading the threat groups..."
try {
    $allGroups = @(Get-MerakiPagedList -Uri "$orgUrl/policyObjects/groups")
} catch {
    Write-Log "Could not read the policy object groups: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "ERROR"
    throw
}
$baseGroup = $allGroups | Where-Object { [string]$_.id -eq [string]$GroupId } | Select-Object -First 1
if (-not $baseGroup) {
    Write-Log "Group $GroupId was not found. Run Add-MerakiThreatIPs_v4.0.ps1 -ListGroups to find the right ID." -Level "ERROR"
    throw "Group $GroupId was not found."
}
$baseName     = [string]$baseGroup.name
$numberedName = '^' + [regex]::Escape($baseName) + ' (\d{3})$'
$threatGroups = New-Object System.Collections.Generic.List[object]
foreach ($g in $allGroups) {
    $groupNumber = 0
    if ([string]$g.id -eq [string]$GroupId) { $groupNumber = 1 }
    elseif ([string]$g.name -match $numberedName) { $groupNumber = [int]$Matches[1] }
    if ($groupNumber -gt 0) {
        $threatGroups.Add([pscustomobject]@{ Number = $groupNumber; Id = [string]$g.id; Name = [string]$g.name; Members = @($g.objectIds).Count })
    }
}
$sortedGroups = @($threatGroups | Sort-Object Number)
Write-LogTable -Rows $sortedGroups -Properties "Number", "Name", "Id", "Members"

$groupTokens = @($sortedGroups | ForEach-Object { "GRP($($_.Id))" })
$ruleCount   = [int][math]::Ceiling($groupTokens.Count / $GroupsPerRule)

# The rule(s) every network should have
$desiredRules = New-Object System.Collections.Generic.List[object]
for ($ruleIndex = 0; $ruleIndex -lt $ruleCount; $ruleIndex++) {
    $chunk = @($groupTokens | Select-Object -Skip ($ruleIndex * $GroupsPerRule) -First $GroupsPerRule)
    $comment = $RuleComment
    if ($ruleCount -gt 1) { $comment = "{0} ({1} of {2})" -f $RuleComment, ($ruleIndex + 1), $ruleCount }
    $desiredRules.Add([ordered]@{
        comment       = $comment
        policy        = "deny"
        protocol      = "any"
        srcPort       = "Any"
        srcCidr       = "Any"
        destPort      = "Any"
        destCidr      = ($chunk -join ",")
        syslogEnabled = $true
    })
}
$desiredTokens = @($groupTokens | Sort-Object -Unique)
Write-Log "The deny rule will list $($groupTokens.Count) group(s) in $ruleCount rule(s)."


# -- Find the networks and templates to handle
Write-Log "Reading the org's networks..."
try {
    $orgNetworks = @(Get-MerakiPagedList -Uri "$orgUrl/networks")
} catch {
    Write-Log "Could not read the networks: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "ERROR"
    throw
}

$targets    = New-Object System.Collections.Generic.List[object]
$boundCount = 0
foreach ($net in $orgNetworks) {
    if (@($net.productTypes) -notcontains "appliance") { continue }
    if ($net.configTemplateId) { $boundCount++; continue }
    $targets.Add([pscustomobject]@{ Id = [string]$net.id; Name = [string]$net.name; Kind = "network" })
}
Write-Log "  $($targets.Count) MX network(s) found. $boundCount bound to a template (skipped, the template supplies their rules)."

Write-Log "Reading the org's configuration templates..."
try {
    $templates = @(Get-MerakiPagedList -Uri "$orgUrl/configTemplates")
    foreach ($template in $templates) {
        if (@($template.productTypes) -contains "appliance") {
            $targets.Add([pscustomobject]@{ Id = [string]$template.id; Name = [string]$template.name; Kind = "template" })
        }
    }
} catch {
    Write-Log "Could not read the configuration templates, so none are handled: $(Get-MerakiErrorText -ErrorRecord $_)" -Level "WARN"
}

if (@($NetworkId).Count -gt 0) {
    foreach ($wanted in $NetworkId) {
        if (-not ($targets | Where-Object { $_.Id -eq $wanted })) {
            Write-Log "-NetworkId $wanted is not an MX network or template in this org." -Level "WARN"
        }
    }
    $kept = @($targets | Where-Object { $NetworkId -contains $_.Id })
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($keptTarget in $kept) { $targets.Add($keptTarget) }
}

# Networks that must never be changed: the CONFIGURATION list plus -ExcludeNetworkId
$excludeIds      = @(@($ExcludedNetworkIds) + @($ExcludeNetworkId) | Where-Object { $_ -and ([string]$_).Trim() -ne "" } | ForEach-Object { ([string]$_).Trim() })
$excludedTargets = @($targets | Where-Object { $excludeIds -contains $_.Id })
if ($excludedTargets.Count -gt 0) {
    $kept = @($targets | Where-Object { $excludeIds -notcontains $_.Id })
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($keptTarget in $kept) { $targets.Add($keptTarget) }
    Write-Log "Excluded $($excludedTargets.Count) network(s), left untouched: $((($excludedTargets | ForEach-Object { $_.Name }) -join ', '))" -Level "WARN"
}
foreach ($excludedId in $excludeIds) {
    if (-not ($excludedTargets | Where-Object { $_.Id -eq $excludedId })) {
        Write-Log "Excluded ID $excludedId is not an MX network or template in this org (nothing to exclude)." -Level "WARN"
    }
}
if ($targets.Count -eq 0) {
    Write-Log "No networks to handle." -Level "ERROR"
    throw "No networks to handle."
}
Write-Log "Handling $($targets.Count) network(s)/template(s)."


# -- Check and update each network
$alreadyProtected = 0
$ruleUpdated      = 0
$needsUpdate      = 0
$failCount        = 0
$results          = New-Object System.Collections.Generic.List[object]
foreach ($excludedTarget in $excludedTargets) {
    $results.Add([pscustomobject]@{ Name = $excludedTarget.Name; Id = $excludedTarget.Id; Kind = $excludedTarget.Kind; Status = "Excluded"; Detail = "on the exclusion list, not read or changed" })
}
$l3Path           = "appliance/firewall/l3FirewallRules"

foreach ($target in $targets) {

    $rulesUri = "$BaseUrlRoot/networks/$($target.Id)/$l3Path"
    Write-Log "$($target.Kind): $($target.Name) ($($target.Id))"

    try {
        $current = Invoke-MerakiRequest -Uri $rulesUri
        if ($null -eq $current -or $null -eq $current.rules) {
            throw "Meraki returned no rule list. Nothing was changed."
        }
        $existingRules = @($current.rules)

        $managedRules = @($existingRules | Where-Object { ([string]$_.comment).StartsWith($RuleComment, [StringComparison]::OrdinalIgnoreCase) })
        $otherRules   = @($existingRules | Where-Object {
            -not ([string]$_.comment).StartsWith($RuleComment, [StringComparison]::OrdinalIgnoreCase) -and [string]$_.comment -ne "Default rule"
        })

        $existingTokens = New-Object System.Collections.Generic.List[string]
        $allDeny        = $true
        foreach ($managedRule in $managedRules) {
            if ([string]$managedRule.policy -ne "deny") { $allDeny = $false }
            foreach ($token in (Get-GroupTokens -Destination ([string]$managedRule.destCidr))) { $existingTokens.Add($token) }
        }
        $existingTokenSet = @($existingTokens | Sort-Object -Unique)
        $sameTokens = (($existingTokenSet -join ";") -eq ($desiredTokens -join ";"))

        if ($managedRules.Count -eq $desiredRules.Count -and $sameTokens -and $allDeny) {
            Write-Log "  [SKIP] Rule is correct ($($desiredTokens.Count) group(s))."
            $alreadyProtected++
            $results.Add([pscustomobject]@{ Name = $target.Name; Id = $target.Id; Kind = $target.Kind; Status = "Correct"; Detail = "" })
            continue
        }

        $missingCount = @($desiredTokens | Where-Object { $existingTokenSet -notcontains $_ }).Count
        if ($managedRules.Count -eq 0) {
            $why = "no threat rule"
        } elseif ($missingCount -gt 0) {
            $why = "rule lists $($existingTokenSet.Count) of $($desiredTokens.Count) group(s), $missingCount missing"
        } else {
            $why = "rule layout differs ($($managedRules.Count) threat rule(s), want $($desiredRules.Count))"
        }
        $needsUpdate++

        if ($AuditOnly -or $Preview) {
            $statusText = "Needs update"
            if ($Preview) { $statusText = "Would update" }
            Write-Log "  [$($statusText.ToUpper())] $why" -Level "WARN"
            $results.Add([pscustomobject]@{ Name = $target.Name; Id = $target.Id; Kind = $target.Kind; Status = $statusText; Detail = $why })
            continue
        }

        $updatedRules = New-Object System.Collections.Generic.List[object]
        foreach ($desiredRule in $desiredRules) { $updatedRules.Add($desiredRule) }
        foreach ($otherRule in $otherRules) { $updatedRules.Add($otherRule) }
        $body = @{ rules = $updatedRules.ToArray() } | ConvertTo-Json -Depth 6

        $putResult = Invoke-MerakiRequest -Uri $rulesUri -Method "PUT" -Body $body
        $ruleTotal = @($putResult.rules).Count
        Write-Log "  [OK] Threat rule set ($why). The network now has $ruleTotal rule(s) including the default." -Level "SUCCESS"
        $ruleUpdated++
        $results.Add([pscustomobject]@{ Name = $target.Name; Id = $target.Id; Kind = $target.Kind; Status = "Updated"; Detail = $why })

    } catch {
        $errText = Get-MerakiErrorText -ErrorRecord $_
        Write-Log "  [FAIL] $errText" -Level "ERROR"
        $failCount++
        $results.Add([pscustomobject]@{ Name = $target.Name; Id = $target.Id; Kind = $target.Kind; Status = "FAILED"; Detail = $errText })
    }
}


# -- Summary
Write-Log "------------------------------"
Write-LogTable -Rows $results -Properties "Name", "Id", "Kind", "Status", "Detail"
Write-Log "------------------------------"
if ($AuditOnly -or $Preview) {
    Write-Log "No changes were made." -Level "WARN"
    Write-Log "  Correct now   : $alreadyProtected"
    Write-Log "  Need an update: $needsUpdate"
} else {
    Write-Log "  Already correct : $alreadyProtected"
    Write-Log "  Updated         : $ruleUpdated" -Level "SUCCESS"
}
$failLevel = "INFO"
if ($failCount -gt 0) { $failLevel = "ERROR" }
Write-Log "  Excluded        : $($excludedTargets.Count)"
Write-Log "  Failed          : $failCount" -Level $failLevel
Write-Log "------------------------------"
Write-Log "$scriptName finished"

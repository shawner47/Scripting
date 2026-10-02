# ============================================================
# Export-NSG-Rules_v1.0.ps1
# Version 1.0
#
# Read-only export and comparison of the CUSTOM rules in the
# Network Security Groups (NSGs) of the selected Azure
# subscriptions. Its purpose is to show which NSGs have the
# same rules, which rules are shared between NSGs, and which
# rules are unique, so NSGs can be consolidated deliberately.
#
# WHAT THIS SCRIPT COLLECTS:
#   1. Every custom rule of every matching NSG, one row per
#      rule (name, priority, direction, access, protocol,
#      source/destination address, ASG, and port, description).
#   2. One row per NSG, with a rule-set ID:
#        Strict ID -- NSGs with the same ID have identical
#                     rules, comparing everything except the
#                     rule name and description.
#        Loose ID  -- as Strict, but also ignoring priority.
#   3. One row per distinct rule (ignoring name and priority),
#      with how many NSGs contain it and which ones.
#   Default rules that Azure adds to every NSG are NOT exported.
#
# WHAT THIS SCRIPT CHANGES:
#   Azure:           Nothing. Only Get-* cmdlets read from Azure.
#   Your PS session: While scanning, it switches the active
#                    subscription (Set-AzContext -Scope Process,
#                    contained to this session). When it
#                    finishes -- or if it fails partway --
#                    it restores the context you started with.
#   Your computer:   Creates the output and log folders if they
#                    do not exist. Writes three CSV files and
#                    one log file.
#
# HANDLE THE OUTPUT AS SENSITIVE:
#   The CSV files contain your rule contents: IP ranges, ports
#   and rule descriptions. Store and share them accordingly.
#
# WHAT THE RESULTS DO NOT SHOW:
#   - Which resources are protected by each NSG. Use
#     Inventory-NSG-Associations for attachments (the NSG file
#     here lists attached subnets and NICs for reference).
#   - Two rules that match on every compared field but have
#     different priorities can behave differently when other
#     rules overlap them. Compare Strict IDs when priority
#     matters and Loose IDs when it does not.
#   - Rules are compared as text. The script does not work out
#     whether one rule's address range contains another's.
#
# PREREQUISITES:
#   - Az.Accounts and Az.Network PowerShell modules installed
#   - Active Azure session: run Connect-AzAccount first
#   - Reader (or higher) on each subscription to be scanned
#
# PARAMETERS:
#   -OutputDirectory   Folder for the CSV files. Created if it
#                      does not exist. Default: C:\Temp
#   -SubscriptionName  One or more subscription names to scan.
#                      Default: Mingledorff Dev Application VPC,
#                      Mingledorff Prod Application VPC, and
#                      Mingledorff's_Prod_Mgmt_VPC. A name that
#                      is not found produces a warning.
#   -NsgNameLike       One or more wildcard patterns. Only NSGs
#                      whose name matches at least one pattern
#                      are exported and compared. Default: *
#                      (every NSG).
#
# OUTPUT:
#   $OutputDirectory\yyyy.MM.dd.HHmmss.nsg-rules.csv
#   $OutputDirectory\yyyy.MM.dd.HHmmss.nsg-ruleset-groups.csv
#   $OutputDirectory\yyyy.MM.dd.HHmmss.nsg-rule-matrix.csv
#   $LogDir\yyyy.MM.dd.HHmmss.Export-NSG-Rules_v1.0.log
#
# EXAMPLES:
#   .\Export-NSG-Rules_v1.0.ps1
#   .\Export-NSG-Rules_v1.0.ps1 -OutputDirectory "D:\Reports"
#   .\Export-NSG-Rules_v1.0.ps1 -SubscriptionName "Mingledorff Dev Application VPC"
#   .\Export-NSG-Rules_v1.0.ps1 -NsgNameLike "MGL-*-nsg"
#   .\Export-NSG-Rules_v1.0.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -NsgNameLike "MGL-STG-*", "MGL-DEV-*"
#
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string]$OutputDirectory = "C:\Temp",
    [string[]]$SubscriptionName = @(
        "Mingledorff Dev Application VPC",
        "Mingledorff Prod Application VPC",
        "Mingledorff's_Prod_Mgmt_VPC"
    ),
    [string[]]$NsgNameLike = @("*")
)

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs\Azure"
$ScriptVersion = "1.0"
# ============================================================


# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
foreach ($dir in @($LogDir, $OutputDirectory)) {
    if (-not (Test-Path -Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
$scriptName = $MyInvocation.MyCommand.Name -replace '\.ps1$', ''
$logFile    = Join-Path $LogDir "$stamp.$scriptName.log"


function Write-Log {
    param([string]$Message = "", [string]$Level = "INFO", [ConsoleColor]$Color = "White")
    $logTs = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line  = "[$logTs] [$Level] $Message"
    $col   = switch ($Level) {
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        "SUCCESS" { "Green" }
        default   { "White" }
    }
    Write-Host $line -ForegroundColor $(if ($Color -ne "White") { $Color } else { $col })
    Add-Content -Path $logFile -Value $line
}

function Write-LogTable {
    # Formats rows as a text table and writes every line through Write-Log,
    # so the table appears in the log file as well as on the console.
    param($Rows, [string[]]$Properties, [string]$Level = "INFO")
    $text = $Rows | Format-Table -Property $Properties -AutoSize | Out-String -Width 250
    foreach ($tableLine in ($text -split '\r?\n')) {
        if ($tableLine.Trim().Length -gt 0) { Write-Log $tableLine -Level $Level }
    }
}

function Get-LastSegment {
    param([string]$ResourceId)
    if ($ResourceId) { ($ResourceId -split '/')[-1] } else { '' }
}

function Join-Sorted {
    # Turns a value or list of values into one sorted, comma-joined string.
    # Empty and null entries are dropped, so the same rule always gives the same text.
    param($Values)
    $clean = @($Values) | Where-Object { $null -ne $_ -and "$_".Length -gt 0 } | ForEach-Object { "$_" } | Sort-Object
    return ($clean -join ",")
}

function Get-AsgNames {
    # Returns the names of application security groups (taken from their resource IDs), sorted and comma-joined.
    param($AsgList)
    $names = @($AsgList) | Where-Object { $_ -and $_.Id } | ForEach-Object { Get-LastSegment $_.Id }
    return (Join-Sorted $names)
}


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log "Output directory: $OutputDirectory"
Write-Log "Log file: $logFile"
Write-Log ("NSG name patterns: {0}" -f ($NsgNameLike -join ", "))


# -- Verify Azure session exists before doing anything
$originalContext = Get-AzContext
if (-not $originalContext) {
    Write-Log "No Azure session found. Run Connect-AzAccount first, then run this script again." -Level ERROR
    throw "No Azure session found. Run Connect-AzAccount first."
}
Write-Log "Starting in subscription: $($originalContext.Subscription.Name)"


$ruleRows   = New-Object System.Collections.Generic.List[object]
$nsgSummary = New-Object System.Collections.Generic.List[object]
$tallyRows  = New-Object System.Collections.Generic.List[object]
$ruleIndex  = @{}


try {
    # -- Select the subscriptions to scan
    $allSubs    = @(Get-AzSubscription | Where-Object { $_.State -eq "Enabled" })
    $subs       = @($allSubs | Where-Object { $SubscriptionName -contains $_.Name } | Sort-Object Id -Unique)
    $foundNames = @($subs | ForEach-Object { $_.Name })
    foreach ($wanted in $SubscriptionName) {
        if ($foundNames -notcontains $wanted) {
            Write-Log "Requested subscription not found among enabled subscriptions: $wanted" -Level WARN
        }
    }
    if ($subs.Count -eq 0) {
        Write-Log "None of the requested subscriptions were found. Nothing to scan." -Level ERROR
        throw "None of the requested subscriptions were found among the enabled subscriptions."
    }
    Write-Log "$($subs.Count) subscription(s) selected for scanning."

    foreach ($sub in $subs) {
        Write-Log "Scanning: $($sub.Name)"

        # -Scope Process keeps the switch inside this session only.
        # The tenant token warning it emits has been harmless; it is hidden here.
        # The check below confirms the switch really happened before anything is read.
        $null = Set-AzContext -SubscriptionId $sub.Id -Scope Process -WarningAction SilentlyContinue
        if ((Get-AzContext).Subscription.Id -ne $sub.Id) {
            Write-Log "Could not switch to subscription '$($sub.Name)'. Skipping." -Level WARN
            continue
        }

        # Only NSGs whose name matches at least one -NsgNameLike pattern are used.
        $nsgs = @(Get-AzNetworkSecurityGroup | Where-Object {
            $nsgName = $_.Name
            @($NsgNameLike | Where-Object { $nsgName -like $_ }).Count -gt 0
        })

        $subRuleCount = 0
        foreach ($nsg in $nsgs) {
            $attachedSubnets = @($nsg.Subnets) | Where-Object { $_ -and $_.Id } | ForEach-Object {
                '{0}/{1}' -f (($_.Id -split '/')[-3]), (($_.Id -split '/')[-1])
            }
            $attachedNics = @($nsg.NetworkInterfaces) | Where-Object { $_ -and $_.Id } | ForEach-Object {
                ($_.Id -split '/')[-1]
            }
            $nsgKey     = '{0}/{1}' -f $sub.Name, $nsg.Name
            $strictList = New-Object System.Collections.Generic.List[string]
            $looseList  = New-Object System.Collections.Generic.List[string]

            foreach ($rule in @($nsg.SecurityRules)) {
                if (-not $rule) { continue }

                $srcAddr  = Join-Sorted $rule.SourceAddressPrefix
                $srcAsg   = Get-AsgNames $rule.SourceApplicationSecurityGroups
                $srcPort  = Join-Sorted $rule.SourcePortRange
                $dstAddr  = Join-Sorted $rule.DestinationAddressPrefix
                $dstAsg   = Get-AsgNames $rule.DestinationApplicationSecurityGroups
                $dstPort  = Join-Sorted $rule.DestinationPortRange
                $prioText = [string]$rule.Priority

                # Fingerprints: every compared field, joined. Rule name and description are left out on purpose.
                $loose  = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $rule.Direction, $rule.Access, $rule.Protocol, $srcAddr, $srcAsg, $srcPort, $dstAddr, $dstAsg, $dstPort
                $strict = '{0}|P{1}' -f $loose, $prioText
                $strictList.Add($strict)
                $looseList.Add($loose)

                $ruleRows.Add([pscustomobject]@{
                    Subscription             = $sub.Name
                    NSG                      = $nsg.Name
                    ResourceGroup            = $nsg.ResourceGroupName
                    RuleName                 = $rule.Name
                    Priority                 = $rule.Priority
                    Direction                = $rule.Direction
                    Access                   = $rule.Access
                    Protocol                 = $rule.Protocol
                    SourceAddressPrefix      = $srcAddr
                    SourceAsg                = $srcAsg
                    SourcePortRange          = $srcPort
                    DestinationAddressPrefix = $dstAddr
                    DestinationAsg           = $dstAsg
                    DestinationPortRange     = $dstPort
                    Description              = $rule.Description
                })
                $subRuleCount = $subRuleCount + 1

                # Rule index: one entry per distinct rule (ignoring name and priority)
                if (-not $ruleIndex.ContainsKey($loose)) {
                    $ruleIndex[$loose] = [pscustomobject]@{
                        Direction                = $rule.Direction
                        Access                   = $rule.Access
                        Protocol                 = $rule.Protocol
                        SourceAddressPrefix      = $srcAddr
                        SourceAsg                = $srcAsg
                        SourcePortRange          = $srcPort
                        DestinationAddressPrefix = $dstAddr
                        DestinationAsg           = $dstAsg
                        DestinationPortRange     = $dstPort
                        Priorities               = New-Object System.Collections.Generic.List[string]
                        Names                    = New-Object System.Collections.Generic.List[string]
                        NSGs                     = New-Object System.Collections.Generic.List[string]
                    }
                }
                $entry = $ruleIndex[$loose]
                if ($entry.NSGs -notcontains $nsgKey)         { $entry.NSGs.Add($nsgKey) }
                if ($entry.Priorities -notcontains $prioText) { $entry.Priorities.Add($prioText) }
                if ($entry.Names -notcontains $rule.Name)     { $entry.Names.Add($rule.Name) }
            }

            $strictSig = "(no custom rules)"
            $looseSig  = "(no custom rules)"
            if ($strictList.Count -gt 0) {
                $strictSig = (@($strictList | Sort-Object)) -join ";"
                $looseSig  = (@($looseList | Sort-Object)) -join ";"
            }

            $nsgSummary.Add([pscustomobject]@{
                Subscription    = $sub.Name
                NSG             = $nsg.Name
                ResourceGroup   = $nsg.ResourceGroupName
                CustomRuleCount = $strictList.Count
                StrictSig       = $strictSig
                LooseSig        = $looseSig
                AttachedSubnets = ($attachedSubnets -join '; ')
                AttachedNICs    = ($attachedNics -join '; ')
            })
        }

        $tallyRows.Add([pscustomobject]@{
            Subscription = $sub.Name
            NSGs         = $nsgs.Count
            CustomRules  = $subRuleCount
        })
        Write-Log ("  Tally: {0} NSG(s) matched, {1} custom rule(s)" -f $nsgs.Count, $subRuleCount)
    }
} finally {
    # Runs on success and on failure: restore the original subscription context.
    $null = Set-AzContext -Context $originalContext -Scope Process -WarningAction SilentlyContinue
    Write-Log "Session context restored to: $($originalContext.Subscription.Name)" -Level SUCCESS
}


# -- Clean stop if nothing matched (not an error)
if ($nsgSummary.Count -eq 0) {
    Write-Log "No NSGs matched the requested subscriptions and name patterns. No files were written." -Level WARN
    exit 0
}


# -- Assign rule-set IDs (same rules = same ID) and count how many NSGs share each
$strictIds    = @{}
$strictCounts = @{}
$looseIds     = @{}
$looseCounts  = @{}
$strictNext   = 0
$looseNext    = 0
foreach ($row in $nsgSummary) {
    if (-not $strictIds.ContainsKey($row.StrictSig)) {
        $strictNext = $strictNext + 1
        $strictIds[$row.StrictSig]    = 'S{0:D2}' -f $strictNext
        $strictCounts[$row.StrictSig] = 0
    }
    $strictCounts[$row.StrictSig] = $strictCounts[$row.StrictSig] + 1

    if (-not $looseIds.ContainsKey($row.LooseSig)) {
        $looseNext = $looseNext + 1
        $looseIds[$row.LooseSig]    = 'L{0:D2}' -f $looseNext
        $looseCounts[$row.LooseSig] = 0
    }
    $looseCounts[$row.LooseSig] = $looseCounts[$row.LooseSig] + 1
}

$groupRows = @(foreach ($row in $nsgSummary) {
    [pscustomobject]@{
        Subscription          = $row.Subscription
        NSG                   = $row.NSG
        ResourceGroup         = $row.ResourceGroup
        CustomRuleCount       = $row.CustomRuleCount
        StrictRuleSetId       = $strictIds[$row.StrictSig]
        NSGsWithSameStrictSet = $strictCounts[$row.StrictSig]
        LooseRuleSetId        = $looseIds[$row.LooseSig]
        NSGsWithSameLooseSet  = $looseCounts[$row.LooseSig]
        AttachedSubnets       = $row.AttachedSubnets
        AttachedNICs          = $row.AttachedNICs
    }
})

$totalNsgs  = $nsgSummary.Count
$matrixRows = @(foreach ($key in $ruleIndex.Keys) {
    $e = $ruleIndex[$key]
    [pscustomobject]@{
        NSGCount                 = $e.NSGs.Count
        Direction                = $e.Direction
        Access                   = $e.Access
        Protocol                 = $e.Protocol
        SourceAddressPrefix      = $e.SourceAddressPrefix
        SourceAsg                = $e.SourceAsg
        SourcePortRange          = $e.SourcePortRange
        DestinationAddressPrefix = $e.DestinationAddressPrefix
        DestinationAsg           = $e.DestinationAsg
        DestinationPortRange     = $e.DestinationPortRange
        PrioritiesSeen           = ($e.Priorities -join ", ")
        NamesSeen                = ($e.Names -join "; ")
        NSGs                     = ($e.NSGs -join "; ")
    }
})
$matrixRows = @($matrixRows | Sort-Object -Property @{ Expression = "NSGCount"; Descending = $true }, "Direction", "Protocol", "DestinationPortRange")


# -- Export CSVs
$rulesFile  = Join-Path $OutputDirectory "$stamp.nsg-rules.csv"
$groupsFile = Join-Path $OutputDirectory "$stamp.nsg-ruleset-groups.csv"
$matrixFile = Join-Path $OutputDirectory "$stamp.nsg-rule-matrix.csv"

$ruleRows   | Export-Csv -Path $rulesFile  -NoTypeInformation -Encoding UTF8
$groupRows  | Export-Csv -Path $groupsFile -NoTypeInformation -Encoding UTF8
$matrixRows | Export-Csv -Path $matrixFile -NoTypeInformation -Encoding UTF8


# -- Console and log summary
Write-Log ""
Write-Log "=== Scan tally (by subscription) ==="
Write-LogTable -Rows $tallyRows -Properties @("Subscription", "NSGs", "CustomRules")

Write-Log ""
Write-Log "=== NSGs and their rule-set IDs ==="
Write-LogTable -Rows ($groupRows | Sort-Object StrictRuleSetId, Subscription, NSG) -Properties @("Subscription", "NSG", "CustomRuleCount", "StrictRuleSetId", "LooseRuleSetId")

Write-Log ""
Write-Log "=== NSGs with identical rule sets (Strict: everything but name and description) ==="
$strictGroups = @($groupRows | Group-Object StrictRuleSetId | Where-Object { $_.Count -gt 1 })
if ($strictGroups.Count -eq 0) {
    Write-Log "  No two NSGs have an identical rule set."
}
foreach ($g in $strictGroups) {
    $members = ($g.Group | ForEach-Object { '{0}/{1}' -f $_.Subscription, $_.NSG }) -join "; "
    Write-Log ("  Rule set {0} is identical in {1} NSGs: {2}" -f $g.Name, $g.Count, $members)
}

Write-Log ""
Write-Log "=== NSGs with identical rule sets when priority is ignored (Loose) ==="
$looseGroups = @($groupRows | Group-Object LooseRuleSetId | Where-Object { $_.Count -gt 1 })
if ($looseGroups.Count -eq 0) {
    Write-Log "  No two NSGs have an identical rule set."
}
foreach ($g in $looseGroups) {
    $members = ($g.Group | ForEach-Object { '{0}/{1}' -f $_.Subscription, $_.NSG }) -join "; "
    Write-Log ("  Rule set {0} is identical in {1} NSGs: {2}" -f $g.Name, $g.Count, $members)
}

$inAll  = @($matrixRows | Where-Object { $_.NSGCount -eq $totalNsgs }).Count
$inOne  = @($matrixRows | Where-Object { $_.NSGCount -eq 1 }).Count
Write-Log ""
Write-Log "=== Rule commonality (rules compared ignoring name and priority) ==="
Write-Log ("  NSGs compared:                      {0}" -f $totalNsgs)
Write-Log ("  Distinct rules found:               {0}" -f $matrixRows.Count)
Write-Log ("  Rules present in every NSG:         {0}" -f $inAll)
Write-Log ("  Rules present in exactly one NSG:   {0}" -f $inOne)
if ($totalNsgs -eq 1) {
    Write-Log "  Only one NSG was compared, so every rule counts as both 'in every NSG' and 'in exactly one'." -Level WARN
}

Write-Log ""
Write-Log "Files written:" -Level SUCCESS
Write-Log "  $rulesFile"
Write-Log "  $groupsFile"
Write-Log "  $matrixFile"
Write-Log "$scriptName finished"

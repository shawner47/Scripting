# ============================================================
# New-BaselineNSG_v1.0.ps1
# Version 1.0
#
# Creates one new Network Security Group holding the agreed
# baseline rule set: the non-domain-controller-specific rules
# from nsg-newdc-devaccess (ICMP, Tanium, SMB, the private-
# subnets outbound rule), plus SSH and RDP rules built by
# combining every source address already in use for those
# ports across the NSGs reviewed on 2026-09-28.
#
# WHAT THIS SCRIPT CHANGES:
#   Azure:  Nothing by default. Only when run with -Apply does
#           it create one new NSG (New-AzNetworkSecurityGroup)
#           with the rules below. It does not attach the NSG
#           to any subnet or NIC, and does not touch any
#           existing NSG. Without -Apply, it only prints what
#           would be created (-Preview behavior, the default).
#   Your PS session: While it runs, it switches the active
#           subscription (Set-AzContext -Scope Process,
#           contained to this session), and restores your
#           original context in a finally block whether it
#           succeeds or fails.
#   Your computer: Creates the log folder if it does not
#           exist, and writes one log file.
#
# PREREQUISITES:
#   - Az.Accounts and Az.Network PowerShell modules installed
#   - Active Azure session: run Connect-AzAccount first
#   - Contributor (or higher) on the target subscription if
#     run with -Apply. Reader is enough for a preview.
#
# PARAMETERS:
#   -SubscriptionName     Subscription the NSG will be created
#                          in. Required.
#   -ResourceGroupName    Resource group the NSG will be
#                          created in. Required.
#   -Location              Azure region for the NSG, for
#                          example "eastus". Required.
#   -NsgName               Name for the new NSG.
#                          Default: baseline-subnet-nsg
#   -Apply                 Switch. Without it, the script only
#                          previews the rules and performs no
#                          write. With it, the NSG is created.
#
# OUTPUT:
#   $LogDir\yyyy.MM.dd.HHmmss.New-BaselineNSG_v1.0.log
#   (no CSV output; this script creates one Azure resource)
#
# EXAMPLES:
#   .\New-BaselineNSG_v1.0.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -Location "eastus"
#       Preview only. Prints every rule that would be created. Creates nothing.
#
#   .\New-BaselineNSG_v1.0.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -Location "eastus" -Apply
#       Creates the NSG for real, with the rules shown in the preview.
#
#   .\New-BaselineNSG_v1.0.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -Location "eastus" -NsgName "baseline-subnet1-nsg" -Apply
#       Same, with a specific NSG name instead of the default.
#
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string]$SubscriptionName = "",
    [string]$ResourceGroupName = "",
    [string]$Location = "",
    [string]$NsgName = "baseline-subnet-nsg",
    [switch]$Apply
)

# -SubscriptionName, -ResourceGroupName and -Location are required, but are not marked
# [Parameter(Mandatory)] per standard 13 (Mandatory rejects "" at runtime). Checked here instead.
$missing = @()
if ($SubscriptionName -eq "")  { $missing += "-SubscriptionName" }
if ($ResourceGroupName -eq "") { $missing += "-ResourceGroupName" }
if ($Location -eq "")          { $missing += "-Location" }
if ($missing.Count -gt 0) {
    throw ("Missing required parameter(s): {0}" -f ($missing -join ", "))
}

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs\Azure"
$ScriptVersion = "1.0"

# Private-subnets list, taken as-is from nsg-newdc-devaccess's inbound rules (ICMP, Tanium, SMB).
$PrivateSubnetsInbound = @(
    "10.10.4.0/23", "10.10.6.0/24", "10.150.0.0/21", "10.20.30.0/24",
    "10.99.0.0/16", "172.16.0.0/16", "172.30.20.0/22", "172.31.20.0/22",
    "192.168.0.0/16"
)

# Destination list for the outbound rule, taken as-is from nsg-newdc-devaccess's
# AllowOutToPrivateSubnets. Deliberately not merged with the inbound list above;
# this is a narrower, separate set already in production.
$PrivateSubnetsOutbound = @(
    "10.10.4.0/23", "10.10.6.0/24", "10.150.0.0/21", "10.99.0.0/16",
    "172.16.100.0/24", "192.168.0.0/16",
    "209.198.200.140/32", "209.198.200.141/32", "209.198.200.228/32"
)

# SSH and RDP source list: the union of every source seen for each port
# across MGL-DEV-OEAAPP1-nsg (SSH), MGL-DEV-OEASQL-nsg / MGL-DEV-OEAWEB1-nsg
# (RDP, "RDP-from-Corp"), and MGL-AZ-DC06-nsg (RDP, "HQ-VLAN4-RDP-in").
$AdminAccessSources = @("192.168.4.0/24", "209.198.200.228")
# ============================================================


# -- Folder, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
if (-not (Test-Path -Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
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
    param($Rows, [string[]]$Properties, [string]$Level = "INFO")
    $text = $Rows | Format-Table -Property $Properties -AutoSize | Out-String -Width 250
    foreach ($tableLine in ($text -split '\r?\n')) {
        if ($tableLine.Trim().Length -gt 0) { Write-Log $tableLine -Level $Level }
    }
}


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log ("Mode: {0}" -f $(if ($Apply) { "APPLY - this run will create a real NSG" } else { "PREVIEW - no changes will be made" }))
Write-Log "Target subscription: $SubscriptionName"
Write-Log "Target resource group: $ResourceGroupName"
Write-Log "Target location: $Location"
Write-Log "NSG name: $NsgName"
Write-Log "Log file: $logFile"


# -- Verify Azure session exists before doing anything
$originalContext = Get-AzContext
if (-not $originalContext) {
    Write-Log "No Azure session found. Run Connect-AzAccount first, then run this script again." -Level ERROR
    throw "No Azure session found. Run Connect-AzAccount first."
}
Write-Log "Starting in subscription: $($originalContext.Subscription.Name)"


# -- Build the rule set (always, preview or apply, so what's shown is what would be created)
$rules = New-Object System.Collections.Generic.List[object]
$priority = 100

$rules.Add(@{ Name = "Allow-ICMPv4-in";           Description = "Baseline: ICMP from private subnets, carried over from nsg-newdc-devaccess"; Direction = "Inbound";  Access = "Allow"; Protocol = "*";   SourceAddressPrefix = $PrivateSubnetsInbound; SourcePortRange = "*"; DestinationAddressPrefix = "*"; DestinationPortRange = "*" })
$priority += 10
$rules.Add(@{ Name = "Allow-Tanium1";             Description = "Baseline: Tanium (139) from private subnets, carried over from nsg-newdc-devaccess"; Direction = "Inbound";  Access = "Allow"; Protocol = "*";   SourceAddressPrefix = $PrivateSubnetsInbound; SourcePortRange = "*"; DestinationAddressPrefix = "*"; DestinationPortRange = "139" })
$priority += 10
$rules.Add(@{ Name = "Allow-SMB";                 Description = "Baseline: SMB (445) from private subnets, carried over from nsg-newdc-devaccess"; Direction = "Inbound";  Access = "Allow"; Protocol = "Tcp"; SourceAddressPrefix = $PrivateSubnetsInbound; SourcePortRange = "*"; DestinationAddressPrefix = "*"; DestinationPortRange = "445" })
$priority += 10
$rules.Add(@{ Name = "Allow-SSH-in";              Description = "Baseline: SSH for Linux VMs, combined source from MGL-DEV-OEAAPP1-nsg"; Direction = "Inbound";  Access = "Allow"; Protocol = "Tcp"; SourceAddressPrefix = $AdminAccessSources;   SourcePortRange = "*"; DestinationAddressPrefix = "*"; DestinationPortRange = "22" })
$priority += 10
$rules.Add(@{ Name = "Allow-RDP-in";              Description = "Baseline: RDP, combined source from MGL-DEV-OEASQL-nsg, MGL-DEV-OEAWEB1-nsg and MGL-AZ-DC06-nsg"; Direction = "Inbound";  Access = "Allow"; Protocol = "Tcp"; SourceAddressPrefix = $AdminAccessSources;   SourcePortRange = "*"; DestinationAddressPrefix = "*"; DestinationPortRange = "3389" })
$priority += 10
$rules.Add(@{ Name = "AllowOutToPrivateSubnets";  Description = "Baseline: outbound to private subnets, carried over from nsg-newdc-devaccess"; Direction = "Outbound"; Access = "Allow"; Protocol = "*";   SourceAddressPrefix = "*"; SourcePortRange = "*"; DestinationAddressPrefix = $PrivateSubnetsOutbound; DestinationPortRange = "*" })

$idx = 0
foreach ($r in $rules) {
    $idx++
    $r["Priority"] = 100 + (($idx - 1) * 10)
}

Write-Log ""
Write-Log "=== Rules that will be created ==="
$previewRows = $rules | ForEach-Object {
    [pscustomobject]@{
        Name        = $_.Name
        Priority    = $_.Priority
        Direction   = $_.Direction
        Access      = $_.Access
        Protocol    = $_.Protocol
        SourcePorts = $_.SourcePortRange
        DestPorts   = $_.DestinationPortRange
        Source      = ($_.SourceAddressPrefix -join ", ")
        Destination = ($_.DestinationAddressPrefix -join ", ")
    }
}
Write-LogTable -Rows $previewRows -Properties @("Name", "Priority", "Direction", "Access", "Protocol", "SourcePorts", "DestPorts")

Write-Log ""
Write-Log "=== Source / destination address lists ==="
foreach ($row in $previewRows) {
    Write-Log ("  {0}: source={1} | destination={2}" -f $row.Name, $row.Source, $row.Destination)
}

if (-not $Apply) {
    Write-Log ""
    Write-Log "Preview only. No changes were made. Re-run with -Apply to create this NSG for real." -Level WARN
    Write-Log "$scriptName finished"
    exit 0
}


# -- Apply: create the NSG for real
try {
    Write-Log ""
    Write-Log "Switching to subscription '$SubscriptionName' to create the NSG..."
    $sub = Get-AzSubscription | Where-Object { $_.Name -eq $SubscriptionName -and $_.State -eq "Enabled" } | Select-Object -First 1
    if (-not $sub) {
        Write-Log "Subscription '$SubscriptionName' was not found among your enabled subscriptions." -Level ERROR
        throw "Subscription '$SubscriptionName' was not found among your enabled subscriptions."
    }

    # -Scope Process keeps the switch inside this session only.
    # The tenant token warning it emits has been harmless; it is hidden here.
    # The check below confirms the switch really happened before anything is written.
    $null = Set-AzContext -SubscriptionId $sub.Id -Scope Process -WarningAction SilentlyContinue
    if ((Get-AzContext).Subscription.Id -ne $sub.Id) {
        Write-Log "Could not switch to subscription '$SubscriptionName'. Nothing was created." -Level ERROR
        throw "Could not switch to subscription '$SubscriptionName'."
    }

    $existing = Get-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "An NSG named '$NsgName' already exists in resource group '$ResourceGroupName'. Nothing was created. Choose a different -NsgName or remove the existing one first." -Level ERROR
        throw "An NSG named '$NsgName' already exists in resource group '$ResourceGroupName'."
    }

    $ruleConfigs = foreach ($r in $rules) {
        $ruleParams = @{
            Name                      = $r.Name
            Description               = $r.Description
            Access                    = $r.Access
            Protocol                  = $r.Protocol
            Direction                 = $r.Direction
            Priority                  = $r.Priority
            SourceAddressPrefix       = $r.SourceAddressPrefix
            SourcePortRange           = $r.SourcePortRange
            DestinationAddressPrefix  = $r.DestinationAddressPrefix
            DestinationPortRange      = $r.DestinationPortRange
        }
        New-AzNetworkSecurityRuleConfig @ruleParams
    }

    $newNsg = New-AzNetworkSecurityGroup -Name $NsgName -ResourceGroupName $ResourceGroupName -Location $Location -SecurityRules $ruleConfigs

    Write-Log ""
    Write-Log "NSG '$NsgName' created in resource group '$ResourceGroupName' with $($rules.Count) rules." -Level SUCCESS
    Write-Log "It is not attached to any subnet or NIC. Attaching it is a separate, deliberate step." -Level WARN
} finally {
    $null = Set-AzContext -Context $originalContext -Scope Process -WarningAction SilentlyContinue
    Write-Log "Session context restored to: $($originalContext.Subscription.Name)" -Level SUCCESS
}

Write-Log "$scriptName finished"

# ============================================================
# Inventory-NSG-Associations_v1.3.ps1
# Version 1.3
#
# Read-only inventory of Network Security Group (NSG)
# associations in the selected Azure subscriptions.
#
# WHAT THIS SCRIPT COLLECTS:
#   1. Every NSG -- custom rule count and attached
#      subnets/NICs
#   2. Every subnet -- attached NSG if any, number of NICs,
#      and a flag for special-purpose subnets
#      (GatewaySubnet, AzureBastionSubnet, AzureFirewallSubnet)
#   3. Every NIC -- VM, private IP, subnet NSG, NIC NSG,
#      and a coverage classification:
#        Both (subnet + NIC) | Subnet only | NIC only |
#        NONE | UNKNOWN (subnet outside scan)
#   4. A per-subscription tally (NSGs, VNets, subnets, NICs)
#      so you can confirm each subscription was scanned in full.
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
# WHAT THE RESULTS DO NOT SHOW:
#   - NONE means no NSG is attached at the subnet or NIC level.
#     It does not by itself mean the VM is unprotected. Other
#     controls (Azure Virtual Network Manager security admin
#     rules, firewalls elsewhere in the path) are not checked.
#   - Rules are counted, not read. Use Export-NSG-Rules to read
#     what the rules allow or deny.
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
#
# OUTPUT:
#   $OutputDirectory\yyyy.MM.dd.HHmmss.nsg-inventory.csv
#   $OutputDirectory\yyyy.MM.dd.HHmmss.subnet-nsg-inventory.csv
#   $OutputDirectory\yyyy.MM.dd.HHmmss.nic-nsg-coverage.csv
#   $LogDir\yyyy.MM.dd.HHmmss.Inventory-NSG-Associations_v1.3.log
#
# EXAMPLES:
#   .\Inventory-NSG-Associations_v1.3.ps1
#   .\Inventory-NSG-Associations_v1.3.ps1 -OutputDirectory "D:\Reports"
#   .\Inventory-NSG-Associations_v1.3.ps1 -SubscriptionName "Mingledorff Dev Application VPC"
#   .\Inventory-NSG-Associations_v1.3.ps1 -SubscriptionName "Mingledorff Dev Application VPC", "Mingledorff Prod Application VPC" -OutputDirectory "D:\Reports"
#
# v1.3 changes:
#   - Scope: added -SubscriptionName so only the selected
#     subscriptions are scanned (default: the three in scope).
#     Duplicate subscription entries are collapsed by Id.
#   - Standards 21 and 27: log file is now named
#     yyyy.MM.dd.HHmmss.<script name>.log (timestamp prefix) and
#     built with Join-Path. One timestamp is now shared by the
#     log file and all CSV files.
#   - Standard 22: the NICs-with-no-NSG table is now written to
#     the log file as well as the console (via Write-LogTable).
#   - Standard 8: the version number is set once in
#     $ScriptVersion instead of being typed into log lines.
#   - Standard 19: log lines use the level colors only
#     (INFO=White, WARN=Yellow, SUCCESS=Green, ERROR=Red).
#   - Added a per-subscription scan tally (NSGs, VNets, subnets,
#     NICs) to the log and console so completeness can be
#     confirmed at a glance.
#   - Added a NICCount column to the subnet CSV and a subnet
#     summary listing every subnet scanned.
#
# v1.2 changes:
#   - Applied CRLF line endings, UTF-8 BOM, and standard
#     toolset header block with version number and history.
#   - Added Write-Log function with console color by level
#     (ERROR=Red, WARN=Yellow, SUCCESS=Green, INFO=White)
#     and timestamped log file output to $LogDir.
#   - Replaced Write-Host / Write-Warning calls with Write-Log.
#
# v1.1 changes:
#   - Added authentication check: script throws with a clear
#     message if no Azure session exists (Connect-AzAccount).
#   - Added context save/restore: original subscription context
#     is saved before scanning and restored in a finally block,
#     ensuring the session is left in the same state regardless
#     of whether the script succeeds or fails midway.
#   - Added -Scope Process to both Set-AzContext calls to
#     contain context switches to this session only.
#   - Expanded description with WHAT THIS SCRIPT CHANGES and
#     WHAT THE RESULTS DO NOT SHOW sections.
#   - Fixed CustomRuleCount: explicit null check for NSG
#     SecurityRules before counting.
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
    )
)

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs\Azure"
$ScriptVersion = "1.3"
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


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log "Output directory: $OutputDirectory"
Write-Log "Log file: $logFile"


# -- Verify Azure session exists before doing anything
$originalContext = Get-AzContext
if (-not $originalContext) {
    Write-Log "No Azure session found. Run Connect-AzAccount first, then run this script again." -Level ERROR
    throw "No Azure session found. Run Connect-AzAccount first."
}
Write-Log "Starting in subscription: $($originalContext.Subscription.Name)"


$nsgRows    = New-Object System.Collections.Generic.List[object]
$subnetRows = New-Object System.Collections.Generic.List[object]
$nicRows    = New-Object System.Collections.Generic.List[object]
$tallyRows  = New-Object System.Collections.Generic.List[object]


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

        # 1. NSGs
        $nsgs = @(Get-AzNetworkSecurityGroup)
        foreach ($nsg in $nsgs) {
            $attachedSubnets = @($nsg.Subnets) | Where-Object { $_ -and $_.Id } | ForEach-Object {
                '{0}/{1}' -f (($_.Id -split '/')[-3]), (($_.Id -split '/')[-1])
            }
            $attachedNics = @($nsg.NetworkInterfaces) | Where-Object { $_ -and $_.Id } | ForEach-Object {
                ($_.Id -split '/')[-1]
            }
            $ruleCount = 0
            if ($nsg.SecurityRules) { $ruleCount = @($nsg.SecurityRules).Count }

            $nsgRows.Add([pscustomobject]@{
                Subscription      = $sub.Name
                NSG               = $nsg.Name
                ResourceGroup     = $nsg.ResourceGroupName
                Location          = $nsg.Location
                CustomRuleCount   = $ruleCount
                AssociatedSubnets = ($attachedSubnets -join '; ')
                AssociatedNICs    = ($attachedNics -join '; ')
            })
        }

        # 2. Subnets -- collected first; also builds the subnet Id -> subnet NSG lookup used in step 3
        $vnets         = @(Get-AzVirtualNetwork)
        $subnetNsgById = @{}
        $subnetInfo    = New-Object System.Collections.Generic.List[object]
        foreach ($vnet in $vnets) {
            foreach ($subnet in $vnet.Subnets) {
                $subnetNsg = ''
                if ($subnet.NetworkSecurityGroup -and $subnet.NetworkSecurityGroup.Id) {
                    $subnetNsg = Get-LastSegment $subnet.NetworkSecurityGroup.Id
                }
                $subnetNsgById[$subnet.Id] = $subnetNsg

                $note = ''
                if ($subnet.Name -in 'GatewaySubnet', 'AzureBastionSubnet', 'AzureFirewallSubnet') {
                    $note = 'Special-purpose subnet - review before changing its NSG'
                }

                $subnetInfo.Add([pscustomobject]@{
                    Id            = $subnet.Id
                    ResourceGroup = $vnet.ResourceGroupName
                    VNet          = $vnet.Name
                    Subnet        = $subnet.Name
                    AddressPrefix = ($subnet.AddressPrefix -join ', ')
                    SubnetNSG     = $subnetNsg
                    Note          = $note
                })
            }
        }

        # 3. NICs -- also counts NICs per subnet for the subnet rows
        $nics               = @(Get-AzNetworkInterface)
        $nicCountBySubnetId = @{}
        foreach ($nic in $nics) {
            $ipConfig = @($nic.IpConfigurations)[0]
            $subnetId = ''
            if ($ipConfig -and $ipConfig.Subnet) { $subnetId = $ipConfig.Subnet.Id }

            if ($subnetId) {
                if ($nicCountBySubnetId.ContainsKey($subnetId)) {
                    $nicCountBySubnetId[$subnetId] = $nicCountBySubnetId[$subnetId] + 1
                } else {
                    $nicCountBySubnetId[$subnetId] = 1
                }
            }

            $subnetNsg = ''
            if ($subnetId -and $subnetNsgById.ContainsKey($subnetId)) { $subnetNsg = $subnetNsgById[$subnetId] }

            $nicNsg = ''
            if ($nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id) {
                $nicNsg = Get-LastSegment $nic.NetworkSecurityGroup.Id
            }

            if ($subnetId -and -not $subnetNsgById.ContainsKey($subnetId)) { $coverage = 'UNKNOWN (subnet outside scan)' }
            elseif ($subnetNsg -and $nicNsg) { $coverage = 'Both (subnet + NIC)' }
            elseif ($subnetNsg)              { $coverage = 'Subnet only' }
            elseif ($nicNsg)                 { $coverage = 'NIC only' }
            else                             { $coverage = 'NONE' }

            $vmName = '(unattached)'
            if ($nic.VirtualMachine -and $nic.VirtualMachine.Id) { $vmName = Get-LastSegment $nic.VirtualMachine.Id }

            $subnetLabel = ''
            if ($subnetId) { $subnetLabel = '{0}/{1}' -f (($subnetId -split '/')[-3]), (($subnetId -split '/')[-1]) }

            $nicRows.Add([pscustomobject]@{
                Subscription  = $sub.Name
                ResourceGroup = $nic.ResourceGroupName
                NIC           = $nic.Name
                VM            = $vmName
                PrivateIP     = ((@($nic.IpConfigurations) | ForEach-Object { $_.PrivateIpAddress }) -join ', ')
                Subnet        = $subnetLabel
                SubnetNSG     = $subnetNsg
                NicNSG        = $nicNsg
                Coverage      = $coverage
            })
        }

        # Subnet rows, now that NIC counts are known
        foreach ($info in $subnetInfo) {
            $nicCount = 0
            if ($nicCountBySubnetId.ContainsKey($info.Id)) { $nicCount = $nicCountBySubnetId[$info.Id] }
            $subnetRows.Add([pscustomobject]@{
                Subscription  = $sub.Name
                ResourceGroup = $info.ResourceGroup
                VNet          = $info.VNet
                Subnet        = $info.Subnet
                AddressPrefix = $info.AddressPrefix
                SubnetNSG     = $info.SubnetNSG
                NICCount      = $nicCount
                Note          = $info.Note
            })
        }

        # Scan tally for this subscription
        $tallyRows.Add([pscustomobject]@{
            Subscription = $sub.Name
            NSGs         = $nsgs.Count
            VNets        = $vnets.Count
            Subnets      = $subnetInfo.Count
            NICs         = $nics.Count
        })
        Write-Log ("  Tally: {0} NSG(s), {1} VNet(s), {2} subnet(s), {3} NIC(s)" -f $nsgs.Count, $vnets.Count, $subnetInfo.Count, $nics.Count)
    }
} finally {
    # Runs on success and on failure: restore the original subscription context.
    $null = Set-AzContext -Context $originalContext -Scope Process -WarningAction SilentlyContinue
    Write-Log "Session context restored to: $($originalContext.Subscription.Name)" -Level SUCCESS
}


# -- Export CSVs
$nsgFile    = Join-Path $OutputDirectory "$stamp.nsg-inventory.csv"
$subnetFile = Join-Path $OutputDirectory "$stamp.subnet-nsg-inventory.csv"
$nicFile    = Join-Path $OutputDirectory "$stamp.nic-nsg-coverage.csv"

$nsgRows    | Export-Csv -Path $nsgFile    -NoTypeInformation -Encoding UTF8
$subnetRows | Export-Csv -Path $subnetFile -NoTypeInformation -Encoding UTF8
$nicRows    | Export-Csv -Path $nicFile    -NoTypeInformation -Encoding UTF8


# -- Console and log summary
Write-Log ""
Write-Log "=== Scan tally (by subscription) ==="
Write-LogTable -Rows $tallyRows -Properties @("Subscription", "NSGs", "VNets", "Subnets", "NICs")

Write-Log ""
Write-Log "=== NIC coverage summary (by subscription) ==="
$nicRows | Group-Object Subscription, Coverage | Sort-Object Name | ForEach-Object {
    Write-Log ("  {0,-70} {1}" -f $_.Name, $_.Count)
}

Write-Log ""
Write-Log "=== Subnet summary (every subnet scanned) ==="
Write-LogTable -Rows ($subnetRows | Sort-Object Subscription, VNet, Subnet) -Properties @("Subscription", "VNet", "Subnet", "AddressPrefix", "SubnetNSG", "NICCount")

$uncovered = @($nicRows | Where-Object { $_.Coverage -eq 'NONE' })
if ($uncovered.Count -gt 0) {
    Write-Log ""
    Write-Log "=== NICs with NO NSG at subnet or NIC level ===" -Level WARN
    Write-LogTable -Rows $uncovered -Properties @("Subscription", "NIC", "VM", "PrivateIP", "Subnet") -Level WARN
}

Write-Log ""
Write-Log "Files written:" -Level SUCCESS
Write-Log "  $nsgFile"
Write-Log "  $subnetFile"
Write-Log "  $nicFile"
Write-Log "$scriptName finished"

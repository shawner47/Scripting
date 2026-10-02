# ============================================================
# Move-Subnet-Delegation-Fix_v1.8.ps1
# Version 1.8
#
# Clears a stuck subnet delegation on vnet-appvpc-vms/subnet1
# and subnet2 (Microsoft.ServiceNetworking/trafficControllers,
# left behind by the decommissioned MingApis-GW resource) by
# temporarily moving every VM currently in those two subnets to
# a temporary subnet, clearing the delegation once both subnets
# are empty, then moving every VM back to its original subnet
# and exact original static IP.
#
# This script discovers every VM/NIC currently in subnet1 and
# subnet2 AT RUNTIME. It does not use a hard-coded list, because
# which VMs are in these subnets, and their IPs, can change
# between when this script is written and when it is run.
#
# WHAT THIS SCRIPT CHANGES:
#   Azure:  Nothing by default (Preview mode). With -Apply, the
#           phase named in -Phase actually runs:
#             MoveOut          - captures a configuration
#                                 snapshot of every discovered
#                                 NIC BEFORE touching anything,
#                                 then stops each discovered VM
#                                 and moves its NIC to the temp
#                                 subnet (Dynamic allocation),
#                                 leaving the VM stopped. Each VM
#                                 is processed independently: one
#                                 VM's failure does not stop the
#                                 others, and if a VM is stopped
#                                 but its NIC move then fails, the
#                                 script automatically restarts
#                                 that VM in its original subnet
#                                 rather than leaving it down for
#                                 no reason.
#             VerifyEmpty      - read-only. Confirms subnet1 and
#                                 subnet2 have no NICs left.
#             ClearDelegation  - clears the delegation on subnet1
#                                 and subnet2. Fails loudly, and
#                                 changes nothing, if either
#                                 subnet is not actually empty.
#             MoveBack         - re-checks, live, that each VM
#                                 recorded in the state file is
#                                 actually still sitting in the
#                                 temp subnet before touching it,
#                                 then moves its NIC back to its
#                                 original subnet, restores its
#                                 original static private IP, and
#                                 starts the VM. Each VM is
#                                 processed independently. Once
#                                 every VM has been attempted, it
#                                 captures an AFTER configuration
#                                 snapshot and automatically
#                                 compares it, property by
#                                 property, against the BEFORE
#                                 snapshot from MoveOut, logging a
#                                 clear match/mismatch result for
#                                 every NIC.
#             Cleanup          - removes the temporary subnet.
#                                 Only proceeds if the temp
#                                 subnet is confirmed empty.
#           Every phase that changes anything runs the matching
#           emptiness/state check first and stops with no changes
#           if that check does not pass.
#   Your PS session: Switches the active subscription (Set-
#           AzContext -Scope Process, contained to this
#           session), and restores your original context in a
#           finally block whether it succeeds or fails.
#   Your computer: Creates the log and state folders if they do
#           not exist. Writes one log file per run, the migration
#           state file, and the before/after NIC snapshot files.
#
# WHY THIS IS A MULTI-PHASE SCRIPT, NOT ONE SCRIPT THAT DOES
# EVERYTHING AT ONCE:
#   Each phase is independently verifiable before the next one
#   runs. If something looks wrong after MoveOut, you can stop
#   there, with VMs safely deallocated (or already automatically
#   restarted, per the per-VM summary) and nothing else touched,
#   rather than being partway through an uninterruptible script
#   with production VMs down.
#
# WHAT THE BEFORE/AFTER SNAPSHOT COVERS, AND WHY:
#   For each NIC: its NSG id, MAC address, IP forwarding and
#   accelerated networking settings, DNS server list, tags, and
#   for its primary IP configuration: subnet id, private IP
#   address, allocation method, and public IP id (if any). These
#   are the properties that would reveal whether anything other
#   than the intended subnet/IP round-trip changed. Because the
#   goal is to restore every NIC to EXACTLY its original state,
#   every one of these fields is expected to match exactly, with
#   no exceptions. The comparison does not inspect fields that
#   change on every write regardless of content, such as ETag,
#   since comparing those would produce constant false mismatches
#   unrelated to whether anything meaningful actually changed.
#
# PREREQUISITES:
#   - Az.Accounts, Az.Network and Az.Compute PowerShell modules
#   - Active Azure session: run Connect-AzAccount first
#   - Contributor (or higher) on the target subscription for any
#     -Apply run. Reader is enough for a preview. The script
#     checks this itself before any -Apply run proceeds (direct,
#     subscription-inherited, or group-based Owner/Contributor on
#     the target resource group) and stops with no changes if it
#     is not found.
#   - Every discovered VM is assumed to currently have a Static
#     private IP on a single IP configuration, with no public IP
#     attached to that configuration. If any discovered NIC is
#     not Static, has more than one IP configuration, or has a
#     public IP attached, the MoveOut phase stops with no changes
#     and lists which NIC(s) are the problem.
#
# RECOMMENDED EXECUTION ORDER:
#   1. Run with no -Apply (preview). Review the discovery table
#      and all three precondition warnings (non-Static, multi-
#      config, public IP). Do not continue until the warnings
#      section is empty.
#   2. -Phase MoveOut -Apply
#      Check: the "MoveOut results" table shows Success for
#      every VM. If any show Failed-*, resolve those before
#      continuing - the affected VM(s) did not move.
#   3. -Phase VerifyEmpty -Apply
#      Check: the log says "Confirmed: target subnet(s) are
#      empty." This step is a recommended manual checkpoint, not
#      a hard gate - ClearDelegation independently re-checks
#      emptiness itself and will refuse to run if it is not
#      empty, regardless of what this step reported.
#   4. -Phase ClearDelegation -Apply
#      Check: the log says "Confirmed: no delegations remain."
#   5. -Phase MoveBack -Apply
#      Check two things: the "MoveBack results" table shows
#      Success for every VM, AND the "Comparison summary" table
#      shows MATCH for every NIC. A VM can show Success while a
#      NIC still shows MISMATCH (for example, a tag or DNS
#      setting that changed for an unrelated reason) - both
#      tables matter, not just one.
#   6. Outside this script: confirm the VMs are actually healthy
#      - reachable on their original IP, applications/services on
#      them responding as expected. This script restores Azure
#      network configuration; it cannot confirm application-level
#      health inside the guest OS.
#   7. -Phase Cleanup -Apply
#      Only run this once step 6 is confirmed. This removes the
#      temporary subnet, and there is no "undo" for that step
#      short of recreating the subnet by hand.
#
# PARAMETERS:
#   -SubscriptionName   Subscription to operate in. Required.
#   -ResourceGroupName  Resource group holding the VNet and VMs.
#                       Required.
#   -VNetName           VNet containing the affected subnets.
#                       Required.
#   -SubnetNames        The subnet(s) to clear the delegation
#                       from. Default: subnet1, subnet2
#   -TempSubnetName      Name for the temporary subnet.
#                       Default: subnet-temp-migration
#   -TempSubnetPrefix    Address prefix for the temporary subnet.
#                       Default: 10.150.4.0/27
#   -Phase               One of: MoveOut, VerifyEmpty,
#                       ClearDelegation, MoveBack, Cleanup.
#                       Required with -Apply. Preview mode
#                       (no -Apply) always just discovers and
#                       prints current subnet1/subnet2 contents,
#                       regardless of -Phase.
#   -Apply               Switch. Without it, the script only
#                       previews. With it, the named -Phase
#                       actually runs.
#
# OUTPUT:
#   $LogDir\yyyy.MM.dd.HHmmss.Move-Subnet-Delegation-Fix_v1.8.log
#   $StateDir\subnet-migration-state.json   (written by MoveOut,
#       read by MoveBack and Cleanup)
#   $StateDir\nic-snapshot-before.json      (written by MoveOut)
#   $StateDir\nic-snapshot-after.json       (written by MoveBack)
#
# EXAMPLES:
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms"
#       Preview only. Discovers and prints every VM/NIC currently
#       in subnet1 and subnet2. Creates nothing, moves nothing.
#
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms" -Phase MoveOut -Apply
#       Captures the BEFORE snapshot, creates the temp subnet if
#       needed, stops each discovered VM, moves its NIC to the
#       temp subnet, writes the state file. Prints a per-VM
#       success/failure summary at the end.
#
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms" -Phase VerifyEmpty -Apply
#       Confirms subnet1 and subnet2 have no NICs left.
#
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms" -Phase ClearDelegation -Apply
#       Clears the delegation on subnet1 and subnet2.
#
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms" -Phase MoveBack -Apply
#       Moves every VM recorded in the state file back to its
#       original subnet and original static IP, then starts it.
#       Captures the AFTER snapshot and automatically compares it
#       against the BEFORE snapshot, logging a match/mismatch
#       result for every NIC.
#
#   .\Move-Subnet-Delegation-Fix_v1.8.ps1 -SubscriptionName "Mingledorff Dev Application VPC" -ResourceGroupName "Virtual_Machines" -VNetName "vnet-appvpc-vms" -Phase Cleanup -Apply
#       Removes the temporary subnet, once confirmed empty.
#
# v1.8 changes:
#   - v1.7's fix was INCOMPLETE. It split Get-Content onto its
#     own line but still wrote @($rawJson | ConvertFrom-Json) -
#     still wrapping @() directly around a live pipe, just with
#     Get-Content moved out of it. This still reproduced the
#     exact same failure in a live run ("Loaded 1 VM(s)",
#     followed by the same ParameterBindingException).
#   - The actual, now directly verified fix: three fully
#     separate statements, not two. Read the raw text; parse it
#     into its own plain variable with NO @() involved in that
#     statement at all; only then wrap that already-materialized
#     variable in @() as a distinct, final statement. @() only
#     behaves correctly here around an existing variable, not
#     around any live "... | ConvertFrom-Json" pipe, regardless
#     of whether Get-Content is inline or on a prior line.
#   - This was confirmed with a standalone diagnostic script
#     before being applied to the real script again, given the
#     v1.7 fix had already been asserted as correct once and
#     turned out not to be.
#
# v1.7 changes:
#   - Fixed a confirmed, reproduced bug in MoveBack's state and
#     snapshot file loading. @(Get-Content -Raw | ConvertFrom-
#     Json), written as a single combined expression, was
#     directly reproduced on PowerShell 5.1 Desktop to collapse
#     a 7-element JSON array into a single element whose
#     properties were space-joined strings of every entry's
#     values combined - not 7 separate objects. This caused
#     MoveBack to report "Loaded 1 VM(s)" and then fail outright
#     on the first NIC lookup. The fix splits the raw file read
#     and the JSON parse into two separate statements before
#     wrapping in @(), which was confirmed correct by direct,
#     side-by-side testing against the same file. This affected
#     both the state file load and the before-snapshot load used
#     in the post-MoveBack comparison.
#   - This bug was never caught by any earlier review because it
#     only manifests on the specific combination of PowerShell
#     5.1 Desktop plus a multi-element JSON array read back in
#     this exact single-expression form; manually re-running the
#     same two operations as separate interactive commands did
#     not reproduce it, which is why isolating it required a
#     standalone diagnostic script run the same way the real
#     script runs (as a file, not typed interactively).
#
# v1.6 changes:
#   - Fixed a confirmed, live bug in Test-SufficientPermission:
#     Get-AzRoleAssignment -ResourceGroupName combined with
#     -ExpandPrincipalGroups is not a valid parameter
#     combination (threw AmbiguousParameterSet on first real
#     -Apply run). The check now pulls every assignment for the
#     account subscription-wide via -SignInName and
#     -ExpandPrincipalGroups alone (where this switch is
#     actually valid per its own documentation), then matches
#     each assignment's Scope against the resource group's own
#     scope and the subscription root itself. This still does
#     not check inheritance from a management group above the
#     subscription.
#   - This failure occurred at the very first line of the
#     permission check, before any VM was touched, confirming
#     the fail-fast placement of this check worked as intended
#     even though the check itself had a bug.
#
# v1.5 changes:
#   - Added a RECOMMENDED EXECUTION ORDER section to the header,
#     listing all five steps in sequence, what to check after
#     each one, and which checks are enforced by the script
#     itself versus which are advisory.
#   - VerifyEmpty's success path now explicitly states the next
#     step (ClearDelegation); it previously gave no guidance.
#   - VerifyEmpty's failure path now tells you what to do (review
#     MoveOut, resolve, re-run), not just that it failed.
#   - Cleanup now ends with a short list of final checks to make
#     (subnet usability, the MoveBack comparison result, VM
#     health), since it is the last phase and previously ended
#     with no closing guidance at all.
#
# v1.4 changes:
#   - Added Test-SufficientPermission. Before any -Apply run
#     proceeds (any phase), the script now confirms the signed-in
#     account has "Owner" or "Contributor" on the target resource
#     group - checked directly at the resource group, inherited
#     from the subscription (or higher), and via AD group
#     membership (-ExpandPrincipalGroups). If none of these are
#     found, the script stops immediately with no changes made,
#     before touching any VM. This check only recognizes the two
#     named built-in roles; a custom role granting equivalent
#     rights under a different name is not recognized.
#
# v1.3 changes:
#   - Fixed a bug in Get-NicSnapshot's tag capture: enumerating a
#     Hashtable in PowerShell yields DictionaryEntry objects,
#     which expose .Key, not .Name. The previous version read
#     $_.Name, which does not exist on a DictionaryEntry, so
#     every tag was silently captured as blank in both the before
#     and after snapshot. This made the Tags field always report
#     MATCH, even if tags had actually changed, since blank was
#     always being compared against blank. Now reads $_.Key, so
#     tag values are actually captured and actually compared.
#   - DNS server list is now sorted before being joined into the
#     snapshot's DnsServers field. Without this, two snapshots of
#     the same, unchanged DNS server list could be rendered in a
#     different order and be flagged as a false MISMATCH, since
#     the comparison is a plain string comparison of the joined
#     list.
#
# v1.2 changes:
#   - Added the public-IP check: a discovered NIC with a public
#     IP on its primary IP configuration now blocks MoveOut, the
#     same way a non-Static or multi-config NIC does.
#   - Added Get-NicSnapshot, which captures the specific,
#     meaningful properties of a NIC (NSG id, MAC address, IP
#     forwarding, accelerated networking, DNS servers, tags, and
#     the primary IP configuration's subnet id, private IP,
#     allocation method, and public IP id).
#   - MoveOut now captures a BEFORE snapshot of every discovered
#     NIC, before any VM is stopped or any NIC is touched, and
#     saves it to nic-snapshot-before.json.
#   - MoveBack now captures an AFTER snapshot of every NIC listed
#     in the state file, once all VMs have been attempted, and
#     automatically compares it field by field against the BEFORE
#     snapshot. Every NIC is logged as MATCH or MISMATCH, and any
#     mismatch names the exact field(s) that differ.
#
# v1.1 changes:
#   - MoveOut and MoveBack now process each VM inside its own
#     try/catch, tracked by named step (Stop, MoveNic,
#     RestoreStatic, Start). One VM's failure no longer aborts
#     the remaining VMs in the batch.
#   - MoveOut: if a VM is successfully stopped but its NIC move
#     then fails, the script automatically restarts that VM in
#     its ORIGINAL subnet (the NIC was never successfully
#     changed), rather than leaving it down for no reason. This
#     is logged clearly and the VM is marked Failed-RolledBack.
#   - MoveBack: before touching any VM from the state file, its
#     NIC is re-checked live to confirm it is still actually
#     sitting in the temp subnet. If it is not (already moved,
#     deleted, or otherwise changed since MoveOut ran), that VM
#     is skipped with a clear reason instead of being acted on
#     blindly.
#   - MoveBack: if the subnet-move-back step fails, the VM is
#     left stopped in the temp subnet (same safe state as after
#     MoveOut) rather than started with a wrong configuration.
#     If only the static-IP-restore step fails (subnet move
#     already succeeded), the VM is still started, since it is
#     in the correct subnet, and is flagged loudly that its IP
#     does not match the original and needs manual correction.
#   - Added a check for NICs with more than one IP configuration.
#     Treated the same as a non-Static NIC: blocks MoveOut with
#     a named list, since the script only reads and restores a
#     single IP configuration per NIC.
#   - Temp subnet reuse now requires the existing temp subnet to
#     be confirmed empty before being reused. A non-empty existing
#     temp subnet now stops the MoveOut phase with no changes.
#   - MoveOut and MoveBack each end with a logged per-VM result
#     table (Success / Failed-* / Skipped-*) so a partial run is
#     immediately visible, not something to piece together from
#     the log.
#
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string]$SubscriptionName = "",
    [string]$ResourceGroupName = "",
    [string]$VNetName = "",
    [string[]]$SubnetNames = @("subnet1", "subnet2"),
    [string]$TempSubnetName = "subnet-temp-migration",
    [string]$TempSubnetPrefix = "10.150.4.0/27",
    [string]$Phase = "",
    [switch]$Apply
)

# -SubscriptionName, -ResourceGroupName and -VNetName are required, but are not marked
# [Parameter(Mandatory)] per standard 13 (Mandatory rejects "" at runtime). Checked here instead.
$missing = @()
if ($SubscriptionName -eq "")  { $missing += "-SubscriptionName" }
if ($ResourceGroupName -eq "") { $missing += "-ResourceGroupName" }
if ($VNetName -eq "")          { $missing += "-VNetName" }
if ($missing.Count -gt 0) {
    throw ("Missing required parameter(s): {0}" -f ($missing -join ", "))
}

$validPhases = @("MoveOut", "VerifyEmpty", "ClearDelegation", "MoveBack", "Cleanup")
if ($Apply -and ($validPhases -notcontains $Phase)) {
    throw ("With -Apply, -Phase must be one of: {0}" -f ($validPhases -join ", "))
}

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir             = "C:\Logs\Azure"
$StateDir           = "C:\Logs\Azure\State"
$StateFile          = Join-Path $StateDir "subnet-migration-state.json"
$BeforeSnapshotFile = Join-Path $StateDir "nic-snapshot-before.json"
$AfterSnapshotFile  = Join-Path $StateDir "nic-snapshot-after.json"
$ScriptVersion      = "1.8"
# ============================================================


# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
foreach ($dir in @($LogDir, $StateDir)) {
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

function Get-DiscoveredVMs {
    # Discovers, right now, every NIC whose primary IP configuration sits in one of the
    # named subnets of the named VNet, and returns VM name, NIC name, subnet name,
    # current private IP, current allocation method, IP configuration count, and
    # whether a public IP is attached, for each.
    param($VNet, [string[]]$SubnetNames)

    $subnetIds = @{}
    foreach ($name in $SubnetNames) {
        $s = $VNet.Subnets | Where-Object { $_.Name -eq $name }
        if (-not $s) { throw "Subnet '$name' was not found in VNet '$($VNet.Name)'." }
        $subnetIds[$name] = $s.Id
    }

    $allNics = Get-AzNetworkInterface -ResourceGroupName $VNet.ResourceGroupName
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($nic in $allNics) {
        $ipConfig = @($nic.IpConfigurations)[0]
        if (-not $ipConfig -or -not $ipConfig.Subnet) { continue }
        $matchName = $null
        foreach ($name in $SubnetNames) {
            if ($ipConfig.Subnet.Id -eq $subnetIds[$name]) { $matchName = $name; break }
        }
        if (-not $matchName) { continue }

        $vmName = ""
        if ($nic.VirtualMachine -and $nic.VirtualMachine.Id) { $vmName = Get-LastSegment $nic.VirtualMachine.Id }

        $hasPublicIp = $false
        if ($ipConfig.PublicIpAddress -and $ipConfig.PublicIpAddress.Id) { $hasPublicIp = $true }

        $found.Add([pscustomobject]@{
            VM                = $vmName
            NicName           = $nic.Name
            OriginalSubnet    = $matchName
            OriginalIp        = $ipConfig.PrivateIpAddress
            AllocationMethod  = $ipConfig.PrivateIpAllocationMethod
            IpConfigCount     = @($nic.IpConfigurations).Count
            HasPublicIp       = $hasPublicIp
        })
    }
    return $found
}

function Test-SufficientPermission {
    # Checks whether the currently signed-in account has a role assignment of "Owner" or
    # "Contributor" effective at the given resource group - including one inherited from
    # the subscription root, and one granted via AD group membership, not only a role
    # assigned directly to the individual user at the resource group itself.
    #
    # Get-AzRoleAssignment does not support combining -ExpandPrincipalGroups with
    # -ResourceGroupName in a single call (confirmed by a live ParameterBindingException:
    # AmbiguousParameterSet). Instead, every assignment for the account is pulled
    # subscription-wide (where -ExpandPrincipalGroups is valid), and the scope of each
    # one is matched here against the resource group's own scope and the subscription
    # root. This does not check inheritance from a management group above the
    # subscription; it only covers the subscription-root and resource-group levels.
    #
    # This checks for the two common, broad, built-in roles by name. It does NOT inspect
    # custom roles or specific permission strings, so a custom role that grants
    # equivalent rights under a different name would not be recognized here.
    param([string]$ResourceGroupName)

    $account = (Get-AzContext).Account.Id
    $subId   = (Get-AzContext).Subscription.Id
    $sufficientRoles = @("Owner", "Contributor")
    $validScopes = @(
        "/subscriptions/$subId",
        "/subscriptions/$subId/resourceGroups/$ResourceGroupName"
    )

    $assignments = Get-AzRoleAssignment -SignInName $account -ExpandPrincipalGroups -ErrorAction SilentlyContinue
    $matches = @($assignments | Where-Object {
        ($sufficientRoles -contains $_.RoleDefinitionName) -and ($validScopes -contains $_.Scope)
    })

    if ($matches.Count -gt 0) {
        return [pscustomobject]@{ Sufficient = $true; FoundRole = ($matches[0].RoleDefinitionName); Account = $account }
    }
    return [pscustomobject]@{ Sufficient = $false; FoundRole = ""; Account = $account }
}

function Test-SubnetEmpty {
    # Read-only. Returns $true if no NIC in the resource group currently has its primary
    # IP configuration in the named subnet of the given VNet.
    param($VNet, [string]$SubnetName, [string]$ResourceGroupName)

    $s = $VNet.Subnets | Where-Object { $_.Name -eq $SubnetName }
    if (-not $s) { return $true }
    $match = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName | Where-Object {
        $ip = @($_.IpConfigurations)[0]
        $ip -and $ip.Subnet -and $ip.Subnet.Id -eq $s.Id
    }
    return (@($match).Count -eq 0)
}

function Get-NicSnapshot {
    # Captures the specific, meaningful properties of a named NIC: the ones that would
    # reveal whether anything other than the intended subnet/IP round-trip changed.
    # Deliberately does not capture fields that change on every write regardless of
    # content (ETag, ProvisioningState), since comparing those would produce constant
    # false mismatches unrelated to whether anything meaningful actually changed.
    param([string]$NicName, [string]$ResourceGroupName)

    $nic = Get-AzNetworkInterface -Name $NicName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $nic) {
        return [pscustomobject]@{ NicName = $NicName; Found = $false }
    }
    $ipConfig = @($nic.IpConfigurations)[0]
    $nsgId = ""
    if ($nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id) { $nsgId = $nic.NetworkSecurityGroup.Id }
    $pubIpId = ""
    if ($ipConfig -and $ipConfig.PublicIpAddress -and $ipConfig.PublicIpAddress.Id) { $pubIpId = $ipConfig.PublicIpAddress.Id }
    $dnsServers = @()
    if ($nic.DnsSettings -and $nic.DnsSettings.DnsServers) { $dnsServers = @($nic.DnsSettings.DnsServers | Sort-Object) }
    $tagString = ""
    if ($nic.Tag) { $tagString = ($nic.Tag.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";" }

    return [pscustomobject]@{
        NicName                  = $nic.Name
        Found                    = $true
        NsgId                    = $nsgId
        MacAddress               = $nic.MacAddress
        EnableIPForwarding       = $nic.EnableIPForwarding
        EnableAcceleratedNetworking = $nic.EnableAcceleratedNetworking
        DnsServers               = ($dnsServers -join ",")
        Tags                     = $tagString
        SubnetId                 = $(if ($ipConfig -and $ipConfig.Subnet) { $ipConfig.Subnet.Id } else { "" })
        PrivateIpAddress         = $(if ($ipConfig) { $ipConfig.PrivateIpAddress } else { "" })
        PrivateIpAllocationMethod = $(if ($ipConfig) { $ipConfig.PrivateIpAllocationMethod } else { "" })
        PublicIpId               = $pubIpId
    }
}

function Compare-NicSnapshots {
    # Compares two snapshots of the same NIC (as produced by Get-NicSnapshot) field by
    # field, and returns a list of the field names that differ. An empty list means the
    # two snapshots match exactly on every tracked field.
    param($Before, $After)

    $fieldsToCompare = @(
        "NsgId", "MacAddress", "EnableIPForwarding", "EnableAcceleratedNetworking",
        "DnsServers", "Tags", "SubnetId", "PrivateIpAddress", "PrivateIpAllocationMethod", "PublicIpId"
    )
    $diffs = New-Object System.Collections.Generic.List[string]
    foreach ($field in $fieldsToCompare) {
        $beforeVal = "$($Before.$field)"
        $afterVal  = "$($After.$field)"
        if ($beforeVal -ne $afterVal) {
            $diffs.Add("$field (before='$beforeVal', after='$afterVal')")
        }
    }
    return $diffs
}


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log ("Mode: {0}" -f $(if ($Apply) { "APPLY - phase '$Phase' will make changes" } else { "PREVIEW - discovery only, no changes will be made" }))
Write-Log "Target subscription: $SubscriptionName"
Write-Log "Target resource group: $ResourceGroupName"
Write-Log "Target VNet: $VNetName"
Write-Log ("Target subnets: {0}" -f ($SubnetNames -join ", "))
Write-Log "Log file: $logFile"


$originalContext = Get-AzContext
if (-not $originalContext) {
    Write-Log "No Azure session found. Run Connect-AzAccount first, then run this script again." -Level ERROR
    throw "No Azure session found. Run Connect-AzAccount first."
}
Write-Log "Starting in subscription: $($originalContext.Subscription.Name)"


try {
    $sub = Get-AzSubscription | Where-Object { $_.Name -eq $SubscriptionName -and $_.State -eq "Enabled" } | Select-Object -First 1
    if (-not $sub) {
        Write-Log "Subscription '$SubscriptionName' was not found among your enabled subscriptions." -Level ERROR
        throw "Subscription '$SubscriptionName' was not found among your enabled subscriptions."
    }
    $null = Set-AzContext -SubscriptionId $sub.Id -Scope Process -WarningAction SilentlyContinue
    if ((Get-AzContext).Subscription.Id -ne $sub.Id) {
        Write-Log "Could not switch to subscription '$SubscriptionName'. Stopping." -Level ERROR
        throw "Could not switch to subscription '$SubscriptionName'."
    }

    if ($Apply) {
        $permCheck = Test-SufficientPermission -ResourceGroupName $ResourceGroupName
        if ($permCheck.Sufficient) {
            Write-Log "Permission check: '$($permCheck.Account)' has '$($permCheck.FoundRole)' on resource group '$ResourceGroupName'. Proceeding." -Level SUCCESS
        } else {
            Write-Log "Permission check FAILED: '$($permCheck.Account)' does not have Owner or Contributor on resource group '$ResourceGroupName' (checked directly, inherited from subscription, and via group membership). Stopping before any changes are made." -Level ERROR
            throw "Insufficient permissions: '$($permCheck.Account)' does not have Owner or Contributor on '$ResourceGroupName'."
        }
    }

    $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
    $discovered = Get-DiscoveredVMs -VNet $vnet -SubnetNames $SubnetNames

    Write-Log ""
    Write-Log "=== Currently discovered in target subnet(s) ==="
    if ($discovered.Count -eq 0) {
        Write-Log "  Nothing found. Target subnet(s) are already empty."
    } else {
        Write-LogTable -Rows $discovered -Properties @("VM", "NicName", "OriginalSubnet", "OriginalIp", "AllocationMethod", "IpConfigCount", "HasPublicIp")
    }

    $nonStatic = @($discovered | Where-Object { $_.AllocationMethod -ne "Static" })
    if ($nonStatic.Count -gt 0) {
        Write-Log ""
        Write-Log "=== WARNING: the following NIC(s) are NOT Static ===" -Level WARN
        Write-LogTable -Rows $nonStatic -Properties @("VM", "NicName", "AllocationMethod") -Level WARN
    }

    $multiConfig = @($discovered | Where-Object { $_.IpConfigCount -gt 1 })
    if ($multiConfig.Count -gt 0) {
        Write-Log ""
        Write-Log "=== WARNING: the following NIC(s) have more than one IP configuration ===" -Level WARN
        Write-LogTable -Rows $multiConfig -Properties @("VM", "NicName", "IpConfigCount") -Level WARN
    }

    $withPublicIp = @($discovered | Where-Object { $_.HasPublicIp })
    if ($withPublicIp.Count -gt 0) {
        Write-Log ""
        Write-Log "=== WARNING: the following NIC(s) have a public IP attached ===" -Level WARN
        Write-LogTable -Rows $withPublicIp -Properties @("VM", "NicName") -Level WARN
    }

    if ($nonStatic.Count -gt 0 -or $multiConfig.Count -gt 0 -or $withPublicIp.Count -gt 0) {
        Write-Log "MoveOut will refuse to run while any warning above is present. Resolve these first." -Level WARN
    }

    if (-not $Apply) {
        Write-Log ""
        Write-Log "Preview only. No changes were made. Re-run with -Apply and a -Phase to act." -Level WARN
        Write-Log "$scriptName finished"
        exit 0
    }

    switch ($Phase) {

        "MoveOut" {
            if ($nonStatic.Count -gt 0 -or $multiConfig.Count -gt 0 -or $withPublicIp.Count -gt 0) {
                Write-Log "Stopping: see the WARN lines above. No changes made." -Level ERROR
                throw "One or more discovered NICs failed a precondition. See the WARN lines above."
            }
            if ($discovered.Count -eq 0) {
                Write-Log "Nothing discovered in the target subnet(s). Nothing to move. No changes made." -Level WARN
                break
            }

            $existingTemp = $vnet.Subnets | Where-Object { $_.Name -eq $TempSubnetName }
            if ($existingTemp) {
                $tempEmpty = Test-SubnetEmpty -VNet $vnet -SubnetName $TempSubnetName -ResourceGroupName $ResourceGroupName
                if (-not $tempEmpty) {
                    Write-Log "Temporary subnet '$TempSubnetName' already exists AND already has NIC(s) in it. Refusing to reuse it blindly. Investigate manually. No changes made." -Level ERROR
                    throw "Temporary subnet '$TempSubnetName' is not empty."
                }
                Write-Log "Temporary subnet '$TempSubnetName' already exists and is confirmed empty. Reusing it."
            } else {
                Write-Log "Creating temporary subnet '$TempSubnetName' ($TempSubnetPrefix)..."
                Add-AzVirtualNetworkSubnetConfig -Name $TempSubnetName -AddressPrefix $TempSubnetPrefix -VirtualNetwork $vnet | Out-Null
                Set-AzVirtualNetwork -VirtualNetwork $vnet | Out-Null
                $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
                Write-Log "Temporary subnet created." -Level SUCCESS
            }
            $tempSubnet = ($vnet.Subnets | Where-Object { $_.Name -eq $TempSubnetName })

            $discovered | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile
            Write-Log "Saved discovered VM/NIC state to $StateFile before making any changes." -Level SUCCESS

            Write-Log "Capturing BEFORE configuration snapshot for every discovered NIC..."
            $beforeSnaps = @($discovered | ForEach-Object { Get-NicSnapshot -NicName $_.NicName -ResourceGroupName $ResourceGroupName })
            $beforeSnaps | ConvertTo-Json -Depth 5 | Set-Content -Path $BeforeSnapshotFile
            Write-Log "Saved BEFORE snapshot to $BeforeSnapshotFile." -Level SUCCESS

            $results = New-Object System.Collections.Generic.List[object]
            foreach ($entry in $discovered) {
                $status = "Unknown"
                $detail = ""
                $stopped = $false

                try {
                    Write-Log "Stopping VM '$($entry.VM)'..."
                    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $entry.VM -Force -ErrorAction Stop | Out-Null
                    $stopped = $true
                } catch {
                    $status = "Failed-NeverStopped"
                    $detail = $_.Exception.Message
                    Write-Log "Failed to stop VM '$($entry.VM)': $detail" -Level ERROR
                    $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
                    continue
                }

                try {
                    $nic = Get-AzNetworkInterface -Name $entry.NicName -ResourceGroupName $ResourceGroupName
                    $nic.IpConfigurations[0].Subnet.Id = $tempSubnet.Id
                    $nic.IpConfigurations[0].PrivateIpAllocationMethod = "Dynamic"
                    Set-AzNetworkInterface -NetworkInterface $nic -ErrorAction Stop | Out-Null
                    Write-Log "Moved NIC '$($entry.NicName)' (VM '$($entry.VM)') to temp subnet. VM left stopped." -Level SUCCESS
                    $status = "Success"
                } catch {
                    $detail = $_.Exception.Message
                    Write-Log "Failed to move NIC for VM '$($entry.VM)': $detail" -Level ERROR
                    if ($stopped) {
                        Write-Log "VM '$($entry.VM)' was already stopped. Its NIC was never successfully changed, so restarting it in its original subnet..." -Level WARN
                        try {
                            Start-AzVM -ResourceGroupName $ResourceGroupName -Name $entry.VM -ErrorAction Stop | Out-Null
                            $status = "Failed-RolledBack"
                            Write-Log "VM '$($entry.VM)' restarted successfully in its original subnet." -Level SUCCESS
                        } catch {
                            $status = "Failed-StoppedAndNotRestarted"
                            $detail = "$detail | Restart also failed: $($_.Exception.Message)"
                            Write-Log "VM '$($entry.VM)' could not be restarted either. Manual attention needed." -Level ERROR
                        }
                    } else {
                        $status = "Failed-NeverStopped"
                    }
                }
                $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
            }

            Write-Log ""
            Write-Log "=== MoveOut results ==="
            Write-LogTable -Rows $results -Properties @("VM", "Status", "Detail")
            $okCount = @($results | Where-Object { $_.Status -eq "Success" }).Count
            Write-Log ""
            Write-Log "MoveOut complete. $okCount of $($discovered.Count) VM(s) successfully moved to '$TempSubnetName' and left stopped." -Level SUCCESS
            if ($okCount -lt $discovered.Count) {
                Write-Log "Not all VMs succeeded. Review the table above before proceeding to VerifyEmpty / ClearDelegation." -Level WARN
            } else {
                Write-Log "Next: run -Phase VerifyEmpty, then -Phase ClearDelegation." -Level WARN
            }
        }

        "VerifyEmpty" {
            if ($discovered.Count -eq 0) {
                Write-Log "Confirmed: target subnet(s) are empty." -Level SUCCESS
                Write-Log "Next: run -Phase ClearDelegation." -Level WARN
            } else {
                Write-Log "NOT empty. $($discovered.Count) NIC(s) still present in the target subnet(s). Do not proceed to ClearDelegation." -Level ERROR
                Write-Log "Review the MoveOut results table, resolve the remaining NIC(s), then re-run -Phase VerifyEmpty." -Level WARN
            }
        }

        "ClearDelegation" {
            if ($discovered.Count -gt 0) {
                Write-Log "Target subnet(s) are not empty. Refusing to clear delegation. Run -Phase MoveOut (and confirm with -Phase VerifyEmpty) first." -Level ERROR
                throw "Target subnet(s) are not empty. No changes made."
            }
            foreach ($name in $SubnetNames) {
                $s = $vnet.Subnets | Where-Object { $_.Name -eq $name }
                $before = @($s.Delegations | ForEach-Object { $_.Name }) -join ", "
                $s.Delegations.Clear()
                Write-Log "Cleared delegation(s) on '$name' (was: $(if ($before) { $before } else { '(none)' }))."
            }
            Set-AzVirtualNetwork -VirtualNetwork $vnet | Out-Null

            $vnetCheck = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroupName
            $stillDelegated = @($vnetCheck.Subnets | Where-Object { $SubnetNames -contains $_.Name -and @($_.Delegations).Count -gt 0 })
            if ($stillDelegated.Count -gt 0) {
                Write-Log "One or more target subnets still show a delegation after the update. Check manually." -Level ERROR
            } else {
                Write-Log "Confirmed: no delegations remain on $($SubnetNames -join ', ')." -Level SUCCESS
                Write-Log "Next: run -Phase MoveBack." -Level WARN
            }
        }

        "MoveBack" {
            if (-not (Test-Path $StateFile)) {
                Write-Log "No state file found at $StateFile. Cannot determine what to move back. Nothing changed." -Level ERROR
                throw "No state file found at $StateFile."
            }
            # Three fully separate statements, not two. On PowerShell 5.1 Desktop, @() wrapped
            # directly around a live "... | ConvertFrom-Json" pipe has been confirmed, by direct
            # reproduction, to collapse a multi-element JSON array into one element whose
            # properties are space-joined strings of every entry's values - even when the
            # Get-Content call feeding that pipe is on its own prior line. @() only behaves
            # correctly here when it wraps an already-materialized variable, not a live pipe.
            $rawStateJson = Get-Content -Path $StateFile -Raw
            $parsedState = $rawStateJson | ConvertFrom-Json
            $savedState = @($parsedState)
            Write-Log "Loaded $($savedState.Count) VM(s) from saved state ($StateFile)."

            $tempSubnetObj = $vnet.Subnets | Where-Object { $_.Name -eq $TempSubnetName }

            $results = New-Object System.Collections.Generic.List[object]
            foreach ($entry in $savedState) {
                $status = "Unknown"
                $detail = ""

                $currentNic = Get-AzNetworkInterface -Name $entry.NicName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                if (-not $currentNic) {
                    $status = "Skipped-NicNotFound"
                    $detail = "NIC '$($entry.NicName)' no longer exists."
                    Write-Log "Skipping VM '$($entry.VM)': $detail" -Level WARN
                    $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
                    continue
                }
                $currentIpConfig = @($currentNic.IpConfigurations)[0]
                $isInTemp = $tempSubnetObj -and $currentIpConfig -and $currentIpConfig.Subnet -and ($currentIpConfig.Subnet.Id -eq $tempSubnetObj.Id)
                if (-not $isInTemp) {
                    $status = "Skipped-NotInTempSubnet"
                    $detail = "NIC '$($entry.NicName)' is not currently in '$TempSubnetName'. It may have already been moved, or never moved. Not touching it."
                    Write-Log "Skipping VM '$($entry.VM)': $detail" -Level WARN
                    $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
                    continue
                }

                $targetSubnet = $vnet.Subnets | Where-Object { $_.Name -eq $entry.OriginalSubnet }
                if (-not $targetSubnet) {
                    $status = "Failed-OriginalSubnetMissing"
                    $detail = "Original subnet '$($entry.OriginalSubnet)' was not found."
                    Write-Log "Skipping VM '$($entry.VM)': $detail" -Level ERROR
                    $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
                    continue
                }

                $subnetMoveOk = $false
                try {
                    $nic = Get-AzNetworkInterface -Name $entry.NicName -ResourceGroupName $ResourceGroupName
                    $nic.IpConfigurations[0].Subnet.Id = $targetSubnet.Id
                    $nic.IpConfigurations[0].PrivateIpAllocationMethod = "Dynamic"
                    Set-AzNetworkInterface -NetworkInterface $nic -ErrorAction Stop | Out-Null
                    $subnetMoveOk = $true
                } catch {
                    $status = "Failed-SubnetMoveBack"
                    $detail = $_.Exception.Message
                    Write-Log "Failed to move NIC for VM '$($entry.VM)' back to '$($entry.OriginalSubnet)': $detail. VM left stopped in '$TempSubnetName' (safe, same state as after MoveOut)." -Level ERROR
                    $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
                    continue
                }

                $staticOk = $false
                try {
                    $nic = Get-AzNetworkInterface -Name $entry.NicName -ResourceGroupName $ResourceGroupName
                    $nic.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
                    $nic.IpConfigurations[0].PrivateIpAddress = $entry.OriginalIp
                    Set-AzNetworkInterface -NetworkInterface $nic -ErrorAction Stop | Out-Null
                    $staticOk = $true
                    Write-Log "Restored NIC '$($entry.NicName)' to '$($entry.OriginalSubnet)' at $($entry.OriginalIp)." -Level SUCCESS
                } catch {
                    $detail = $_.Exception.Message
                    Write-Log "Subnet move for VM '$($entry.VM)' succeeded, but restoring the static IP $($entry.OriginalIp) failed: $detail" -Level ERROR
                }

                try {
                    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $entry.VM -ErrorAction Stop | Out-Null
                    if ($staticOk) {
                        $status = "Success"
                        Write-Log "Started VM '$($entry.VM)'." -Level SUCCESS
                    } else {
                        $status = "Failed-StartedWithWrongIP"
                        $detail = "$detail | VM started but is NOT on its original static IP ($($entry.OriginalIp)). Correct manually."
                        Write-Log "VM '$($entry.VM)' started, but is NOT on its original IP. Manual correction needed." -Level ERROR
                    }
                } catch {
                    $status = "Failed-NicCorrectButNotStarted"
                    $detail = "$detail | Start-AzVM failed: $($_.Exception.Message)"
                    Write-Log "NIC for VM '$($entry.VM)' is correctly configured, but the VM failed to start: $($_.Exception.Message)" -Level ERROR
                }

                $results.Add([pscustomobject]@{ VM = $entry.VM; Status = $status; Detail = $detail })
            }

            Write-Log ""
            Write-Log "=== MoveBack results ==="
            Write-LogTable -Rows $results -Properties @("VM", "Status", "Detail")
            $okCount = @($results | Where-Object { $_.Status -eq "Success" }).Count
            Write-Log ""
            Write-Log "MoveBack complete. $okCount of $($savedState.Count) VM(s) fully restored." -Level SUCCESS

            if (-not (Test-Path $BeforeSnapshotFile)) {
                Write-Log "No BEFORE snapshot found at $BeforeSnapshotFile. Skipping configuration comparison." -Level WARN
            } else {
                Write-Log ""
                Write-Log "Capturing AFTER configuration snapshot for every VM in saved state..."
                $afterSnaps = @($savedState | ForEach-Object { Get-NicSnapshot -NicName $_.NicName -ResourceGroupName $ResourceGroupName })
                $afterSnaps | ConvertTo-Json -Depth 5 | Set-Content -Path $AfterSnapshotFile
                Write-Log "Saved AFTER snapshot to $AfterSnapshotFile." -Level SUCCESS

                # Same corrected three-statement fix as the state file load above.
                $rawBeforeJson = Get-Content -Path $BeforeSnapshotFile -Raw
                $parsedBefore = $rawBeforeJson | ConvertFrom-Json
                $beforeSnaps = @($parsedBefore)
                Write-Log ""
                Write-Log "=== Configuration comparison: BEFORE (MoveOut) vs AFTER (MoveBack) ==="
                $compareResults = New-Object System.Collections.Generic.List[object]
                foreach ($beforeSnap in $beforeSnaps) {
                    $afterSnap = $afterSnaps | Where-Object { $_.NicName -eq $beforeSnap.NicName } | Select-Object -First 1
                    if (-not $afterSnap) {
                        Write-Log "NIC '$($beforeSnap.NicName)': no AFTER snapshot found (NIC may have been skipped above)." -Level WARN
                        $compareResults.Add([pscustomobject]@{ NicName = $beforeSnap.NicName; Result = "NO-AFTER-SNAPSHOT"; Fields = "" })
                        continue
                    }
                    if (-not $beforeSnap.Found -or -not $afterSnap.Found) {
                        Write-Log "NIC '$($beforeSnap.NicName)': NIC missing in before or after snapshot." -Level ERROR
                        $compareResults.Add([pscustomobject]@{ NicName = $beforeSnap.NicName; Result = "MISMATCH"; Fields = "NIC not found in one of the snapshots" })
                        continue
                    }
                    $diffs = Compare-NicSnapshots -Before $beforeSnap -After $afterSnap
                    if ($diffs.Count -eq 0) {
                        Write-Log "NIC '$($beforeSnap.NicName)': MATCH. All tracked fields identical to before MoveOut." -Level SUCCESS
                        $compareResults.Add([pscustomobject]@{ NicName = $beforeSnap.NicName; Result = "MATCH"; Fields = "" })
                    } else {
                        Write-Log "NIC '$($beforeSnap.NicName)': MISMATCH. $($diffs -join ' | ')" -Level ERROR
                        $compareResults.Add([pscustomobject]@{ NicName = $beforeSnap.NicName; Result = "MISMATCH"; Fields = ($diffs -join "; ") })
                    }
                }
                Write-Log ""
                Write-Log "=== Comparison summary ==="
                Write-LogTable -Rows $compareResults -Properties @("NicName", "Result", "Fields")
                $mismatchCount = @($compareResults | Where-Object { $_.Result -ne "MATCH" }).Count
                if ($mismatchCount -eq 0) {
                    Write-Log "All NICs confirmed identical to their pre-migration configuration." -Level SUCCESS
                } else {
                    Write-Log "$mismatchCount NIC(s) did not match their pre-migration configuration. Review the table above." -Level ERROR
                }
            }

            if ($okCount -lt $savedState.Count) {
                Write-Log "Not all VMs fully succeeded. Review the table above before running -Phase Cleanup." -Level WARN
            } else {
                Write-Log "Next: confirm all VMs are healthy, then run -Phase Cleanup to remove the temp subnet." -Level WARN
            }
        }

        "Cleanup" {
            $tempEmpty = Test-SubnetEmpty -VNet $vnet -SubnetName $TempSubnetName -ResourceGroupName $ResourceGroupName
            if (-not $tempEmpty) {
                Write-Log "Temp subnet '$TempSubnetName' still has NIC(s) in it. Refusing to remove it. Run -Phase MoveBack first." -Level ERROR
                throw "Temp subnet is not empty. No changes made."
            }
            Remove-AzVirtualNetworkSubnetConfig -Name $TempSubnetName -VirtualNetwork $vnet | Out-Null
            Set-AzVirtualNetwork -VirtualNetwork $vnet | Out-Null
            Write-Log "Removed temporary subnet '$TempSubnetName'." -Level SUCCESS
            Write-Log ""
            Write-Log "=== All phases complete. Recommended final checks ===" -Level WARN
            Write-Log "  1. Confirm the target subnet(s) now accept new VM/NIC creation (the original problem this script was built to fix)."
            Write-Log "  2. If you have not already, review the MoveBack comparison summary and confirm every NIC showed MATCH."
            Write-Log "  3. Confirm each VM is reachable on its original IP and that applications/services on it are behaving normally."
        }
    }

} finally {
    $null = Set-AzContext -Context $originalContext -Scope Process -WarningAction SilentlyContinue
    Write-Log "Session context restored to: $($originalContext.Subscription.Name)" -Level SUCCESS
}

Write-Log "$scriptName finished"

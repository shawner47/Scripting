# ============================================================
# Get-AzureGovernanceReport_v1.0.ps1
# Version 1.0
#
# Reports on Azure governance and inventory across an entire tenant:
# subscriptions, management group hierarchy, resource groups,
# resources (by type), RBAC role assignments, and Azure Policy
# assignments + compliance state. Read-only -- no changes are made to
# any subscription, resource, role assignment, or policy.
#
# DATA SOURCE:
#   Almost everything here comes from Azure Resource Graph
#   (Search-AzGraph, Az.ResourceGraph module) rather than looping
#   individual cmdlets (Get-AzRoleAssignment, Get-AzPolicyAssignment,
#   etc.) per subscription -- Resource Graph indexes the whole tenant
#   centrally, including RBAC (AuthorizationResources table) and
#   Policy (PolicyResources table), not just plain resources. This is
#   the same "one bulk query beats many individual calls" principle
#   used elsewhere for speed at scale. Management group hierarchy is
#   the one piece that comes from a dedicated cmdlet
#   (Get-AzManagementGroup), since Resource Graph doesn't expose the
#   parent/child tree structure itself.
#
# PERMISSIONS NOTE:
#   Entra ID roles (including Global Administrator) and Azure RBAC are
#   separate, independently managed authorization systems -- being
#   Global Admin does NOT automatically grant visibility into Azure
#   subscriptions, resources, RBAC, or policy. If Get-AzSubscription
#   or the queries below return nothing or an incomplete picture, the
#   fix is Entra ID > Properties > "Access management for Azure
#   resources" (Yes), which assigns User Access Administrator at the
#   tenant root management group scope -- that role's actions include
#   */read, which is exactly the visibility this report needs.
#   Microsoft's own guidance is to treat this as a temporary elevation
#   and toggle it back off once you're done, since it's a
#   high-privilege state.
#
# SCOPE NOTE:
#   This reports on ONE tenant at a time -- whichever tenant the
#   current Az session is connected to, or the one specified with
#   -TenantId. If you administer multiple separate tenants, run this
#   once per tenant rather than expecting one run to aggregate across
#   all of them.
#
# WHAT THIS DOES NOT ANSWER:
#   Whether a formal "landing zone" (per the Cloud Adoption Framework /
#   Azure Landing Zones reference pattern) is implemented is not a
#   yes/no fact any API exposes -- it's inferred from whether the
#   management group hierarchy and policy assignments resemble the
#   reference pattern, which is a judgment call on the data, not
#   something this script asserts. The ManagementGroups.csv and
#   PolicyAssignments.csv output give you the raw evidence to make
#   that call yourself.
#
# PARAMETERS:
#   -OutputPath            Folder for the CSV reports.
#                          Default: C:\Reports\AzureGovernance
#   -TenantId              Connect to a specific tenant instead of
#                          whatever the current/default Az context is.
#   -SkipPolicyCompliance  Skip the policy compliance-state summary
#                          (PolicyResources/PolicyStates). Assignments
#                          themselves are still reported; only the
#                          compliant/non-compliant resource counts are
#                          skipped. Use this for a faster run on a
#                          large estate if you only need to know what's
#                          assigned, not current compliance.
#
# OUTPUT (all in one timestamped run, in -OutputPath):
#   yyyy.MM.dd.HHmmss.Subscriptions.csv
#   yyyy.MM.dd.HHmmss.ManagementGroups.csv
#   yyyy.MM.dd.HHmmss.ResourceGroups.csv
#   yyyy.MM.dd.HHmmss.Resources.csv
#   yyyy.MM.dd.HHmmss.RoleAssignments.csv
#   yyyy.MM.dd.HHmmss.PolicyAssignments.csv
#   yyyy.MM.dd.HHmmss.PolicyComplianceSummary.csv   (unless -SkipPolicyCompliance)
#   Console summary: counts for each category, top resource types,
#   and (unless skipped) overall compliance percentage.
#
# EXAMPLES:
#   .\Get-AzureGovernanceReport_v1.0.ps1
#   .\Get-AzureGovernanceReport_v1.0.ps1 -TenantId "11111111-2222-3333-4444-555555555555"
#   .\Get-AzureGovernanceReport_v1.0.ps1 -SkipPolicyCompliance
#
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
Param(
    [string]$OutputPath,
    [string]$TenantId,
    [switch]$SkipPolicyCompliance
)

# ============================================================
# CONFIGURATION
# ============================================================
$Script:Config = @{
    LogDirectory    = 'C:\Logs\AzureGovernanceReport'
    OutputDirectory = 'C:\Reports\AzureGovernance'
}
# ============================================================

if (-not $OutputPath) { $OutputPath = $Script:Config.OutputDirectory }

# ------------------------------------------------------------
# Setup: create directories first (before logging exists)
# ------------------------------------------------------------
foreach ($dir in @($Script:Config.LogDirectory, $OutputPath)) {
    if (-not (Test-Path $dir)) {
        try {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "FATAL: Could not create required directory '$dir': $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
}

$runStamp = Get-Date -Format 'yyyy.MM.dd.HHmmss'
$Script:LogFile = Join-Path $Script:Config.LogDirectory "Get-AzureGovernanceReport_$runStamp.log"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $Script:LogFile -Value $line
}

Write-Log "===== Get-AzureGovernanceReport_v1.0.ps1 started ====="
Write-Log "Output path          : $OutputPath"
Write-Log "Skip policy compliance: $SkipPolicyCompliance"

# ------------------------------------------------------------
# Module checks
# ------------------------------------------------------------
foreach ($mod in @('Az.Accounts','Az.ResourceGraph','Az.Resources')) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Log "$mod module is not installed. Run: Install-Module $mod -Scope CurrentUser" -Level ERROR
        throw "$mod module not installed."
    }
}

# ------------------------------------------------------------
# Connect to Azure
# ------------------------------------------------------------
try {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or ($TenantId -and $context.Tenant.Id -ne $TenantId)) {
        Write-Log "No existing Az session found (or a different tenant was requested). Connecting..."
        if ($TenantId) {
            Connect-AzAccount -Tenant $TenantId -ErrorAction Stop | Out-Null
        } else {
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }
        $context = Get-AzContext
        Write-Log "Connected to Azure. Tenant: $($context.Tenant.Id) | Account: $($context.Account.Id)" -Level SUCCESS
    } else {
        Write-Log "Using existing Az session. Tenant: $($context.Tenant.Id) | Account: $($context.Account.Id)"
    }
} catch {
    Write-Log "Failed to connect to Azure: $($_.Exception.Message)" -Level ERROR
    throw
}

# ------------------------------------------------------------
# Helper: paginated Resource Graph query. Resource Graph caps at 1000
# rows per response regardless of query -- confirmed against the
# cmdlet's own documentation, not assumed. -UseTenantScope ensures the
# query covers every subscription in the tenant the account can see,
# not just whatever the current subscription context happens to be.
# ------------------------------------------------------------
function Invoke-PagedGraphQuery {
    param([Parameter(Mandatory)][string]$Query)
    $all = @()
    $skipToken = $null
    do {
        try {
            if ($skipToken) {
                $response = Search-AzGraph -Query $Query -SkipToken $skipToken -First 1000 -ErrorAction Stop
            } else {
                $response = Search-AzGraph -Query $Query -UseTenantScope -First 1000 -ErrorAction Stop
            }
        } catch {
            Write-Log "  Resource Graph query failed: $($_.Exception.Message)" -Level ERROR
            throw
        }
        $all += $response
        $skipToken = $response.SkipToken
    } while ($skipToken)
    return $all
}

# ------------------------------------------------------------
# Helper: classify an RBAC/Policy assignment scope string into a
# governance level, so RoleAssignments.csv / PolicyAssignments.csv
# are readable without manually parsing ARM resource ID strings.
# ------------------------------------------------------------
function Get-ScopeType {
    param([string]$Scope)
    if (-not $Scope) { return "Unknown" }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/') { return "ManagementGroup" }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+/.+') { return "Resource" }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return "ResourceGroup" }
    if ($Scope -match '^/subscriptions/[^/]+$') { return "Subscription" }
    return "Unknown"
}

$results = @{}   # bucket for every dataset this run collects, keyed by name


# ============================================================
# PHASE 1: Subscriptions
# ============================================================
Write-Log "" ; Write-Log "Phase 1: Subscriptions" -Level INFO
try {
    $subs = @(Get-AzSubscription -TenantId $context.Tenant.Id -ErrorAction Stop)
    $results.Subscriptions = $subs | Select-Object `
        @{N='SubscriptionId'; E={$_.Id}}, `
        @{N='Name'; E={$_.Name}}, `
        @{N='State'; E={$_.State}}, `
        @{N='TenantId'; E={$_.TenantId}}
    Write-Log "  $($results.Subscriptions.Count) subscription(s) found."
} catch {
    Write-Log "  Failed to fetch subscriptions: $($_.Exception.Message)" -Level ERROR
    $results.Subscriptions = @()
}
$subNameById = @{}
foreach ($s in $results.Subscriptions) { $subNameById[$s.SubscriptionId] = $s.Name }


# ============================================================
# PHASE 2: Management group hierarchy
# ============================================================
Write-Log "" ; Write-Log "Phase 2: Management groups" -Level INFO
try {
    $mgList = @(Get-AzManagementGroup -ErrorAction Stop)
    Write-Log "  $($mgList.Count) management group(s) visible to this account."
    $mgRows = @()
    foreach ($mg in $mgList) {
        try {
            $detail = Get-AzManagementGroup -GroupName $mg.Name -Expand -ErrorAction Stop
            $mgRows += [PSCustomObject]@{
                Id             = $detail.Id
                Name           = $detail.Name
                DisplayName    = $detail.DisplayName
                ParentId       = $detail.ParentId
                ParentDisplayName = $detail.ParentDisplayName
                ChildCount     = @($detail.Children).Count
            }
        } catch {
            Write-Log "    [WARN] Could not expand management group '$($mg.Name)': $($_.Exception.Message)" -Level WARN
        }
    }
    $results.ManagementGroups = $mgRows
} catch {
    Write-Log "  Failed to fetch management groups: $($_.Exception.Message)" -Level ERROR
    Write-Log "  (If this is empty/incomplete and you're a Global Admin, see the PERMISSIONS NOTE in this script's header -- Entra role alone does not grant Azure RBAC visibility.)" -Level WARN
    $results.ManagementGroups = @()
}


# ============================================================
# PHASE 3: Resource groups (via Resource Graph's ResourceContainers
# table, which includes empty resource groups too -- unlike deriving
# the list from the Resources table, which would miss any resource
# group with zero resources in it)
# ============================================================
Write-Log "" ; Write-Log "Phase 3: Resource groups" -Level INFO
try {
    $rgQuery = "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' " +
               "| project SubscriptionId=subscriptionId, ResourceGroupName=name, Location=location, Tags=tostring(tags)"
    $rgRaw = Invoke-PagedGraphQuery -Query $rgQuery
    $results.ResourceGroups = $rgRaw | ForEach-Object {
        [PSCustomObject]@{
            SubscriptionId    = $_.SubscriptionId
            SubscriptionName  = if ($subNameById.ContainsKey($_.SubscriptionId)) { $subNameById[$_.SubscriptionId] } else { "" }
            ResourceGroupName = $_.ResourceGroupName
            Location          = $_.Location
            Tags              = $_.Tags
        }
    }
    Write-Log "  $($results.ResourceGroups.Count) resource group(s) found."
} catch {
    Write-Log "  Failed to fetch resource groups: $($_.Exception.Message)" -Level ERROR
    $results.ResourceGroups = @()
}


# ============================================================
# PHASE 4: Resources
# ============================================================
Write-Log "" ; Write-Log "Phase 4: Resources" -Level INFO
try {
    $resQuery = "Resources | project SubscriptionId=subscriptionId, ResourceGroup=resourceGroup, " +
                "Name=name, Type=type, Location=location, Tags=tostring(tags), ResourceId=id"
    $resRaw = Invoke-PagedGraphQuery -Query $resQuery
    $results.Resources = $resRaw | ForEach-Object {
        [PSCustomObject]@{
            SubscriptionId   = $_.SubscriptionId
            SubscriptionName = if ($subNameById.ContainsKey($_.SubscriptionId)) { $subNameById[$_.SubscriptionId] } else { "" }
            ResourceGroup    = $_.ResourceGroup
            Name             = $_.Name
            Type             = $_.Type
            Location         = $_.Location
            Tags             = $_.Tags
            ResourceId       = $_.ResourceId
        }
    }
    Write-Log "  $($results.Resources.Count) resource(s) found."
} catch {
    Write-Log "  Failed to fetch resources: $($_.Exception.Message)" -Level ERROR
    $results.Resources = @()
}


# ============================================================
# PHASE 5: RBAC role assignments
# ============================================================
Write-Log "" ; Write-Log "Phase 5: RBAC role assignments" -Level INFO
try {
    $roleDefQuery = "AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' " +
                    "| extend RoleName=tostring(properties.roleName) | project RoleDefinitionId=id, RoleName"
    $roleDefRaw = Invoke-PagedGraphQuery -Query $roleDefQuery
    $roleNameById = @{}
    foreach ($rd in $roleDefRaw) { $roleNameById[$rd.RoleDefinitionId.ToLowerInvariant()] = $rd.RoleName }
    Write-Log "  $($roleDefRaw.Count) role definition(s) found (for name resolution)."

    $raQuery = "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' " +
               "| extend PrincipalId=tostring(properties.principalId), PrincipalType=tostring(properties.principalType), " +
               "RoleDefinitionId=tostring(properties.roleDefinitionId), Scope=tostring(properties.scope) " +
               "| project PrincipalId, PrincipalType, RoleDefinitionId, Scope, ResourceId=id"
    $raRaw = Invoke-PagedGraphQuery -Query $raQuery
    $results.RoleAssignments = $raRaw | ForEach-Object {
        $roleKey = if ($_.RoleDefinitionId) { $_.RoleDefinitionId.ToLowerInvariant() } else { $null }
        [PSCustomObject]@{
            PrincipalId     = $_.PrincipalId
            PrincipalType   = $_.PrincipalType
            RoleDefinitionId= $_.RoleDefinitionId
            RoleName        = if ($roleKey -and $roleNameById.ContainsKey($roleKey)) { $roleNameById[$roleKey] } else { "" }
            Scope           = $_.Scope
            ScopeType       = Get-ScopeType -Scope $_.Scope
        }
    }
    Write-Log "  $($results.RoleAssignments.Count) role assignment(s) found."
} catch {
    Write-Log "  Failed to fetch RBAC role assignments: $($_.Exception.Message)" -Level ERROR
    $results.RoleAssignments = @()
}


# ============================================================
# PHASE 6: Policy assignments and (optionally) compliance summary
# ============================================================
Write-Log "" ; Write-Log "Phase 6: Policy assignments" -Level INFO
try {
    $paQuery = "PolicyResources | where type =~ 'microsoft.authorization/policyassignments' " +
               "| extend DisplayName=tostring(properties.displayName), PolicyDefinitionId=tostring(properties.policyDefinitionId), " +
               "Scope=tostring(properties.scope), EnforcementMode=tostring(properties.enforcementMode) " +
               "| project Name=name, DisplayName, PolicyDefinitionId, Scope, EnforcementMode, ResourceId=id"
    $paRaw = Invoke-PagedGraphQuery -Query $paQuery
    $results.PolicyAssignments = $paRaw | ForEach-Object {
        [PSCustomObject]@{
            Name             = $_.Name
            DisplayName      = $_.DisplayName
            PolicyDefinitionId = $_.PolicyDefinitionId
            Scope            = $_.Scope
            ScopeType        = Get-ScopeType -Scope $_.Scope
            EnforcementMode  = $_.EnforcementMode
            ResourceId       = $_.ResourceId
        }
    }
    Write-Log "  $($results.PolicyAssignments.Count) policy assignment(s) found."
} catch {
    Write-Log "  Failed to fetch policy assignments: $($_.Exception.Message)" -Level ERROR
    $results.PolicyAssignments = @()
}

if (-not $SkipPolicyCompliance) {
    Write-Log "Phase 6b: Policy compliance summary" -Level INFO
    try {
        $pcQuery = "PolicyResources | where type =~ 'microsoft.policyinsights/policystates' " +
                   "| extend ComplianceState=tostring(properties.complianceState), PolicyAssignmentId=tostring(properties.policyAssignmentId) " +
                   "| summarize ResourceCount=count() by PolicyAssignmentId, ComplianceState"
        $pcRaw = Invoke-PagedGraphQuery -Query $pcQuery
        $assignmentNameById = @{}
        foreach ($pa in $results.PolicyAssignments) {
            if ($pa.ResourceId) { $assignmentNameById[$pa.ResourceId.ToLowerInvariant()] = $pa.DisplayName }
        }
        $results.PolicyComplianceSummary = $pcRaw | ForEach-Object {
            $idKey = if ($_.PolicyAssignmentId) { $_.PolicyAssignmentId.ToLowerInvariant() } else { $null }
            [PSCustomObject]@{
                PolicyAssignmentId          = $_.PolicyAssignmentId
                PolicyAssignmentDisplayName = if ($idKey -and $assignmentNameById.ContainsKey($idKey)) { $assignmentNameById[$idKey] } else { "" }
                ComplianceState             = $_.ComplianceState
                ResourceCount               = $_.ResourceCount
            }
        }
        Write-Log "  Compliance summary built across $($results.PolicyComplianceSummary.Count) assignment/state combination(s)."
    } catch {
        Write-Log "  Failed to fetch policy compliance summary: $($_.Exception.Message)" -Level ERROR
        $results.PolicyComplianceSummary = @()
    }
} else {
    Write-Log "  Skipped (per -SkipPolicyCompliance)."
    $results.PolicyComplianceSummary = @()
}


# ============================================================
# Output: CSVs
# ============================================================
Write-Log "" ; Write-Log "Writing CSV reports..." -Level INFO

$outputs = @(
    @{ Name = "Subscriptions";            Data = $results.Subscriptions }
    @{ Name = "ManagementGroups";         Data = $results.ManagementGroups }
    @{ Name = "ResourceGroups";           Data = $results.ResourceGroups }
    @{ Name = "Resources";                Data = $results.Resources }
    @{ Name = "RoleAssignments";          Data = $results.RoleAssignments }
    @{ Name = "PolicyAssignments";        Data = $results.PolicyAssignments }
)
if (-not $SkipPolicyCompliance) {
    $outputs += @{ Name = "PolicyComplianceSummary"; Data = $results.PolicyComplianceSummary }
}

$writtenPaths = @()
foreach ($o in $outputs) {
    $path = Join-Path $OutputPath "$runStamp.$($o.Name).csv"
    try {
        if ($o.Data.Count -gt 0) {
            $o.Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        } else {
            # Write a header-only file rather than nothing, so an empty
            # result is visibly "checked, found zero" rather than
            # indistinguishable from "this report never ran".
            "" | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        }
        Write-Log "  $($o.Name): $($o.Data.Count) row(s) -> $path" -Level SUCCESS
        $writtenPaths += $path
    } catch {
        Write-Log "  Failed to write $($o.Name).csv: $($_.Exception.Message)" -Level ERROR
    }
}


# ============================================================
# Summary
# ============================================================
Write-Log "" ; Write-Log "----- Summary -----"
Write-Log "Subscriptions      : $($results.Subscriptions.Count)"
Write-Log "Management groups  : $($results.ManagementGroups.Count)"
Write-Log "Resource groups    : $($results.ResourceGroups.Count)"
Write-Log "Resources          : $($results.Resources.Count)"
Write-Log "Role assignments   : $($results.RoleAssignments.Count)"
Write-Log "Policy assignments : $($results.PolicyAssignments.Count)"

if ($results.Resources.Count -gt 0) {
    Write-Log ""
    Write-Log "Top 10 resource types:"
    $results.Resources | Group-Object Type | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Log ("  {0,-6} {1}" -f $_.Count, $_.Name)
    }
}

if (-not $SkipPolicyCompliance -and $results.PolicyComplianceSummary.Count -gt 0) {
    $compliant    = ($results.PolicyComplianceSummary | Where-Object { $_.ComplianceState -eq "Compliant" } | Measure-Object -Property ResourceCount -Sum).Sum
    $nonCompliant = ($results.PolicyComplianceSummary | Where-Object { $_.ComplianceState -eq "NonCompliant" } | Measure-Object -Property ResourceCount -Sum).Sum
    $totalEvaluated = $compliant + $nonCompliant
    Write-Log ""
    if ($totalEvaluated -gt 0) {
        $pct = [math]::Round(($compliant / $totalEvaluated) * 100, 1)
        Write-Log "Policy compliance  : $pct% ($compliant compliant / $nonCompliant non-compliant of $totalEvaluated evaluated resource-assignment pairs)"
    } else {
        Write-Log "Policy compliance  : no evaluated resource-assignment pairs found."
    }
}

Write-Log "===== Get-AzureGovernanceReport_v1.0.ps1 completed ====="

Write-Host ""
Write-Host "Done. Reports written to: $OutputPath" -ForegroundColor Green

# Note: the Az session is intentionally left open in case this is run as
# part of a larger sequence. Disconnect manually with Disconnect-AzAccount
# if needed. If you elevated access via Entra ID > Properties > "Access
# management for Azure resources" to run this, remember to toggle that
# back off when you're done -- see the PERMISSIONS NOTE at the top.

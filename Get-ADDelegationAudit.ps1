#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
	Audits delegated permissions and privileged access in Active Directory.

.DESCRIPTION
	Produces a set of CSV reports that show who has been given access to what
	in Active Directory. By default the whole domain is audited. Use
	-SearchBase to scope the audit to a single OU.

	Sections (all run by default, choose a subset with -Section):

		OUPermissions       Explicit (non-inherited) permissions on every OU,
							plus the domain root, AdminSDHolder and the default
							containers when auditing the whole domain.
							Permission GUIDs are resolved to readable attribute,
							object class and extended right names.

		PrivilegedGroups    Recursive membership of the built-in privileged
							groups (Domain Admins, Enterprise Admins, Schema
							Admins, Administrators, Account Operators, Server
							Operators, Print Operators, Backup Operators,
							Group Policy Creator Owners, DnsAdmins) plus any
							groups named in -AdditionalGroups.

		GPOPermissions      Who can read, apply, edit or fully manage each GPO.

		KerberosDelegation  Accounts trusted for unconstrained, constrained
							(with or without protocol transition) or
							resource-based constrained delegation.

	This script only reads from Active Directory. It makes no changes.

.PARAMETER OutputFolder
	Folder where the CSV reports are written. It is created if it does not
	exist. File names are prefixed with DelegationAudit_ and a timestamp.

.PARAMETER SearchBase
	Distinguished name of an OU to scope the audit to.
	Example: "OU=Staff,DC=contoso,DC=com"

	How scoping applies to each section:
		OUPermissions       The OU and every OU beneath it.
		PrivilegedGroups    Not scoped. Privileged groups are always domain-wide.
		GPOPermissions      Only GPOs linked to the OU or to OUs beneath it.
		KerberosDelegation  Only objects located under the OU.

.PARAMETER Section
	One or more of: All, OUPermissions, PrivilegedGroups, GPOPermissions,
	KerberosDelegation. Defaults to All.

.PARAMETER IncludeInherited
	Also report inherited permissions on OUs. Off by default because inherited
	entries only repeat what a parent OU already grants, which makes the report
	much larger.

.PARAMETER HideWellKnown
	Leave default principals (SYSTEM, Domain Admins, Enterprise Admins and so
	on) out of the OUPermissions report. They are flagged in the
	DefaultPrincipal column either way.

.PARAMETER AdditionalGroups
	Extra group names to treat as privileged, for example Exchange or other
	application admin groups.

.EXAMPLE
	# Audit the whole domain
	.\Get-ADDelegationAudit.ps1 -OutputFolder "C:\Temp\DelegationAudit"

.EXAMPLE
	# Scope the audit to one OU
	.\Get-ADDelegationAudit.ps1 -OutputFolder "C:\Temp\DelegationAudit" -SearchBase "OU=Staff,DC=contoso,DC=com"

.EXAMPLE
	# Only the OU permission report, hiding default principals
	.\Get-ADDelegationAudit.ps1 -OutputFolder "C:\Temp\DelegationAudit" -Section OUPermissions -HideWellKnown

.EXAMPLE
	# Include extra groups in the privileged group report
	.\Get-ADDelegationAudit.ps1 -OutputFolder "C:\Temp\DelegationAudit" -AdditionalGroups "Organization Management","Helpdesk Admins"

.NOTES
	- The DefaultPrincipal column means the principal normally appears on
	  default ACLs. It does not mean the specific permission is a default one,
	  so review those rows too, just with lower priority.
	- Default principal detection matches English group names. On a localized
	  domain, DefaultPrincipal may be False for default entries.
	- The GPOPermissions section needs the GroupPolicy module (RSAT Group
	  Policy Management Tools).
	- Enterprise Admins and Schema Admins live in the forest root domain. In a
	  child domain they cannot be read from here and are logged in the errors
	  report.
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory)]
	[string]$OutputFolder,

	[string]$SearchBase,

	[ValidateSet("All", "OUPermissions", "PrivilegedGroups", "GPOPermissions", "KerberosDelegation")]
	[string[]]$Section = "All",

	[switch]$IncludeInherited,

	[switch]$HideWellKnown,

	[string[]]$AdditionalGroups = @()
)

Import-Module ActiveDirectory

# --- SHARED STATE AND HELPERS ---
$script:auditErrors = [System.Collections.Generic.List[object]]::new()
$runAll             = $Section -contains "All"
$stamp              = Get-Date -Format "yyyyMMdd_HHmmss"
$writtenFiles       = [System.Collections.Generic.List[string]]::new()

function Test-Section {
	param([string]$Name)
	return ($runAll -or ($Section -contains $Name))
}

function Add-AuditError {
	param(
		[string]$SectionName,
		[string]$Target,
		[string]$Message
	)
	$script:auditErrors.Add([PSCustomObject]@{
		Section   = $SectionName
		Target    = $Target
		Message   = $Message
		Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
	})
}

function Export-AuditCsv {
	param(
		$Rows,
		[string]$Name
	)
	$path = Join-Path $OutputFolder ("DelegationAudit_{0}_{1}.csv" -f $stamp, $Name)
	if (@($Rows).Count -gt 0) {
		$Rows | Export-Csv -Path $path -NoTypeInformation
		$writtenFiles.Add($path)
		Write-Host "Saved: $path" -ForegroundColor Cyan
	}
	else {
		Write-Host "No rows for $Name, no file written." -ForegroundColor Gray
	}
}

# --- OUTPUT FOLDER ---
if (-not (Test-Path -LiteralPath $OutputFolder)) {
	try {
		New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
	}
	catch {
		Write-Host "ERROR: Could not create output folder $OutputFolder - $($_.Exception.Message)" -ForegroundColor Red
		exit 1
	}
}

# --- DOMAIN INFORMATION ---
try {
	$domain  = Get-ADDomain -ErrorAction Stop
	$rootDse = Get-ADRootDSE -ErrorAction Stop
}
catch {
	Write-Host "ERROR: Could not read domain information - $($_.Exception.Message)" -ForegroundColor Red
	exit 1
}

$domainDn  = $domain.DistinguishedName
$domainSid = $domain.DomainSID.Value

if ($SearchBase) {
	try {
		$null = Get-ADObject -Identity $SearchBase -ErrorAction Stop
	}
	catch {
		Write-Host "ERROR: SearchBase not found: $SearchBase" -ForegroundColor Red
		exit 1
	}
}

Write-Host "Domain      : $($domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Scope       : $(if ($SearchBase) { $SearchBase } else { 'Entire domain' })" -ForegroundColor Cyan
Write-Host "Sections    : $(if ($runAll) { 'All' } else { $Section -join ', ' })" -ForegroundColor Cyan
Write-Host "Output      : $OutputFolder`n" -ForegroundColor Cyan

# =====================================================================
# SECTION 1 - OU PERMISSIONS
# =====================================================================
if (Test-Section "OUPermissions") {
	Write-Host "--- OU permissions ---" -ForegroundColor Cyan

	# Build a GUID to name map from the schema and the extended rights container
	Write-Host "Resolving permission GUIDs from the schema..." -ForegroundColor Cyan
	$guidMap = @{}
	$guidMap["00000000-0000-0000-0000-000000000000"] = "(all)"

	try {
		$schemaObjs = Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName, schemaIDGUID -ErrorAction Stop
		foreach ($so in $schemaObjs) {
			$key = ([guid]$so.schemaIDGUID).ToString().ToLower()
			$guidMap[$key] = $(if ($so.lDAPDisplayName) { [string]$so.lDAPDisplayName } else { [string]$so.Name })
		}

		$rightObjs = Get-ADObject -SearchBase ("CN=Extended-Rights," + $rootDse.configurationNamingContext) -LDAPFilter "(objectClass=controlAccessRight)" -Properties displayName, rightsGUID -ErrorAction Stop
		foreach ($ro in $rightObjs) {
			if ($ro.rightsGUID) {
				$key = ([string]$ro.rightsGUID).ToLower()
				$guidMap[$key] = $(if ($ro.displayName) { [string]$ro.displayName } else { [string]$ro.Name })
			}
		}
		Write-Host "Resolved $($guidMap.Count) GUIDs.`n" -ForegroundColor Cyan
	}
	catch {
		Add-AuditError -SectionName "OUPermissions" -Target "GUID map" -Message $_.Exception.Message
		Write-Host "WARNING: Could not fully resolve GUIDs, raw GUIDs will be shown. $($_.Exception.Message)" -ForegroundColor Yellow
	}

	# Principals that normally appear on default ACLs
	$defaultLeaf = @(
		"SYSTEM", "SELF", "ENTERPRISE DOMAIN CONTROLLERS", "Authenticated Users", "Everyone",
		"CREATOR OWNER", "Administrators", "Pre-Windows 2000 Compatible Access",
		"Account Operators", "Print Operators", "Domain Admins", "Enterprise Admins",
		"Domain Controllers", "Enterprise Read-only Domain Controllers",
		"Read-only Domain Controllers", "Key Admins", "Enterprise Key Admins",
		"Terminal Server License Servers", "Windows Authorization Access Group",
		"RAS and IAS Servers"
	)

	function Test-DefaultPrincipal {
		param([string]$Identity)
		$leaf = ($Identity -split "\\")[-1]
		return ($defaultLeaf -contains $leaf)
	}

	function Get-RightsNote {
		param(
			[string]$Rights,
			[string]$ObjectName,
			[string]$Access
		)
		$notes = [System.Collections.Generic.List[string]]::new()

		if ($Access -ne "Allow") {
			$notes.Add("Explicit deny")
			return ($notes -join "; ")
		}

		if ($Rights -match "GenericAll")  { $notes.Add("Full control") }
		if ($Rights -match "WriteDacl")   { $notes.Add("Can change permissions") }
		if ($Rights -match "WriteOwner")  { $notes.Add("Can take ownership") }
		if ($Rights -match "GenericWrite") { $notes.Add("Generic write") }

		if ($Rights -match "CreateChild" -and $ObjectName -eq "(all)") { $notes.Add("Can create any child object") }
		if ($Rights -match "DeleteChild" -and $ObjectName -eq "(all)") { $notes.Add("Can delete any child object") }
		if ($Rights -match "WriteProperty" -and $ObjectName -eq "(all)") { $notes.Add("Can write all properties") }

		if ($ObjectName -eq "Reset Password" -and $Rights -match "ExtendedRight") { $notes.Add("Can reset passwords") }
		if ($ObjectName -like "Replicating Directory Changes*" -and $Rights -match "ExtendedRight") { $notes.Add("Directory replication right (DCSync capable)") }
		if ($ObjectName -eq "gPLink" -and $Rights -match "WriteProperty") { $notes.Add("Can link GPOs") }
		if ($ObjectName -eq "member" -and $Rights -match "WriteProperty") { $notes.Add("Can modify group membership") }
		if ($ObjectName -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" -and $Rights -match "WriteProperty") { $notes.Add("Can configure resource-based delegation") }

		return ($notes -join "; ")
	}

	# Work out which objects to read ACLs from
	$targets = [System.Collections.Generic.List[object]]::new()
	$ouParams = @{ Filter = "*" }
	if ($SearchBase) { $ouParams["SearchBase"] = $SearchBase }

	try {
		$ous = Get-ADOrganizationalUnit @ouParams -ErrorAction Stop
		foreach ($ou in $ous) {
			$targets.Add([PSCustomObject]@{ DN = $ou.DistinguishedName; Kind = "OU" })
		}
	}
	catch {
		Add-AuditError -SectionName "OUPermissions" -Target "OU enumeration" -Message $_.Exception.Message
		Write-Host "ERROR: Could not enumerate OUs - $($_.Exception.Message)" -ForegroundColor Red
	}

	if ($SearchBase) {
		$baseListed = @($targets | Where-Object { $_.DN -eq $SearchBase }).Count -gt 0
		if (-not $baseListed) {
			$targets.Add([PSCustomObject]@{ DN = $SearchBase; Kind = "SearchBase" })
		}
	}
	else {
		$targets.Add([PSCustomObject]@{ DN = $domainDn; Kind = "Domain Root" })
		$targets.Add([PSCustomObject]@{ DN = "CN=AdminSDHolder,CN=System,$domainDn"; Kind = "AdminSDHolder" })
		$targets.Add([PSCustomObject]@{ DN = "CN=Builtin,$domainDn"; Kind = "Container" })
		$targets.Add([PSCustomObject]@{ DN = "CN=Users,$domainDn"; Kind = "Container" })
		$targets.Add([PSCustomObject]@{ DN = "CN=Computers,$domainDn"; Kind = "Container" })
	}

	Write-Host "Reading permissions on $($targets.Count) objects..." -ForegroundColor Cyan

	$ouResults = [System.Collections.Generic.List[object]]::new()
	$i = 0

	foreach ($t in $targets) {
		$i++
		if (($i % 25) -eq 0 -or $i -eq $targets.Count) {
			Write-Progress -Activity "Reading OU permissions" -Status "$i of $($targets.Count)" -PercentComplete (($i / $targets.Count) * 100)
		}

		try {
			$acl = Get-Acl -LiteralPath ("AD:\" + $t.DN) -ErrorAction Stop
		}
		catch {
			Add-AuditError -SectionName "OUPermissions" -Target $t.DN -Message $_.Exception.Message
			continue
		}

		foreach ($ace in $acl.Access) {
			if ($ace.IsInherited -and -not $IncludeInherited) { continue }

			$identity  = $ace.IdentityReference.Value
			$isDefault = Test-DefaultPrincipal -Identity $identity
			if ($HideWellKnown -and $isDefault) { continue }

			$objGuid = $ace.ObjectType.ToString().ToLower()
			$inhGuid = $ace.InheritedObjectType.ToString().ToLower()
			$objName = $(if ($guidMap.ContainsKey($objGuid)) { $guidMap[$objGuid] } else { $objGuid })
			$inhName = $(if ($guidMap.ContainsKey($inhGuid)) { $guidMap[$inhGuid] } else { $inhGuid })

			$rights   = $ace.ActiveDirectoryRights.ToString()
			$access   = $ace.AccessControlType.ToString()
			$orphaned = ($identity -match "^S-1-5-21-")

			$note = Get-RightsNote -Rights $rights -ObjectName $objName -Access $access
			if ($orphaned) {
				$note = $(if ($note) { "Orphaned SID (account no longer exists); $note" } else { "Orphaned SID (account no longer exists)" })
			}

			$ouResults.Add([PSCustomObject]@{
				ObjectDN                = $t.DN
				ObjectKind              = $t.Kind
				Principal               = $identity
				DefaultPrincipal        = $isDefault
				OrphanedSid             = $orphaned
				Access                  = $access
				Rights                  = $rights
				ObjectTypeName          = $objName
				InheritedObjectTypeName = $inhName
				InheritanceType         = $ace.InheritanceType.ToString()
				IsInherited             = $ace.IsInherited
				Notes                   = $note
			})
		}
	}
	Write-Progress -Activity "Reading OU permissions" -Completed

	Export-AuditCsv -Rows $ouResults -Name "OUPermissions"

	$nonDefault   = @($ouResults | Where-Object { -not $_.DefaultPrincipal })
	$orphanedRows = @($ouResults | Where-Object { $_.OrphanedSid })
	$flaggedRows  = @($ouResults | Where-Object { $_.Notes -and -not $_.DefaultPrincipal })

	Write-Host "`nObjects read             : $($targets.Count)" -ForegroundColor Cyan
	Write-Host "Permission entries       : $($ouResults.Count)" -ForegroundColor Cyan
	Write-Host "Non-default principals   : $($nonDefault.Count) entries" -ForegroundColor Yellow
	Write-Host "Flagged (non-default)    : $($flaggedRows.Count) entries" -ForegroundColor Yellow
	Write-Host "Orphaned SIDs            : $($orphanedRows.Count) entries" -ForegroundColor $(if ($orphanedRows.Count -gt 0) { "Red" } else { "Green" })

	if ($nonDefault.Count -gt 0) {
		Write-Host "`nTop non-default principals by number of entries:" -ForegroundColor Cyan
		$nonDefault | Group-Object Principal | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
			Write-Host ("  {0,5}  {1}" -f $_.Count, $_.Name)
		}
	}
	Write-Host ""
}

# =====================================================================
# SECTION 2 - PRIVILEGED GROUPS
# =====================================================================
if (Test-Section "PrivilegedGroups") {
	Write-Host "--- Privileged group membership ---" -ForegroundColor Cyan

	function Get-GroupMembersRecursive {
		param(
			[string]$GroupDn,
			[string]$TopGroup,
			[string]$Path,
			[int]$Depth,
			$Visited
		)

		if (-not $Visited.Add($GroupDn)) { return }

		try {
			$grp = Get-ADGroup -Identity $GroupDn -Properties member -ErrorAction Stop
		}
		catch {
			Add-AuditError -SectionName "PrivilegedGroups" -Target $GroupDn -Message $_.Exception.Message
			return
		}

		foreach ($memberDn in $grp.member) {
			try {
				$obj = Get-ADObject -Identity $memberDn -Properties samAccountName -ErrorAction Stop
			}
			catch {
				Add-AuditError -SectionName "PrivilegedGroups" -Target $memberDn -Message $_.Exception.Message
				continue
			}

			$class     = [string]$obj.ObjectClass
			$sam       = [string]$obj.samAccountName
			$display   = [string]$obj.Name
			$enabled   = ""
			$lastLogon = ""
			$pwdNever  = ""
			$pwdSet    = ""

			if ($class -eq "user") {
				try {
					$u = Get-ADUser -Identity $memberDn -Properties Enabled, LastLogonDate, PasswordNeverExpires, PasswordLastSet -ErrorAction Stop
					$enabled   = $u.Enabled
					$pwdNever  = $u.PasswordNeverExpires
					$lastLogon = $(if ($u.LastLogonDate) { $u.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" })
					$pwdSet    = $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" })
				}
				catch {
					Add-AuditError -SectionName "PrivilegedGroups" -Target $memberDn -Message $_.Exception.Message
				}
			}
			elseif ($class -eq "computer") {
				try {
					$c = Get-ADComputer -Identity $memberDn -Properties Enabled, LastLogonDate -ErrorAction Stop
					$enabled   = $c.Enabled
					$lastLogon = $(if ($c.LastLogonDate) { $c.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" })
				}
				catch {
					Add-AuditError -SectionName "PrivilegedGroups" -Target $memberDn -Message $_.Exception.Message
				}
			}
			elseif ($class -eq "foreignSecurityPrincipal") {
				try {
					$display = ([System.Security.Principal.SecurityIdentifier]$obj.Name).Translate([System.Security.Principal.NTAccount]).Value
				}
				catch {
					$display = "Foreign principal " + $obj.Name
				}
			}

			[PSCustomObject]@{
				PrivilegedGroup      = $TopGroup
				MemberName           = $display
				SamAccountName       = $sam
				ObjectClass          = $class
				Enabled              = $enabled
				LastLogonDate        = $lastLogon
				PasswordNeverExpires = $pwdNever
				PasswordLastSet      = $pwdSet
				Depth                = $Depth + 1
				MembershipPath       = "$Path > $display"
				DistinguishedName    = $memberDn
			}

			if ($class -eq "group") {
				Get-GroupMembersRecursive -GroupDn $memberDn -TopGroup $TopGroup -Path "$Path > $display" -Depth ($Depth + 1) -Visited $Visited
			}
		}
	}

	# Resolve the forest root domain SID for Enterprise Admins and Schema Admins
	$forestRootSid = $domainSid
	try {
		$forestRootName = (Get-ADForest -ErrorAction Stop).RootDomain
		$forestRootSid  = (Get-ADDomain -Identity $forestRootName -ErrorAction Stop).DomainSID.Value
	}
	catch {
		# Fall back to this domain's SID
	}

	$groupList = [System.Collections.Generic.List[object]]::new()
	$groupList.Add(@{ Label = "Domain Admins";               Identity = "$domainSid-512" })
	$groupList.Add(@{ Label = "Schema Admins";               Identity = "$forestRootSid-518" })
	$groupList.Add(@{ Label = "Enterprise Admins";           Identity = "$forestRootSid-519" })
	$groupList.Add(@{ Label = "Group Policy Creator Owners"; Identity = "$domainSid-520" })
	$groupList.Add(@{ Label = "Administrators";              Identity = "S-1-5-32-544" })
	$groupList.Add(@{ Label = "Account Operators";           Identity = "S-1-5-32-548" })
	$groupList.Add(@{ Label = "Server Operators";            Identity = "S-1-5-32-549" })
	$groupList.Add(@{ Label = "Print Operators";             Identity = "S-1-5-32-550" })
	$groupList.Add(@{ Label = "Backup Operators";            Identity = "S-1-5-32-551" })
	$groupList.Add(@{ Label = "DnsAdmins";                   Identity = "DnsAdmins" })
	foreach ($extra in $AdditionalGroups) {
		if (-not [string]::IsNullOrWhiteSpace($extra)) {
			$groupList.Add(@{ Label = $extra; Identity = $extra })
		}
	}

	$privResults = [System.Collections.Generic.List[object]]::new()
	$groupSummary = [System.Collections.Generic.List[object]]::new()

	foreach ($g in $groupList) {
		try {
			$grp = Get-ADGroup -Identity $g.Identity -ErrorAction Stop
		}
		catch {
			Add-AuditError -SectionName "PrivilegedGroups" -Target $g.Label -Message "Group not found or not readable: $($_.Exception.Message)"
			Write-Host "SKIPPED: $($g.Label) - not found or not readable" -ForegroundColor Yellow
			continue
		}

		$visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
		$members = @(Get-GroupMembersRecursive -GroupDn $grp.DistinguishedName -TopGroup $g.Label -Path $g.Label -Depth 0 -Visited $visited)

		foreach ($m in $members) { $privResults.Add($m) }

		$accounts = @($members | Where-Object { $_.ObjectClass -ne "group" })
		$groupSummary.Add([PSCustomObject]@{
			Group             = $g.Label
			Accounts          = $accounts.Count
			Disabled          = @($accounts | Where-Object { $_.Enabled -eq $false }).Count
			PasswordNeverExp  = @($accounts | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
			NestedGroups      = @($members | Where-Object { $_.ObjectClass -eq "group" }).Count
		})
	}

	Export-AuditCsv -Rows $privResults -Name "PrivilegedGroupMembers"

	Write-Host "`nPrivileged group summary:" -ForegroundColor Cyan
	foreach ($s in $groupSummary) {
		$color = $(if ($s.Accounts -gt 0) { "Yellow" } else { "Gray" })
		Write-Host ("  {0,-30} accounts: {1,3}  disabled: {2,3}  never-expires: {3,3}  nested groups: {4,3}" -f $s.Group, $s.Accounts, $s.Disabled, $s.PasswordNeverExp, $s.NestedGroups) -ForegroundColor $color
	}
	Write-Host ""
}

# =====================================================================
# SECTION 3 - GPO PERMISSIONS
# =====================================================================
if (Test-Section "GPOPermissions") {
	Write-Host "--- GPO permissions ---" -ForegroundColor Cyan

	if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
		Write-Host "SKIPPED: GroupPolicy module not available. Install the RSAT Group Policy Management Tools." -ForegroundColor Yellow
		Add-AuditError -SectionName "GPOPermissions" -Target "GroupPolicy module" -Message "Module not available, section skipped"
	}
	else {
		Import-Module GroupPolicy

		$gpoDefaultEditors = @("Domain Admins", "Enterprise Admins", "SYSTEM")

		# When scoped, only report GPOs linked within the scope
		$scopeGpoIds = $null
		if ($SearchBase) {
			$scopeGpoIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
			try {
				$linkObjs = Get-ADObject -SearchBase $SearchBase -SearchScope Subtree -LDAPFilter "(gPLink=*)" -Properties gPLink -ErrorAction Stop
				foreach ($lo in $linkObjs) {
					foreach ($m in [regex]::Matches([string]$lo.gPLink, '\{[0-9A-Fa-f\-]{36}\}')) {
						[void]$scopeGpoIds.Add($m.Value)
					}
				}
			}
			catch {
				Add-AuditError -SectionName "GPOPermissions" -Target $SearchBase -Message $_.Exception.Message
			}
			Write-Host "Scoped to $($scopeGpoIds.Count) GPOs linked at or below the SearchBase." -ForegroundColor Cyan
		}

		$gpoResults = [System.Collections.Generic.List[object]]::new()

		try {
			$allGpos = @(Get-GPO -All -ErrorAction Stop)
		}
		catch {
			$allGpos = @()
			Add-AuditError -SectionName "GPOPermissions" -Target "Get-GPO" -Message $_.Exception.Message
			Write-Host "ERROR: Could not list GPOs - $($_.Exception.Message)" -ForegroundColor Red
		}

		$i = 0
		foreach ($gpo in $allGpos) {
			$i++
			if (($i % 10) -eq 0 -or $i -eq $allGpos.Count) {
				Write-Progress -Activity "Reading GPO permissions" -Status "$i of $($allGpos.Count)" -PercentComplete (($i / $allGpos.Count) * 100)
			}

			if ($null -ne $scopeGpoIds) {
				if (-not $scopeGpoIds.Contains("{" + $gpo.Id.ToString() + "}")) { continue }
			}

			try {
				$perms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
			}
			catch {
				Add-AuditError -SectionName "GPOPermissions" -Target $gpo.DisplayName -Message $_.Exception.Message
				continue
			}

			foreach ($p in $perms) {
				$perm = [string]$p.Permission
				$note = ""
				$editRight = ($perm -eq "GpoEdit" -or $perm -eq "GpoEditDeleteModifySecurity" -or $perm -eq "GpoCustom")
				if ($editRight -and -not $p.Denied) {
					if ($gpoDefaultEditors -notcontains $p.Trustee.Name) { $note = "Non-default editor" }
				}

				$gpoResults.Add([PSCustomObject]@{
					GpoName       = $gpo.DisplayName
					GpoId         = $gpo.Id.ToString()
					GpoStatus     = [string]$gpo.GpoStatus
					Trustee       = $p.Trustee.Name
					TrusteeDomain = $p.Trustee.Domain
					TrusteeType   = [string]$p.Trustee.SidType
					Permission    = $perm
					Denied        = $p.Denied
					Inherited     = $p.Inherited
					Notes         = $note
				})
			}
		}
		Write-Progress -Activity "Reading GPO permissions" -Completed

		Export-AuditCsv -Rows $gpoResults -Name "GPOPermissions"

		$gposRead  = @($gpoResults | Select-Object -ExpandProperty GpoId -Unique).Count
		$flaggedGp = @($gpoResults | Where-Object { $_.Notes })
		Write-Host "`nGPOs reported            : $gposRead" -ForegroundColor Cyan
		Write-Host "Non-default editors      : $($flaggedGp.Count) entries" -ForegroundColor $(if ($flaggedGp.Count -gt 0) { "Yellow" } else { "Green" })
		if ($flaggedGp.Count -gt 0) {
			$flaggedGp | Group-Object Trustee | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
				Write-Host ("  {0,5}  {1}" -f $_.Count, $_.Name)
			}
		}
		Write-Host ""
	}
}

# =====================================================================
# SECTION 4 - KERBEROS DELEGATION
# =====================================================================
if (Test-Section "KerberosDelegation") {
	Write-Host "--- Kerberos delegation ---" -ForegroundColor Cyan

	$krbFilter = "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
	$krbParams = @{
		LDAPFilter  = $krbFilter
		Properties  = @("userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "primaryGroupID")
		ErrorAction = "Stop"
	}
	if ($SearchBase) { $krbParams["SearchBase"] = $SearchBase }

	$krbResults = [System.Collections.Generic.List[object]]::new()

	try {
		$krbObjs = @(Get-ADObject @krbParams)
	}
	catch {
		$krbObjs = @()
		Add-AuditError -SectionName "KerberosDelegation" -Target "Get-ADObject" -Message $_.Exception.Message
		Write-Host "ERROR: Delegation query failed - $($_.Exception.Message)" -ForegroundColor Red
	}

	foreach ($o in $krbObjs) {
		$uac           = [int]$o.userAccountControl
		$unconstrained = (($uac -band 524288) -ne 0)
		$protoTransit  = (($uac -band 16777216) -ne 0)
		$disabled      = (($uac -band 2) -ne 0)
		$pgid          = [int]$o.primaryGroupID
		$isDc          = ($pgid -eq 516 -or $pgid -eq 521)

		$delegTargets  = $o.'msDS-AllowedToDelegateTo'
		$hasConstrained = ($null -ne $delegTargets -and @($delegTargets).Count -gt 0)
		$targetText    = $(if ($hasConstrained) { (@($delegTargets) -join "; ") } else { "" })

		$rbcd          = $o.'msDS-AllowedToActOnBehalfOfOtherIdentity'
		$hasRbcd       = ($null -ne $rbcd)
		$rbcdText      = ""
		if ($hasRbcd) {
			try {
				$rbcdText = ((@($rbcd.Access) | ForEach-Object { $_.IdentityReference.Value }) -join "; ")
			}
			catch {
				$rbcdText = ""
			}
			if ([string]::IsNullOrWhiteSpace($rbcdText)) { $rbcdText = "(present, principals could not be read)" }
		}

		$types = [System.Collections.Generic.List[string]]::new()
		if ($unconstrained) { $types.Add("Unconstrained") }
		if ($hasConstrained -and $protoTransit) { $types.Add("Constrained (protocol transition)") }
		elseif ($hasConstrained) { $types.Add("Constrained (Kerberos only)") }
		elseif ($protoTransit) { $types.Add("Protocol transition flag set, no target list") }
		if ($hasRbcd) { $types.Add("Resource-based constrained") }

		$risk = "REVIEW"
		if ($unconstrained -and $isDc) { $risk = "INFO: Domain controller (unconstrained is expected)" }
		elseif ($unconstrained) { $risk = "HIGH: Unconstrained delegation on a non-DC" }
		elseif ($hasConstrained -and $protoTransit) { $risk = "MEDIUM: Protocol transition can impersonate any user to the listed services" }
		elseif ($hasConstrained) { $risk = "LOW: Constrained delegation, verify the listed services" }
		elseif ($hasRbcd) { $risk = "LOW: Resource-based, verify the allowed principals" }

		$krbResults.Add([PSCustomObject]@{
			Name                 = $o.Name
			ObjectClass          = [string]$o.ObjectClass
			Enabled              = (-not $disabled)
			IsDomainController   = $isDc
			DelegationTypes      = ($types -join "; ")
			ConstrainedTargets   = $targetText
			RbcdAllowedPrincipals = $rbcdText
			Risk                 = $risk
			DistinguishedName    = $o.DistinguishedName
		})
	}

	Export-AuditCsv -Rows $krbResults -Name "KerberosDelegation"

	$highCount = @($krbResults | Where-Object { $_.Risk -like "HIGH*" }).Count
	$medCount  = @($krbResults | Where-Object { $_.Risk -like "MEDIUM*" }).Count
	Write-Host "`nAccounts with delegation : $($krbResults.Count)" -ForegroundColor Cyan
	Write-Host "High risk                : $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Red" } else { "Green" })
	Write-Host "Medium risk              : $medCount" -ForegroundColor $(if ($medCount -gt 0) { "Yellow" } else { "Green" })
	Write-Host ""
}

# =====================================================================
# ERRORS AND FINISH
# =====================================================================
if ($script:auditErrors.Count -gt 0) {
	Export-AuditCsv -Rows $script:auditErrors -Name "Errors"
	Write-Host "`n$($script:auditErrors.Count) items could not be read. See the Errors file for details." -ForegroundColor Yellow
}

Write-Host "`n--- DONE ---" -ForegroundColor Cyan
Write-Host "Files written: $($writtenFiles.Count)" -ForegroundColor Cyan
foreach ($f in $writtenFiles) { Write-Host "  $f" }

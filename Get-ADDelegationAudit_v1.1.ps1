# ============================================================
# Get-ADDelegationAudit_v1.1.ps1
# Version 1.1
#
# Audits delegated permissions and privileged access in Active
# Directory and writes the results to CSV reports. By default the
# whole domain is audited. Use -SearchBase to scope the audit to a
# single OU. Based on the earlier unversioned Get-ADDelegationAudit.ps1,
# brought up to STANDARDS.md, with the audit gaps listed under
# "WHAT THE RESULTS DO NOT SHOW" reduced.
#
# Sections (all run by default, choose a subset with -Section):
#
#   OUPermissions       Explicit (non-inherited) permissions on every OU,
#                       plus the domain root, AdminSDHolder and the default
#                       containers when auditing the whole domain.
#                       Permission GUIDs are resolved to readable attribute,
#                       object class and extended right names.
#
#   PrivilegedGroups    Recursive membership of the built-in privileged
#                       groups (Domain Admins, Enterprise Admins, Schema
#                       Admins, Administrators, Account Operators, Server
#                       Operators, Print Operators, Backup Operators,
#                       Group Policy Creator Owners, DnsAdmins) plus any
#                       groups named in -AdditionalGroups. Includes
#                       accounts that belong through their primary group.
#
#   GPOPermissions      Who can read, apply, edit or fully manage each GPO.
#
#   KerberosDelegation  Accounts trusted for unconstrained, constrained
#                       (with or without protocol transition) or
#                       resource-based constrained delegation.
#
# WHAT THIS SCRIPT COLLECTS:
#   Read-only queries of Active Directory (ACLs, group membership, GPO
#   permissions, delegation settings).
#
# WHAT THIS SCRIPT CHANGES:
#   Active Directory: Nothing. The script only reads.
#   Your PS session:  Imports the ActiveDirectory module (and the
#                     GroupPolicy module when that section runs).
#   Your computer:    Creates the log and output folders if missing.
#                     Writes a run log and the CSV reports.
#
# HANDLE THE OUTPUT AS SENSITIVE:
#   The reports list privileged accounts, who can change what in
#   Active Directory, and delegation settings. That is a map of how
#   to take over the domain. Store them on a protected path, share
#   them only with people who need them, and delete them when done.
#
# WHAT THE RESULTS DO NOT SHOW:
#   - ACLs on objects other than OUs, the domain root, AdminSDHolder and
#     the Builtin, Users and Computers containers (for example on
#     individual users, groups or computers).
#   - Inherited permissions, unless -IncludeInherited is used.
#   - Rights held through nested groups. The report shows who is
#     named on an ACL, not everyone who is a member of that principal.
#   - The ACL owner of each object.
#   - With -HideWellKnown: default-principal entries are left out, except
#     those that grant write-type rights to Everyone, Authenticated
#     Users, Pre-Windows 2000 Compatible Access, Account Operators or
#     Print Operators. The log says how many were kept for that reason.
#   - Primary-group members are found for groups of THIS domain only.
#     Enterprise Admins and Schema Admins live in the forest root domain
#     and cannot be read from a child domain (logged as an error).
#
# PREREQUISITES:
#   - ActiveDirectory module (RSAT) and a domain-joined computer.
#   - Domain user rights are enough to read most ACLs and groups. Some
#     objects may still be unreadable; they are logged and listed in the
#     Errors report.
#   - GPOPermissions needs the GroupPolicy module (RSAT Group Policy
#     Management Tools).
#   - Windows PowerShell 5.1 or PowerShell 7 on Windows.
#
# PARAMETERS:
#   -OutputDirectory   Folder for the CSV reports. Created if missing.
#                      Default: C:\Temp   (alias: -OutputFolder)
#   -SearchBase        Distinguished name of an OU to scope the audit to,
#                      for example "OU=Staff,DC=contoso,DC=com".
#                      Default: the whole domain.
#                      How scoping applies to each section:
#                        OUPermissions       The OU and every OU beneath it.
#                        PrivilegedGroups    Not scoped. Always domain-wide.
#                        GPOPermissions      Only GPOs linked to the OU or
#                                            to OUs beneath it.
#                        KerberosDelegation  Only objects under the OU.
#   -Section           One or more of: All, OUPermissions, PrivilegedGroups,
#                      GPOPermissions, KerberosDelegation. Default: All
#   -IncludeInherited  Also report inherited permissions on OUs. Off by
#                      default because inherited entries only repeat what a
#                      parent OU already grants and make the report larger.
#   -HideWellKnown     Leave default principals (SYSTEM, Domain Admins,
#                      Enterprise Admins and so on) out of the OUPermissions
#                      report. They are flagged in the DefaultPrincipal column
#                      either way. Default principals that grant write-type
#                      rights to broad groups are NOT hidden (see above).
#   -AdditionalGroups  Extra group names to treat as privileged, for example
#                      Exchange or other application admin groups.
#                      Default: none
#
# OUTPUT:
#   Run log:  C:\Logs\yyyy.MM.dd.HHmmss.Get-ADDelegationAudit_v1.1.log
#   Reports (in -OutputDirectory; a file is written only when it has rows):
#     yyyy.MM.dd.HHmmss.DelegationAudit_OUPermissions.csv
#     yyyy.MM.dd.HHmmss.DelegationAudit_PrivilegedGroupMembers.csv
#     yyyy.MM.dd.HHmmss.DelegationAudit_GPOPermissions.csv
#     yyyy.MM.dd.HHmmss.DelegationAudit_KerberosDelegation.csv
#     yyyy.MM.dd.HHmmss.DelegationAudit_Errors.csv
#   Exit code: 0 when everything was read, 2 when some items could not be
#   read (see the Errors report). A fatal error throws.
#
# NOTES:
#   - The DefaultPrincipal column means the principal normally appears on
#     default ACLs. It does not mean the specific permission is a default
#     one, so review those rows too, just with lower priority. Default
#     principals are recognized by SID, so localized domains work.
#   - SidStatus is Resolved, Orphaned (a SID from this domain whose account
#     no longer exists) or Unresolved (a SID from elsewhere that could not
#     be looked up: a deleted account, or its domain is not reachable).
#
# EXAMPLES:
#   # Audit the whole domain
#   .\Get-ADDelegationAudit_v1.1.ps1
#
#   # Reports somewhere else
#   .\Get-ADDelegationAudit_v1.1.ps1 -OutputDirectory "D:\Audit"
#
#   # Scope the audit to one OU
#   .\Get-ADDelegationAudit_v1.1.ps1 -SearchBase "OU=Staff,DC=contoso,DC=com"
#
#   # Only the OU permission report, hiding default principals
#   .\Get-ADDelegationAudit_v1.1.ps1 -Section OUPermissions -HideWellKnown
#
#   # Include extra groups in the privileged group report
#   .\Get-ADDelegationAudit_v1.1.ps1 -AdditionalGroups "Organization Management","Helpdesk Admins"
#
# v1.1 changes:
#   Fixed OUPermissions returning no rows. How it showed up: a run scoped
#   to one OU logged "Could not read [OUPermissions] <OU>: Cannot find
#   path '//RootDSE/<OU DN>' because it does not exist", so an account
#   that had been delegated rights on that OU never appeared, although
#   the OU exists. v1.0 read each ACL through the AD: PowerShell drive
#   (Get-Acl). The ACL is now read with Get-ADObject -Properties
#   nTSecurityDescriptor, which does not use the drive; the drive is kept
#   as a fallback, and if both fail the Errors report and log show both
#   messages. Confirmed in PowerShell 7 with a mocked AD (the drive path
#   made to fail); NOT yet confirmed against a real domain (#48).
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param (
    [Alias("OutputFolder")]
    [string]$OutputDirectory = "C:\Temp",

    [string]$SearchBase = "",

    [string[]]$Section = @("All"),

    [switch]$IncludeInherited,

    [switch]$HideWellKnown,

    [string[]]$AdditionalGroups = @()
)

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs"                  # default log folder (Standard #46)
$ScriptVersion = "1.1"
$validSections = @("All", "OUPermissions", "PrivilegedGroups", "GPOPermissions", "KerberosDelegation")

# Well-known SIDs that normally appear on default ACLs. Domain-relative ones
# are built from the domain SID once it is read (see below).
$wellKnownAlwaysHide = @(
    "S-1-5-18",       # SYSTEM
    "S-1-5-10",       # SELF
    "S-1-5-9",        # ENTERPRISE DOMAIN CONTROLLERS
    "S-1-3-0",        # CREATOR OWNER
    "S-1-5-32-544",   # Administrators
    "S-1-5-32-560",   # Windows Authorization Access Group
    "S-1-5-32-561"    # Terminal Server License Servers
)
$wellKnownWatch = @(
    "S-1-1-0",        # Everyone
    "S-1-5-11",       # Authenticated Users
    "S-1-5-32-554",   # Pre-Windows 2000 Compatible Access
    "S-1-5-32-548",   # Account Operators
    "S-1-5-32-550"    # Print Operators
)

# Rights that let a principal change something. Used to decide whether a
# default entry for a broad group may be hidden by -HideWellKnown.
$writeRightsPattern = "GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild|DeleteChild|DeleteTree|ExtendedRight"
# ============================================================


# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
if (-not (Test-Path -Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$outputDirError = ""
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    try   { New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    catch { $outputDirError = $_.Exception.Message }
    if (-not $outputDirError -and -not (Test-Path -LiteralPath $OutputDirectory)) { $outputDirError = "the folder was not created" }
}
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

function Stop-WithError {
    # Log at ERROR, then throw (#24)
    param([string]$Message = "")
    Write-Log $Message -Level ERROR
    throw $Message
}


# ============================================================
# Shared state and helpers
# ============================================================
$script:auditErrors  = [System.Collections.Generic.List[object]]::new()
$script:writtenFiles = [System.Collections.Generic.List[string]]::new()
$script:sidNameCache   = @{}
$script:defaultSidNames = @{}   # fallback names for default principals if a lookup fails
$script:objInfoCache = @{}

function Test-Section {
    param([string]$Name)
    return ($script:runAll -or ($script:sectionList -contains $Name))
}

function Add-AuditError {
    param(
        [string]$SectionName = "",
        [string]$Target      = "",
        [string]$Message     = ""
    )
    $script:auditErrors.Add([PSCustomObject]@{
        Section   = $SectionName
        Target    = $Target
        Message   = $Message
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
    Write-Log ("Could not read [{0}] {1}: {2}" -f $SectionName, $Target, $Message) -Level WARN
}

function Export-AuditCsv {
    param(
        $Rows,
        [string]$Name = ""
    )
    $path = Join-Path $OutputDirectory ("{0}.DelegationAudit_{1}.csv" -f $stamp, $Name)
    if (@($Rows).Count -gt 0) {
        $Rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $script:writtenFiles.Add($path)
        Write-Log "Saved: $path"
    }
    else {
        Write-Log "No rows for $Name, no file written." -Level WARN
    }
}

function Get-SidName {
    # Looks a SID up once and remembers the answer. Returns $null when it cannot be resolved.
    param($Sid)
    $key = $Sid.Value
    if ($script:sidNameCache.ContainsKey($key)) { return $script:sidNameCache[$key] }
    $resolved = $null
    try   { $resolved = $Sid.Translate([System.Security.Principal.NTAccount]).Value }
    catch { $resolved = $null }
    if (-not $resolved -and $script:defaultSidNames.ContainsKey($key)) { $resolved = $script:defaultSidNames[$key] }
    $script:sidNameCache[$key] = $resolved
    return $resolved
}

function Get-RightsNote {
    param(
        [string]$Rights     = "",
        [string]$ObjectName = "",
        [string]$Access     = ""
    )
    $notes = [System.Collections.Generic.List[string]]::new()

    if ($Access -ne "Allow") {
        $notes.Add("Explicit deny")
        return ($notes -join "; ")
    }

    if ($Rights -match "GenericAll")   { $notes.Add("Full control") }
    if ($Rights -match "WriteDacl")    { $notes.Add("Can change permissions") }
    if ($Rights -match "WriteOwner")   { $notes.Add("Can take ownership") }
    if ($Rights -match "GenericWrite") { $notes.Add("Generic write") }
    if ($Rights -match "DeleteTree")   { $notes.Add("Can delete the whole subtree") }

    if ($Rights -match "CreateChild" -and $ObjectName -eq "(all)") { $notes.Add("Can create any child object") }
    if ($Rights -match "DeleteChild" -and $ObjectName -eq "(all)") { $notes.Add("Can delete any child object") }
    if ($Rights -match "WriteProperty" -and $ObjectName -eq "(all)") { $notes.Add("Can write all properties") }

    # An extended-right entry with no specific right named grants ALL extended rights
    if ($Rights -match "ExtendedRight" -and $ObjectName -eq "(all)") {
        $notes.Add("All extended rights (includes Reset Password and directory replication)")
    }
    if ($ObjectName -eq "Reset Password" -and $Rights -match "ExtendedRight") { $notes.Add("Can reset passwords") }
    if ($ObjectName -like "Replicating Directory Changes*" -and $Rights -match "ExtendedRight") { $notes.Add("Directory replication right (DCSync capable)") }
    if ($ObjectName -eq "gPLink" -and $Rights -match "WriteProperty") { $notes.Add("Can link GPOs") }
    if ($ObjectName -eq "member" -and $Rights -match "WriteProperty") { $notes.Add("Can modify group membership") }
    if ($ObjectName -eq "msDS-AllowedToActOnBehalfOfOtherIdentity" -and $Rights -match "WriteProperty") { $notes.Add("Can configure resource-based delegation") }

    return ($notes -join "; ")
}

function ConvertFrom-FileTimeText {
    # AD stores times as 64-bit file times. 0 and the max value mean "never".
    param($Value)
    if ($null -eq $Value) { return "Never" }
    try {
        $ticks = [int64]$Value
        if ($ticks -le 0 -or $ticks -eq [int64]::MaxValue) { return "Never" }
        return [DateTime]::FromFileTime($ticks).ToString("yyyy-MM-dd")
    }
    catch { return "Never" }
}

function Get-DirObjectInfo {
    # One lookup per object (cached): class, account name and, for accounts, the status fields.
    param([string]$Dn = "")
    if ($script:objInfoCache.ContainsKey($Dn)) { return $script:objInfoCache[$Dn] }

    $props = @("samAccountName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet")
    $obj   = Get-ADObject -Identity $Dn -Properties $props -ErrorAction Stop

    $class     = [string]$obj.ObjectClass
    $display   = [string]$obj.Name
    $enabled   = ""
    $lastLogon = ""
    $pwdNever  = ""
    $pwdSet    = ""

    $hasUac = ($null -ne $obj.userAccountControl)
    if ($hasUac) {
        $uac     = [int]$obj.userAccountControl
        $enabled = (($uac -band 2) -eq 0)
    }
    if ($class -eq "user" -or $class -eq "computer") {
        $lastLogon = ConvertFrom-FileTimeText $obj.lastLogonTimestamp
    }
    if ($class -eq "user" -and $hasUac) {
        $pwdNever = (($uac -band 65536) -ne 0)
        $pwdSet   = ConvertFrom-FileTimeText $obj.pwdLastSet
    }
    if ($class -eq "foreignSecurityPrincipal") {
        try   { $display = ([System.Security.Principal.SecurityIdentifier]$obj.Name).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $display = "Foreign principal " + $obj.Name }
    }

    $info = [PSCustomObject]@{
        Dn        = $Dn
        Class     = $class
        Display   = $display
        Sam       = [string]$obj.samAccountName
        Enabled   = $enabled
        LastLogon = $lastLogon
        PwdNever  = $pwdNever
        PwdSet    = $pwdSet
    }
    $script:objInfoCache[$Dn] = $info
    return $info
}

function New-MemberRow {
    param(
        $Info,
        [string]$TopGroup       = "",
        [string]$Path           = "",
        [int]$Depth             = 0,
        [string]$MembershipType = "Member"
    )
    [PSCustomObject]@{
        PrivilegedGroup      = $TopGroup
        MemberName           = $Info.Display
        SamAccountName       = $Info.Sam
        ObjectClass          = $Info.Class
        MembershipType       = $MembershipType
        Enabled              = $Info.Enabled
        LastLogonDate        = $Info.LastLogon
        PasswordNeverExpires = $Info.PwdNever
        PasswordLastSet      = $Info.PwdSet
        Depth                = $Depth + 1
        MembershipPath       = "$Path > $($Info.Display)"
        DistinguishedName    = $Info.Dn
    }
}

function Get-PrimaryGroupMembers {
    # Accounts whose PRIMARY group is this group are not in its member list.
    # Only groups of this domain can be checked here.
    param(
        [string]$GroupSid = "",
        [string]$TopGroup = "",
        [string]$Path     = "",
        [int]$Depth       = 0
    )
    if (-not $GroupSid.StartsWith("$($script:domainSid)-")) { return }
    $rid = $GroupSid.Substring($script:domainSid.Length + 1)
    if ($rid -notmatch '^\d+$') { return }

    try {
        $primaryObjs = @(Get-ADObject -SearchBase $script:domainDn -LDAPFilter "(primaryGroupID=$rid)" -ErrorAction Stop)
    }
    catch {
        Add-AuditError -SectionName "PrivilegedGroups" -Target "primary group $TopGroup" -Message $_.Exception.Message
        return
    }
    foreach ($po in $primaryObjs) {
        try   { $info = Get-DirObjectInfo -Dn $po.DistinguishedName }
        catch {
            Add-AuditError -SectionName "PrivilegedGroups" -Target $po.DistinguishedName -Message $_.Exception.Message
            continue
        }
        New-MemberRow -Info $info -TopGroup $TopGroup -Path $Path -Depth $Depth -MembershipType "PrimaryGroup"
    }
}

function Get-GroupMembersRecursive {
    param(
        [string]$GroupDn  = "",
        [string]$TopGroup = "",
        [string]$Path     = "",
        [int]$Depth       = 0,
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
        try   { $info = Get-DirObjectInfo -Dn $memberDn }
        catch {
            Add-AuditError -SectionName "PrivilegedGroups" -Target $memberDn -Message $_.Exception.Message
            continue
        }

        New-MemberRow -Info $info -TopGroup $TopGroup -Path $Path -Depth $Depth -MembershipType "Member"

        if ($info.Class -eq "group") {
            $childPath = "$Path > $($info.Display)"
            Get-GroupMembersRecursive -GroupDn $memberDn -TopGroup $TopGroup -Path $childPath -Depth ($Depth + 1) -Visited $Visited
        }
    }

    if ($null -ne $grp.SID) {
        Get-PrimaryGroupMembers -GroupSid $grp.SID.Value -TopGroup $TopGroup -Path $Path -Depth $Depth
    }
}


# ============================================================
# Start of run, then checks (logged before any check can fail)
# ============================================================
$sectionList = @($Section | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$runAll      = ($sectionList -contains "All")
$scopeText   = $(if ($SearchBase) { $SearchBase } else { "Entire domain" })
$sectionText = $(if ($runAll) { "All" } else { $sectionList -join ", " })

Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log "Mode: READ-ONLY - nothing in Active Directory is changed"
Write-Log "Scope   : $scopeText"
Write-Log "Sections: $sectionText"
Write-Log "Output  : $OutputDirectory"
Write-Log "Log file: $logFile"

if ($outputDirError) { Stop-WithError "Could not create output folder $OutputDirectory - $outputDirError" }

$badSections = @($sectionList | Where-Object { $validSections -notcontains $_ })
if ($badSections.Count -gt 0 -or $sectionList.Count -eq 0) {
    Stop-WithError ("Invalid -Section value(s): {0}. Use: {1}" -f ($badSections -join ", "), ($validSections -join ", "))
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Stop-WithError "The ActiveDirectory module is not installed. Install the RSAT Active Directory tools."
}
try   { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Stop-WithError "Could not load the ActiveDirectory module - $($_.Exception.Message)" }

# -- Domain information
try {
    $domain  = Get-ADDomain -ErrorAction Stop
    $rootDse = Get-ADRootDSE -ErrorAction Stop
}
catch {
    Stop-WithError "Could not read domain information - $($_.Exception.Message)"
}

$script:domainDn  = $domain.DistinguishedName
$script:domainSid = $domain.DomainSID.Value
$domainDn         = $script:domainDn
$domainSid        = $script:domainSid
$script:runAll      = $runAll
$script:sectionList = $sectionList

# Enterprise Admins and Schema Admins belong to the forest root domain
$forestRootSid = $domainSid
try {
    $forestRootName = (Get-ADForest -ErrorAction Stop).RootDomain
    $forestRootSid  = (Get-ADDomain -Identity $forestRootName -ErrorAction Stop).DomainSID.Value
}
catch {
    Write-Log "Could not read the forest root domain, so this domain's SID is used for Enterprise Admins and Schema Admins: $($_.Exception.Message)" -Level WARN
}

if ($SearchBase) {
    try   { $null = Get-ADObject -Identity $SearchBase -ErrorAction Stop }
    catch { Stop-WithError "SearchBase not found: $SearchBase" }
}

Write-Log "Domain  : $($domain.DNSRoot)"

# Default principals by SID (works on localized domains)
$alwaysHideSids = New-Object System.Collections.Generic.HashSet[string]
$watchSids      = New-Object System.Collections.Generic.HashSet[string]
foreach ($s in $wellKnownAlwaysHide) { [void]$alwaysHideSids.Add($s) }
foreach ($s in @("$domainSid-512", "$forestRootSid-519", "$domainSid-516", "$domainSid-521",
                 "$forestRootSid-498", "$domainSid-526", "$forestRootSid-527", "$domainSid-553")) {
    [void]$alwaysHideSids.Add($s)   # Domain Admins, Enterprise Admins, Domain Controllers, RODCs, Enterprise RODCs, Key Admins, Enterprise Key Admins, RAS and IAS
}
foreach ($s in $wellKnownWatch) { [void]$watchSids.Add($s) }

$script:defaultSidNames = @{
    "S-1-5-18" = "NT AUTHORITY\SYSTEM"; "S-1-5-10" = "NT AUTHORITY\SELF"
    "S-1-5-9"  = "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS"; "S-1-3-0" = "CREATOR OWNER"
    "S-1-5-32-544" = "BUILTIN\Administrators"; "S-1-5-32-560" = "BUILTIN\Windows Authorization Access Group"
    "S-1-5-32-561" = "BUILTIN\Terminal Server License Servers"; "S-1-1-0" = "Everyone"
    "S-1-5-11" = "NT AUTHORITY\Authenticated Users"; "S-1-5-32-554" = "BUILTIN\Pre-Windows 2000 Compatible Access"
    "S-1-5-32-548" = "BUILTIN\Account Operators"; "S-1-5-32-550" = "BUILTIN\Print Operators"
    "$domainSid-512" = "Domain Admins"; "$forestRootSid-519" = "Enterprise Admins"
    "$domainSid-516" = "Domain Controllers"; "$domainSid-521" = "Read-only Domain Controllers"
    "$forestRootSid-498" = "Enterprise Read-only Domain Controllers"; "$domainSid-526" = "Key Admins"
    "$forestRootSid-527" = "Enterprise Key Admins"; "$domainSid-553" = "RAS and IAS Servers"
}


# =====================================================================
# SECTION 1 - OU PERMISSIONS
# =====================================================================
if (Test-Section "OUPermissions") {
    Write-Log "--- OU permissions ---"

    # Build a GUID to name map from the schema and the extended rights container
    Write-Log "Resolving permission GUIDs from the schema..."
    $guidMap = @{}
    $guidMap["00000000-0000-0000-0000-000000000000"] = "(all)"

    try {
        $schemaObjs = Get-ADObject -SearchBase $rootDse.schemaNamingContext -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName, schemaIDGUID -ErrorAction Stop
        foreach ($so in $schemaObjs) {
            $key = ([guid]$so.schemaIDGUID).ToString().ToLower()
            $guidMap[$key] = $(if ($so.lDAPDisplayName) { [string]$so.lDAPDisplayName } else { [string]$so.Name })
        }

        $rightsDn  = "CN=Extended-Rights," + $rootDse.configurationNamingContext
        $rightObjs = Get-ADObject -SearchBase $rightsDn -LDAPFilter "(objectClass=controlAccessRight)" -Properties displayName, rightsGUID -ErrorAction Stop
        foreach ($ro in $rightObjs) {
            if ($ro.rightsGUID) {
                $key = ([string]$ro.rightsGUID).ToLower()
                $guidMap[$key] = $(if ($ro.displayName) { [string]$ro.displayName } else { [string]$ro.Name })
            }
        }
        Write-Log "Resolved $($guidMap.Count) GUIDs."
    }
    catch {
        Add-AuditError -SectionName "OUPermissions" -Target "GUID map" -Message $_.Exception.Message
        Write-Log "Could not fully resolve GUIDs, raw GUIDs will be shown. $($_.Exception.Message)" -Level WARN
    }

    # Work out which objects to read ACLs from
    $targets  = [System.Collections.Generic.List[object]]::new()
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

    Write-Log "Reading permissions on $($targets.Count) objects..."

    $ouResults   = [System.Collections.Generic.List[object]]::new()
    $hiddenCount = 0
    $keptCount   = 0
    $i = 0

    foreach ($t in $targets) {
        $i++
        if (($i % 25) -eq 0 -or $i -eq $targets.Count) {
            Write-Progress -Activity "Reading OU permissions" -Status "$i of $($targets.Count)" -PercentComplete (($i / $targets.Count) * 100)
        }

        # Read the ACL with Get-ADObject; fall back to the AD: drive (Get-Acl) if that fails
        $acl = $null
        try {
            $secObj = Get-ADObject -Identity $t.DN -Properties nTSecurityDescriptor -ErrorAction Stop
            $acl    = $secObj.nTSecurityDescriptor
            if ($null -eq $acl) { throw "nTSecurityDescriptor came back empty (no permission to read the ACL?)" }
        }
        catch {
            $firstError = $_.Exception.Message
            try {
                $acl = Get-Acl -LiteralPath ("AD:\" + $t.DN) -ErrorAction Stop
            }
            catch {
                $secondError = $_.Exception.Message
                Add-AuditError -SectionName "OUPermissions" -Target $t.DN -Message "Get-ADObject: $firstError | Get-Acl: $secondError"
                continue
            }
        }

        # Ask for SIDs directly: no name lookup per entry, and default principals are matched by SID
        try {
            $rules = @($acl.GetAccessRules($true, [bool]$IncludeInherited, [System.Security.Principal.SecurityIdentifier]))
        }
        catch {
            Add-AuditError -SectionName "OUPermissions" -Target $t.DN -Message "Could not read the access rules: $($_.Exception.Message)"
            continue
        }

        foreach ($ace in $rules) {
            $sid       = $ace.IdentityReference
            $sidValue  = $sid.Value
            $resolved  = Get-SidName -Sid $sid
            $identity  = $(if ($resolved) { $resolved } else { $sidValue })

            $inAlways  = $alwaysHideSids.Contains($sidValue)
            $inWatch   = $watchSids.Contains($sidValue)
            $isDefault = ($inAlways -or $inWatch)

            $objGuid = $ace.ObjectType.ToString().ToLower()
            $inhGuid = $ace.InheritedObjectType.ToString().ToLower()
            $objName = $(if ($guidMap.ContainsKey($objGuid)) { $guidMap[$objGuid] } else { $objGuid })
            $inhName = $(if ($guidMap.ContainsKey($inhGuid)) { $guidMap[$inhGuid] } else { $inhGuid })

            $rights = $ace.ActiveDirectoryRights.ToString()
            $access = $ace.AccessControlType.ToString()

            $sidStatus = "Resolved"
            if (-not $resolved) {
                $sidStatus = $(if ($sidValue.StartsWith("$domainSid-")) { "Orphaned" } else { "Unresolved" })
            }

            $note = Get-RightsNote -Rights $rights -ObjectName $objName -Access $access
            if ($sidStatus -eq "Orphaned") {
                $prefix = "Orphaned SID (account no longer exists)"
                $note   = $(if ($note) { "$prefix; $note" } else { $prefix })
            }
            elseif ($sidStatus -eq "Unresolved") {
                $prefix = "Unresolved SID (deleted account, or its domain is not reachable)"
                $note   = $(if ($note) { "$prefix; $note" } else { $prefix })
            }

            # -HideWellKnown: always-default principals are hidden when they allow. Broad
            # groups (Everyone, Authenticated Users and so on) are hidden only if they
            # grant nothing write-type and have no note; otherwise they stay in the report.
            if ($HideWellKnown -and $isDefault) {
                $hide = $false
                if ($access -eq "Allow") {
                    if ($inAlways) { $hide = $true }
                    elseif (-not $note -and $rights -notmatch $writeRightsPattern) { $hide = $true }
                }
                if ($hide) { $hiddenCount++; continue }
                $keptCount++
            }

            $ouResults.Add([PSCustomObject]@{
                ObjectDN                = $t.DN
                ObjectKind              = $t.Kind
                Principal               = $identity
                PrincipalSid            = $sidValue
                SidStatus               = $sidStatus
                DefaultPrincipal        = $isDefault
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
    $flaggedRows  = @($ouResults | Where-Object { $_.Notes -and -not $_.DefaultPrincipal })
    $orphanedRows = @($ouResults | Where-Object { $_.SidStatus -eq "Orphaned" })
    $unresolvedRows = @($ouResults | Where-Object { $_.SidStatus -eq "Unresolved" })

    Write-Log "Objects read             : $($targets.Count)"
    Write-Log "Permission entries       : $($ouResults.Count)"
    if ($HideWellKnown) {
        Write-Log "Hidden by -HideWellKnown : $hiddenCount entries"
        Write-Log "Default principals kept  : $keptCount entries (denies, or broad groups with write-type rights)"
    }
    Write-Log "Non-default principals   : $($nonDefault.Count) entries" -Level WARN
    Write-Log "Flagged (non-default)    : $($flaggedRows.Count) entries" -Level WARN
    Write-Log "Orphaned SIDs            : $($orphanedRows.Count) entries" -Level $(if ($orphanedRows.Count -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-Log "Unresolved SIDs          : $($unresolvedRows.Count) entries" -Level $(if ($unresolvedRows.Count -gt 0) { "WARN" } else { "SUCCESS" })

    if ($nonDefault.Count -gt 0) {
        Write-Log "Top non-default principals by number of entries:"
        $topPrincipals = @($nonDefault | Group-Object Principal | Sort-Object Count -Descending | Select-Object -First 10)
        Write-LogTable -Rows $topPrincipals -Properties @("Count", "Name")
    }
}


# =====================================================================
# SECTION 2 - PRIVILEGED GROUPS
# =====================================================================
if (Test-Section "PrivilegedGroups") {
    Write-Log "--- Privileged group membership ---"

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

    $privResults  = [System.Collections.Generic.List[object]]::new()
    $groupSummary = [System.Collections.Generic.List[object]]::new()

    foreach ($g in $groupList) {
        try {
            $grp = Get-ADGroup -Identity $g.Identity -ErrorAction Stop
        }
        catch {
            Add-AuditError -SectionName "PrivilegedGroups" -Target $g.Label -Message "Group not found or not readable: $($_.Exception.Message)"
            continue
        }

        $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $members = @(Get-GroupMembersRecursive -GroupDn $grp.DistinguishedName -TopGroup $g.Label -Path $g.Label -Depth 0 -Visited $visited)

        foreach ($m in $members) { $privResults.Add($m) }

        $accounts = @($members | Where-Object { $_.ObjectClass -ne "group" })
        $groupSummary.Add([PSCustomObject]@{
            Group            = $g.Label
            Accounts         = $accounts.Count
            ViaPrimaryGroup  = @($members | Where-Object { $_.MembershipType -eq "PrimaryGroup" }).Count
            Disabled         = @($accounts | Where-Object { $_.Enabled -eq $false }).Count
            PasswordNeverExp = @($accounts | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
            NestedGroups     = @($members | Where-Object { $_.ObjectClass -eq "group" }).Count
        })
    }

    Export-AuditCsv -Rows $privResults -Name "PrivilegedGroupMembers"

    Write-Log "Groups checked: $($groupSummary.Count) of $($groupList.Count)"
    Write-Log "Privileged group summary:"
    Write-LogTable -Rows $groupSummary -Properties @("Group", "Accounts", "ViaPrimaryGroup", "Disabled", "PasswordNeverExp", "NestedGroups")
}


# =====================================================================
# SECTION 3 - GPO PERMISSIONS
# =====================================================================
if (Test-Section "GPOPermissions") {
    Write-Log "--- GPO permissions ---"

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "SKIPPED: GroupPolicy module not available. Install the RSAT Group Policy Management Tools." -Level WARN
        Add-AuditError -SectionName "GPOPermissions" -Target "GroupPolicy module" -Message "Module not available, section skipped"
    }
    else {
        Import-Module GroupPolicy

        # Default editors, by SID: Domain Admins, Enterprise Admins, SYSTEM
        $gpoDefaultEditorSids = @("$domainSid-512", "$forestRootSid-519", "S-1-5-18")

        # When scoped, only report GPOs linked within the scope
        $scopeGpoIds = $null
        if ($SearchBase) {
            $scopeGpoIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            try {
                $linkObjs = Get-ADObject -SearchBase $SearchBase -SearchScope Subtree -LDAPFilter "(gPLink=*)" -Properties gPLink -ErrorAction Stop
                foreach ($lo in $linkObjs) {
                    foreach ($gm in [regex]::Matches([string]$lo.gPLink, '\{[0-9A-Fa-f\-]{36}\}')) {
                        [void]$scopeGpoIds.Add($gm.Value)
                    }
                }
            }
            catch {
                Add-AuditError -SectionName "GPOPermissions" -Target $SearchBase -Message $_.Exception.Message
            }
            Write-Log "Scoped to $($scopeGpoIds.Count) GPOs linked at or below the SearchBase."
        }

        $gpoResults = [System.Collections.Generic.List[object]]::new()

        try {
            $allGpos = @(Get-GPO -All -ErrorAction Stop)
        }
        catch {
            $allGpos = @()
            Add-AuditError -SectionName "GPOPermissions" -Target "Get-GPO" -Message $_.Exception.Message
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
                $perm      = [string]$p.Permission
                $note      = ""
                $trustee   = $p.Trustee
                $trusteeSid = $(if ($null -ne $trustee.Sid) { $trustee.Sid.Value } else { "" })
                $editRight = ($perm -eq "GpoEdit" -or $perm -eq "GpoEditDeleteModifySecurity" -or $perm -eq "GpoCustom")
                if ($editRight -and -not $p.Denied) {
                    if ($gpoDefaultEditorSids -notcontains $trusteeSid) { $note = "Non-default editor" }
                }

                $gpoResults.Add([PSCustomObject]@{
                    GpoName       = $gpo.DisplayName
                    GpoId         = $gpo.Id.ToString()
                    GpoStatus     = [string]$gpo.GpoStatus
                    Trustee       = $trustee.Name
                    TrusteeDomain = $trustee.Domain
                    TrusteeSid    = $trusteeSid
                    TrusteeType   = [string]$trustee.SidType
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
        Write-Log "GPOs reported            : $gposRead"
        Write-Log "Non-default editors      : $($flaggedGp.Count) entries" -Level $(if ($flaggedGp.Count -gt 0) { "WARN" } else { "SUCCESS" })
        if ($flaggedGp.Count -gt 0) {
            $topEditors = @($flaggedGp | Group-Object Trustee | Sort-Object Count -Descending | Select-Object -First 10)
            Write-LogTable -Rows $topEditors -Properties @("Count", "Name")
        }
    }
}


# =====================================================================
# SECTION 4 - KERBEROS DELEGATION
# =====================================================================
if (Test-Section "KerberosDelegation") {
    Write-Log "--- Kerberos delegation ---"

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
    }

    foreach ($o in $krbObjs) {
        $uac           = [int]$o.userAccountControl
        $unconstrained = (($uac -band 524288) -ne 0)
        $protoTransit  = (($uac -band 16777216) -ne 0)
        $disabled      = (($uac -band 2) -ne 0)
        $pgid          = [int]$o.primaryGroupID
        $isDc          = ($pgid -eq 516 -or $pgid -eq 521)

        $delegTargets   = $o.'msDS-AllowedToDelegateTo'
        $hasConstrained = ($null -ne $delegTargets -and @($delegTargets).Count -gt 0)
        $targetText     = $(if ($hasConstrained) { (@($delegTargets) -join "; ") } else { "" })

        $rbcd     = $o.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $hasRbcd  = ($null -ne $rbcd)
        $rbcdText = ""
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
            Name                  = $o.Name
            ObjectClass           = [string]$o.ObjectClass
            Enabled               = (-not $disabled)
            IsDomainController    = $isDc
            DelegationTypes       = ($types -join "; ")
            ConstrainedTargets    = $targetText
            RbcdAllowedPrincipals = $rbcdText
            Risk                  = $risk
            DistinguishedName     = $o.DistinguishedName
        })
    }

    Export-AuditCsv -Rows $krbResults -Name "KerberosDelegation"

    $highCount = @($krbResults | Where-Object { $_.Risk -like "HIGH*" }).Count
    $medCount  = @($krbResults | Where-Object { $_.Risk -like "MEDIUM*" }).Count
    Write-Log "Accounts with delegation : $($krbResults.Count)"
    Write-Log "High risk                : $highCount" -Level $(if ($highCount -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-Log "Medium risk              : $medCount" -Level $(if ($medCount -gt 0) { "WARN" } else { "SUCCESS" })
}


# =====================================================================
# ERRORS AND FINISH
# =====================================================================
$errorCount = $script:auditErrors.Count
if ($errorCount -gt 0) {
    Export-AuditCsv -Rows $script:auditErrors -Name "Errors"
    Write-Log "$errorCount item(s) could not be read. See the Errors report and the warnings above." -Level WARN
}

$fileCount = $script:writtenFiles.Count
if ($fileCount -gt 0) {
    Write-Log "Files written:" -Level SUCCESS
    foreach ($written in $script:writtenFiles) { Write-Log "  $written" -Level SUCCESS }
}
else {
    Write-Log "No report files were written (no rows in any section)." -Level WARN
}

Write-Log "$scriptName finished"
if ($errorCount -gt 0) { exit 2 }

# ============================================================
# Set-MerakiNetworkACL.ps1
# Version 2.7
#
# Applies or restores a Meraki MS network-level switch ACL
# driven by a CSV policy file. Supports multiple server/port
# restrictions in a single ruleset, making it portable across
# networks and orgs without script changes.
#
# Enforcement note: This ACL applies only to inter-VLAN routed
# traffic. Intra-VLAN traffic (hosts on the same subnet as the
# server) bypasses routing and will not be filtered here.
# Restrict same-subnet access at the server host firewall.
#
# POLICY CSV FILE:
#   By default the script looks for MerakiACLPolicy.csv in the
#   SAME DIRECTORY as this script. Place the CSV there, or
#   supply the full path via -PolicyCsv if it lives elsewhere.
#
# POLICY CSV FORMAT:
#   ServerIp,Port,Protocol,AllowedSources,Comment
#   192.168.15.100,80;443,tcp,192.168.15.0/24;192.168.4.0/24;10.10.4.0/23;10.10.6.0/24,Webserver HTTP+HTTPS
#   192.168.15.200,3389,tcp,192.168.4.0/24;10.10.4.0/23,RDP Server
#
#   Columns:
#     ServerIp       - IPv4 address of the server to restrict
#     Port           - destination port. Use semicolons to separate
#                      multiple ports or ranges -- NOT commas (commas
#                      are the CSV field delimiter and will break
#                      parsing). Examples:
#                        443        single port
#                        80;443     two ports
#                        8080-8090  range
#                        80;443;8080-8090  mixed
#     Protocol       - tcp, udp, or any
#     AllowedSources - semicolon-separated list of CIDRs
#                      permitted to reach this server/port
#     Comment        - free-text label (no commas)
#
#   Row order does not matter -- rules are built per-row with
#   allow entries before the row's deny, and the global
#   default-permit is appended last.
#
# API KEY RESOLUTION (in order):
#   1. -ApiKey parameter (plain text -- suitable for automation)
#   2. Encrypted file at -KeyFile path (DPAPI, same user/machine)
#   3. Interactive Read-Host prompt (masked, never in history)
#      Offers to save as encrypted file for future runs.
#
# PARAMETERS:
#   -ApiKey        Meraki Dashboard API key (plain text).
#   -KeyFile       Path to DPAPI-encrypted API key file.
#                  Default: ~\.meraki_api_key
#   -NetworkId     Target network ID.
#                  Default: N_646829496481089841
#   -PolicyCsv     Path to the CSV policy file.
#                  Default: MerakiACLPolicy.csv in the same
#                  directory as this script ($PSScriptRoot).
#                  Edit this parameter default or use -PolicyCsv
#                  if the file lives somewhere else.
#   -BackupDir     Directory for ACL backup JSON files.
#                  Default: MerakiACLBackups\ subfolder in the
#                  same directory as this script ($PSScriptRoot).
#   -Apply         Push the ACL to the network. Without this
#                  switch the script runs in preview mode only.
#   -Force         Required when meaningful ACL rules already
#                  exist. Prompts for confirmation when running
#                  interactively.
#   -Restore       Restore the most recent backup for this
#                  network from -BackupDir instead of applying
#                  a policy. Use -BackupFile to target a
#                  specific backup. Requires -Apply to execute;
#                  without -Apply runs in preview mode.
#   -BackupFile    Explicit path to a backup JSON to restore.
#                  Overrides auto-selection when used with
#                  -Restore.
#   -Backup        Read the current ACL from the network and save
#                  it to -BackupDir without making any changes.
#                  Useful for snapshotting before manual edits or
#                  before running this script for the first time.
#   -AutoSelectLatestBackup
#                  When multiple backups exist for this network,
#                  skip the selection prompt and automatically
#                  use the most recent one. Default behavior
#                  when -Restore finds multiple backups is to
#                  prompt for a selection.
#
# USAGE:
#   # Preview policy (CSV must be in same folder as script, or use -PolicyCsv)
#   .\Set-MerakiNetworkACL_v2.4.ps1
#
#   # Preview with an explicit CSV path
#   .\Set-MerakiNetworkACL_v2.4.ps1 -PolicyCsv 'C:\Meraki\MyPolicy.csv'
#
#   # Apply policy from CSV
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Apply
#
#   # Apply to a different network (same policy CSV)
#   .\Set-MerakiNetworkACL_v2.4.ps1 -NetworkId 'N_xxxx' -Apply
#
#   # Apply with a CSV stored elsewhere
#   .\Set-MerakiNetworkACL_v2.4.ps1 -PolicyCsv 'C:\Meraki\MyPolicy.csv' -Apply
#
#   # Snapshot the current ACL before making changes (recommended first step)
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Backup
#
#   # Preview what restore would push (no changes)
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Restore
#
#   # Restore most recent backup (prompts if multiple exist)
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Restore -Apply
#
#   # Restore most recent backup without prompting
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Restore -Apply -AutoSelectLatestBackup
#
#   # Restore a specific backup file
#   .\Set-MerakiNetworkACL_v2.4.ps1 -Restore -Apply -BackupFile 'C:\...\ACL_Backup_N_xxx_20261023_152000.json'
#
# v1.0 - 2026-10-23 - Initial release
# v1.1 - 2026-10-23 - Added SecureString key resolution, IP/CIDR
#                     validation, ACL backup, post-apply verification,
#                     null guards, interactive Force confirmation
# v1.2 - 2026-10-23 - Fixed ACL endpoint to network-level
#                     /switch/accessControlLists; removed -StackId;
#                     added vlan field to rule schema
# v2.0 - 2026-10-23 - Redesigned as CSV-driven policy script.
#                     Added -PolicyCsv for multi-server/port rules.
#                     Added -Restore / -BackupFile /
#                     -PromptOnMultipleBackups for one-switch rollback.
#                     NetworkId now a portable parameter -- same CSV
#                     applies to any network.
# v2.1 - 2026-10-23 - Changed -PromptOnMultipleBackups to
#                     -AutoSelectLatestBackup (inverted default).
#                     Prompt on multiple backups is now the default
#                     when -Restore is used; add -AutoSelectLatestBackup
#                     to skip the prompt and use the most recent file.
# v2.2 - 2026-10-23 - Port field now accepts semicolon-separated ports
#                     and ranges (e.g. 80;443 or 8080-8090). Script
#                     translates semicolons to commas for the API.
#                     Added -Backup for standalone ACL snapshots
#                     without applying any policy changes.
# v2.3 - 2026-10-23 - Fixed port delimiter in CSV from comma to
#                     semicolon (commas break CSV field parsing).
#                     Updated validation regex and rule-builder to
#                     split on semicolon and rejoin with comma for
#                     the API. Updated CSV format docs and example.
# v2.4 - 2026-10-23 - PolicyCsv default changed from user profile
#                     to $PSScriptRoot (same directory as the script).
#                     Added POLICY CSV FILE section to header calling
#                     out default location. Added -PolicyCsv usage
#                     examples. Added -AutoSelectLatestBackup and
#                     -Backup usage examples.
# v2.5 - 2026-10-23 - Fixed PropertyNotFoundException under
#                     Set-StrictMode -Version Latest when CSV or
#                     backup JSON contains only one row/rule.
#                     Import-Csv and ConvertFrom-Json results now
#                     wrapped in @() to guarantee array type.
# v2.6 - 2026-10-23 - BackupDir default changed from user profile
#                     to $PSScriptRoot\MerakiACLBackups (same folder
#                     as the script). Updated -BackupDir param doc.
# v2.7 - 2026-10-23 - Fixed remaining PropertyNotFoundException under
#                     Set-StrictMode -Version Latest. $missing and
#                     $sources Where-Object pipelines now wrapped in
#                     @() to guarantee array type when no items match.
# ============================================================

[CmdletBinding()]
param (
    [string] $ApiKey,
    [string] $KeyFile       = (Join-Path $env:USERPROFILE '.meraki_api_key'),
    [string] $NetworkId     = 'N_646829496481089841',
    [string] $PolicyCsv     = (Join-Path $PSScriptRoot 'MerakiACLPolicy.csv'),
    [string] $BackupDir     = (Join-Path $PSScriptRoot 'MerakiACLBackups'),
    [string] $BackupFile,
    [switch] $Apply,
    [switch] $Force,
    [switch] $Restore,
    [switch] $Backup,
    [switch] $AutoSelectLatestBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptVersion         = '2.7'
$baseUrl               = 'https://api.meraki.com/api/v1'

# ============================================================
# Functions
# ============================================================
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')]
        [string]$Level = 'INFO'
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'INFO'    { 'Cyan'   }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red'    }
        'SUCCESS' { 'Green'  }
        'DEBUG'   { 'Gray'   }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

function Invoke-MerakiRequest {
    param (
        [string]$Uri,
        [string]$Method = 'GET',
        [object]$Body
    )
    $params = @{
        Uri     = $Uri
        Method  = $Method
        Headers = @{
            'X-Cisco-Meraki-API-Key' = $script:ApiKey
            'Content-Type'           = 'application/json'
        }
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }
    Invoke-RestMethod @params
}

function Get-ResolvedApiKey {
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Log 'API key sourced from -ApiKey parameter.' DEBUG
        return $ApiKey
    }
    if (Test-Path $KeyFile) {
        Write-Log "API key sourced from encrypted file: $KeyFile" DEBUG
        try {
            $ss = Get-Content $KeyFile | ConvertTo-SecureString
            return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                       [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
        }
        catch {
            Write-Log "Failed to decrypt key file '$KeyFile': $_. Falling back to prompt." WARN
        }
    }
    Write-Log 'No API key supplied. Enter key interactively (input is masked).' WARN
    $ss = Read-Host -Prompt 'Meraki API Key' -AsSecureString
    if ($ss.Length -eq 0) {
        Write-Log 'No API key entered.' ERROR
        exit 1
    }
    $save = Read-Host "Save encrypted key to '$KeyFile' for future runs? (y/N)"
    if ($save -eq 'y') {
        try {
            $dir = Split-Path $KeyFile -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $ss | ConvertFrom-SecureString | Set-Content $KeyFile
            Write-Log "Key saved to $KeyFile (DPAPI-encrypted -- this user/machine only)." SUCCESS
        }
        catch { Write-Log "Could not save key file: $_" WARN }
    }
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
               [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
}

function ConvertTo-PlainRule {
    # Normalise a PSCustomObject from JSON back to a hashtable for display/compare
    param ([object]$Rule)
    @{
        comment   = $Rule.comment
        policy    = $Rule.policy
        ipVersion = $Rule.ipVersion
        protocol  = $Rule.protocol
        srcCidr   = $Rule.srcCidr
        srcPort   = $Rule.srcPort
        dstCidr   = $Rule.dstCidr
        dstPort   = $Rule.dstPort
        vlan      = $Rule.vlan
    }
}

function Show-Ruleset {
    param ([System.Collections.Generic.List[hashtable]]$Rules)
    Write-Host ''
    $i = 1
    foreach ($rule in $Rules) {
        # Write-Host used here intentionally to apply per-rule color by
        # policy; Write-Log does not support arbitrary foreground color.
        $color = if ($rule.policy -eq 'allow') { 'Green' } else { 'Red' }
        Write-Host ("  [{0:D2}] [{1,-5}] {2,-4}  src={3}:{4}  dst={5}:{6}  # {7}" -f `
            $i,
            $rule.policy.ToUpper(),
            $rule.protocol,
            $rule.srcCidr, $rule.srcPort,
            $rule.dstCidr, $rule.dstPort,
            $rule.comment) -ForegroundColor $color
        $i++
    }
    Write-Host ''
}

function Invoke-AclPut {
    param (
        [string]$Uri,
        [System.Collections.Generic.List[hashtable]]$Rules
    )
    Write-Log 'Pushing ACL to network...'
    try {
        $body   = @{ rules = $Rules.ToArray() }
        $result = Invoke-MerakiRequest -Uri $Uri -Method PUT -Body $body
        Write-Log "PUT accepted -- $(@($result.rules).Count) rule(s) reported by API." SUCCESS
    }
    catch {
        Write-Log "Failed to apply ACL: $_" ERROR
        exit 1
    }

    Write-Log 'Verifying applied ACL...'
    try {
        $live      = Invoke-MerakiRequest -Uri $Uri
        $liveRules = @($live.rules)
        $expCount  = $Rules.Count

        if ($liveRules.Count -ne $expCount) {
            Write-Log "Rule count mismatch: expected $expCount, live network reports $($liveRules.Count)." WARN
            Write-Log 'Review the ACL in the Meraki dashboard.' WARN
            return
        }

        $mismatch = $false
        for ($j = 0; $j -lt $expCount; $j++) {
            $exp  = $Rules[$j]
            $live_rule = $liveRules[$j]
            if ($exp.policy   -ne $live_rule.policy   -or
                $exp.srcCidr  -ne $live_rule.srcCidr   -or
                $exp.dstCidr  -ne $live_rule.dstCidr   -or
                $exp.dstPort  -ne $live_rule.dstPort   -or
                $exp.protocol -ne $live_rule.protocol) {
                Write-Log ("Rule [{0:D2}] mismatch: expected [{1}] {2} src={3} dst={4}:{5}" -f `
                    ($j + 1), $exp.policy, $exp.protocol,
                    $exp.srcCidr, $exp.dstCidr, $exp.dstPort) WARN
                $mismatch = $true
            }
        }
        if (-not $mismatch) {
            Write-Log "Verification passed -- all $($liveRules.Count) rule(s) confirmed on network." SUCCESS
        }
        else {
            Write-Log 'One or more rules did not match. Review the ACL in the Meraki dashboard.' WARN
        }
    }
    catch {
        Write-Log "Verification GET failed: $_" WARN
        Write-Log 'Could not confirm live state -- check the Meraki dashboard.' WARN
    }
}

function Backup-ExistingAcl {
    param ([object]$Existing)
    if ($null -eq $Existing -or $null -eq $Existing.rules) { return }

    $meaningful = @($Existing.rules | Where-Object {
        -not (
            $_.policy   -in @('allow','any') -and
            $_.srcCidr  -eq 'any'            -and
            $_.dstCidr  -eq 'any'            -and
            $_.protocol -eq 'any'
        )
    })
    if ($meaningful.Count -eq 0) { return }

    try {
        if (-not (Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        }
        $ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
        $file       = Join-Path $BackupDir "ACL_Backup_${NetworkId}_${ts}.json"
        $Existing.rules | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
        Write-Log "Existing ACL backed up to: $file" SUCCESS
    }
    catch {
        Write-Log "Failed to save ACL backup: $_" ERROR
        Write-Log 'Aborting -- fix the backup path or use a different -BackupDir.' ERROR
        exit 1
    }
}

function Confirm-Overwrite {
    if ([System.Environment]::UserInteractive) {
        $confirm = Read-Host 'Type YES to confirm overwrite of existing rules'
        if ($confirm -ne 'YES') {
            Write-Log 'Overwrite not confirmed. Exiting.' WARN
            exit 0
        }
    }
}

# ============================================================
# Parameter validation
# ============================================================
$validationErrors = @()
if ([string]::IsNullOrWhiteSpace($NetworkId)) { $validationErrors += 'NetworkId is required.' }

if (-not $Restore) {
    if ([string]::IsNullOrWhiteSpace($PolicyCsv)) {
        $validationErrors += 'PolicyCsv is required when not using -Restore.'
    }
    elseif (-not (Test-Path $PolicyCsv)) {
        $validationErrors += "PolicyCsv not found: $PolicyCsv"
    }
}

if ($validationErrors.Count -gt 0) {
    $validationErrors | ForEach-Object { Write-Log $_ ERROR }
    exit 1
}

# ============================================================
# API key resolution
# ============================================================
$ApiKey = Get-ResolvedApiKey
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Log 'API key could not be resolved.' ERROR
    exit 1
}

# ============================================================
# Header
# ============================================================
$mode    = if ($Apply) { 'APPLY' } else { 'PREVIEW' }
$opLabel = if ($Restore) { 'RESTORE' } else { 'POLICY' }
$aclUri  = "$baseUrl/networks/$NetworkId/switch/accessControlLists"

Write-Log "Set-MerakiNetworkACL v$ScriptVersion -- Mode: $mode | Operation: $opLabel"
Write-Log "Network ID  : $NetworkId"
Write-Log "ACL endpoint: $aclUri"
Write-Log "Backup dir  : $BackupDir"

# ============================================================
# BACKUP path
# ============================================================
if ($Backup) {
    Write-Log 'Reading current network switch ACL for snapshot...'
    try {
        $snapExisting = Invoke-MerakiRequest -Uri $aclUri
    }
    catch {
        Write-Log "Failed to read ACL: $_" ERROR
        exit 1
    }

    if ($null -eq $snapExisting -or $null -eq $snapExisting.rules -or @($snapExisting.rules).Count -eq 0) {
        Write-Log 'No rules found on network -- nothing to back up.' WARN
        exit 0
    }

    try {
        if (-not (Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
        }
        $ts       = Get-Date -Format 'yyyyMMdd_HHmmss'
        $snapFile = Join-Path $BackupDir "ACL_Backup_${NetworkId}_${ts}.json"
        $snapExisting.rules | ConvertTo-Json -Depth 10 | Set-Content -Path $snapFile -Encoding UTF8
        Write-Log "ACL snapshot saved ($(@($snapExisting.rules).Count) rule(s)): $snapFile" SUCCESS
    }
    catch {
        Write-Log "Failed to save backup: $_" ERROR
        exit 1
    }
    exit 0
}

# ============================================================
# RESTORE path
# ============================================================
if ($Restore) {

    # Resolve backup file to restore
    if (-not [string]::IsNullOrWhiteSpace($BackupFile)) {
        if (-not (Test-Path $BackupFile)) {
            Write-Log "BackupFile not found: $BackupFile" ERROR
            exit 1
        }
        $resolvedBackup = $BackupFile
        Write-Log "Restore source (explicit): $resolvedBackup"
    }
    else {
        # Auto-select from BackupDir
        $pattern  = Join-Path $BackupDir "ACL_Backup_${NetworkId}_*.json"
        $backups  = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending)

        if ($backups.Count -eq 0) {
            Write-Log "No backup files found for network '$NetworkId' in: $BackupDir" ERROR
            Write-Log 'Use -BackupFile to specify a backup explicitly.' ERROR
            exit 1
        }

        if ($backups.Count -gt 1 -and -not $AutoSelectLatestBackup) {
            Write-Log "$($backups.Count) backup(s) found. Select one:" INFO
            for ($k = 0; $k -lt $backups.Count; $k++) {
                Write-Host ("  [{0}] {1}  ({2})" -f $k, $backups[$k].Name,
                    $backups[$k].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
            }
            $pick = Read-Host 'Enter number'
            if ($pick -notmatch '^\d+$' -or [int]$pick -ge $backups.Count) {
                Write-Log 'Invalid selection. Exiting.' ERROR
                exit 1
            }
            $resolvedBackup = $backups[[int]$pick].FullName
        }
        else {
            $resolvedBackup = $backups[0].FullName
            if ($backups.Count -gt 1) {
                Write-Log "$($backups.Count) backup(s) found -- auto-selecting most recent (-AutoSelectLatestBackup)." INFO
            }
        }
        Write-Log "Restore source (auto): $resolvedBackup"
    }

    # Load backup
    try {
        $backupRules = @(Get-Content $resolvedBackup -Raw | ConvertFrom-Json)
    }
    catch {
        Write-Log "Failed to read backup file: $_" ERROR
        exit 1
    }

    # Convert to List[hashtable] for display and PUT
    $restoreList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($r in $backupRules) { $restoreList.Add((ConvertTo-PlainRule $r)) }

    Write-Log "=== Rules to be restored ($($restoreList.Count) total) ==="
    Show-Ruleset $restoreList

    if (-not $Apply) {
        Write-Log 'Preview complete. Re-run with -Restore -Apply to push the restored ruleset.' INFO
        exit 0
    }

    # Read live ACL and back it up before overwriting
    try {
        $liveExisting = Invoke-MerakiRequest -Uri $aclUri
        Backup-ExistingAcl $liveExisting
    }
    catch { Write-Log "Could not read/backup current ACL: $_" WARN }

    Invoke-AclPut -Uri $aclUri -Rules $restoreList
    Write-Log 'Done.'
    exit 0
}

# ============================================================
# POLICY path -- read and validate CSV
# ============================================================
Write-Log "Reading policy CSV: $PolicyCsv"
try {
    $policyRows = @(Import-Csv -Path $PolicyCsv)
}
catch {
    Write-Log "Failed to read policy CSV: $_" ERROR
    exit 1
}

if ($policyRows.Count -eq 0) {
    Write-Log 'Policy CSV contains no rows.' ERROR
    exit 1
}

# Validate required columns
$requiredCols = @('ServerIp','Port','Protocol','AllowedSources','Comment')
$csvCols      = $policyRows[0].PSObject.Properties.Name
$missing      = @($requiredCols | Where-Object { $_ -notin $csvCols })
if ($missing.Count -gt 0) {
    Write-Log "Policy CSV is missing required column(s): $($missing -join ', ')" ERROR
    exit 1
}

$csvErrors = @()
foreach ($row in $policyRows) {
    if ($row.ServerIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $csvErrors += "Row '$($row.Comment)': ServerIp '$($row.ServerIp)' is not a valid IPv4 address."
    }
    if ($row.Port -notmatch '^[\d;\-]+$') {
        $csvErrors += "Row '$($row.Comment)': Port '$($row.Port)' must be a number, semicolon-separated list (80;443), or range (8080-8090). Do not use commas -- they break CSV parsing."
    }
    if ($row.Protocol -notin @('tcp','udp','any')) {
        $csvErrors += "Row '$($row.Comment)': Protocol '$($row.Protocol)' must be tcp, udp, or any."
    }
    $sources = @($row.AllowedSources -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($sources.Count -eq 0) {
        $csvErrors += "Row '$($row.Comment)': AllowedSources is empty."
    }
    foreach ($cidr in $sources) {
        if ($cidr -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
            $csvErrors += "Row '$($row.Comment)': AllowedSources entry '$cidr' is not a valid CIDR."
        }
    }
}
if ($csvErrors.Count -gt 0) {
    $csvErrors | ForEach-Object { Write-Log $_ ERROR }
    exit 1
}

Write-Log "$($policyRows.Count) policy row(s) loaded and validated."

# ============================================================
# Read existing ACL and check for conflicts
# ============================================================
Write-Log 'Reading existing network switch ACL...'
try {
    $existing = Invoke-MerakiRequest -Uri $aclUri
}
catch {
    Write-Log "Failed to read existing ACL: $_" ERROR
    exit 1
}

if ($null -eq $existing -or $null -eq $existing.rules) {
    $meaningfulRules = @()
}
else {
    $meaningfulRules = @($existing.rules | Where-Object {
        -not (
            $_.policy   -in @('allow','any') -and
            $_.srcCidr  -eq 'any'            -and
            $_.dstCidr  -eq 'any'            -and
            $_.protocol -eq 'any'
        )
    })
}

if ($meaningfulRules.Count -gt 0) {
    Write-Log "$($meaningfulRules.Count) existing meaningful rule(s) on network:" WARN
    foreach ($rule in $meaningfulRules) {
        Write-Log ("  [{0,-5}] {1,-4}  src={2}:{3}  dst={4}:{5}" -f `
            $rule.policy.ToUpper(), $rule.protocol,
            $rule.srcCidr, $rule.srcPort,
            $rule.dstCidr, $rule.dstPort) WARN
    }
    if ($Apply -and -not $Force) {
        Write-Log 'Existing rules will be replaced. Re-run with -Apply -Force to confirm.' WARN
        exit 1
    }
    if ($Apply -and $Force) {
        Write-Log 'Existing rules will be overwritten (-Force supplied).' WARN
        Confirm-Overwrite
    }
}
else {
    Write-Log 'No meaningful existing rules found -- safe to proceed.'
}

# ============================================================
# Build new ruleset from CSV
# ============================================================
$newRules = [System.Collections.Generic.List[hashtable]]::new()

foreach ($row in $policyRows) {
    $serverCidr = "$($row.ServerIp)/32"
    $sources    = $row.AllowedSources -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    # Semicolons are used in the CSV to avoid breaking the field delimiter.
    # The Meraki API expects commas for multi-port values, so translate here.
    $apiPort    = ($row.Port -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ','

    foreach ($src in $sources) {
        $newRules.Add(@{
            comment   = "Allow $($row.Protocol.ToUpper())/$apiPort to $($row.ServerIp) from $src ($($row.Comment))"
            policy    = 'allow'
            ipVersion = 'ipv4'
            protocol  = $row.Protocol
            srcCidr   = $src
            srcPort   = 'any'
            dstCidr   = $serverCidr
            dstPort   = $apiPort
            vlan      = 'any'
        })
    }

    $newRules.Add(@{
        comment   = "Deny $($row.Protocol.ToUpper())/$apiPort to $($row.ServerIp) -- all other sources ($($row.Comment))"
        policy    = 'deny'
        ipVersion = 'ipv4'
        protocol  = $row.Protocol
        srcCidr   = 'any'
        srcPort   = 'any'
        dstCidr   = $serverCidr
        dstPort   = $apiPort
        vlan      = 'any'
    })
}

# NOTE: This default-permit rule MUST remain the last entry.
# Its presence ensures all non-targeted inter-VLAN traffic
# continues to flow. Removing it or placing it before any
# deny rule would break routing for unrelated VLANs.
$newRules.Add(@{
    comment   = 'Default allow -- permit all other traffic'
    policy    = 'allow'
    ipVersion = 'any'
    protocol  = 'any'
    srcCidr   = 'any'
    srcPort   = 'any'
    dstCidr   = 'any'
    dstPort   = 'any'
    vlan      = 'any'
})

# ============================================================
# Rule limit check (Meraki supports up to 64 rules per network)
# ============================================================
$ruleLimit = 64
if ($newRules.Count -gt $ruleLimit) {
    Write-Log "Ruleset has $($newRules.Count) rules but Meraki supports a maximum of $ruleLimit per network." ERROR
    Write-Log 'Reduce the number of policy rows or consolidate allowed sources into larger CIDRs.' ERROR
    exit 1
}
Write-Log "Ruleset: $($newRules.Count) rule(s) (limit: $ruleLimit)."

# ============================================================
# Preview
# ============================================================
Write-Log '=== Proposed ruleset ==='
Show-Ruleset $newRules

if (-not $Apply) {
    Write-Log 'Preview complete. Re-run with -Apply to push the ruleset to the network.' INFO
    exit 0
}

# ============================================================
# Backup then apply
# ============================================================
Backup-ExistingAcl $existing
Invoke-AclPut -Uri $aclUri -Rules $newRules
Write-Log 'Done.'

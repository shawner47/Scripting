# ============================================================
# Set-MerakiNetworkACL_v2.10.ps1
# Version 2.10
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
# Follows STANDARDS.md (secrets: #50, transport: #51).
#
# WHAT THIS SCRIPT CHANGES:
#   Meraki:          Nothing without -Apply. With -Apply (policy or
#                    -Restore) it REPLACES the whole network-level
#                    switch ACL on -NetworkId. -Backup only reads.
#                    Before any change, the live ACL is read again,
#                    saved to a backup file and the file is read back
#                    and checked. If that fails, nothing is changed.
#   Your PS session: Nothing beyond this run's variables. Sets the
#                    TLS protocol for this process to include TLS 1.2.
#   Your computer:   Writes a run log under C:\Logs and ACL
#                    backup JSON files under -BackupDir. If you answer
#                    y at the key prompt, writes the encrypted key file.
#
# HANDLE THE OUTPUT AS SENSITIVE:
#   The log and the backup JSON files list your ACL rules (server
#   IPs, ports and allowed networks). The key file is encrypted to
#   your Windows user, but any process running as you can read it.
#
# PREREQUISITES:
#   - Meraki Dashboard API key with write access to the network
#     (the key must be stored in the encrypted key file, see below).
#   - Windows PowerShell 5.1 or PowerShell 7 on Windows (the key file
#     uses DPAPI, so it is tied to your user and this machine).
#
# API KEY (Standard #50):
#   There is no -ApiKey parameter. The key is read in this order:
#   1. The DPAPI-encrypted file at -KeyFile (this user and machine).
#   2. A masked prompt (Read-Host -AsSecureString) that offers to
#      save the encrypted file for future runs.
#   For scheduled or unattended runs, create the key file first by
#   running the script once, interactively, as the account that will
#   run it. A non-interactive run with no usable key file fails.
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
# PARAMETERS:
#   -NetworkId     Target network ID. Required (no default, because a
#                  real network ID must not be stored in the script).
#   -KeyFile       Path to the DPAPI-encrypted API key file.
#                  Default: ~\.meraki_api_key
#   -PolicyCsv     Path to the CSV policy file.
#                  Default: MerakiACLPolicy.csv in the same
#                  directory as this script ($PSScriptRoot).
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
# OUTPUT:
#   Run log:     C:\Logs\yyyy.MM.dd.HHmmss.Set-MerakiNetworkACL_v2.10.log
#   ACL backups: <BackupDir>\yyyy.MM.dd.HHmmss.ACL_Backup_<NetworkId>.json
#                (-Restore also finds older ACL_Backup_<NetworkId>_*.json files)
#
# EXAMPLES:
#   # Preview policy (CSV must be in same folder as script, or use -PolicyCsv)
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx'
#
#   # Preview with an explicit CSV path
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -PolicyCsv 'C:\Meraki\MyPolicy.csv'
#
#   # Apply policy from CSV
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Apply
#
#   # Snapshot the current ACL before making changes (recommended first step)
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Backup
#
#   # Preview what restore would push (no changes)
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Restore
#
#   # Restore most recent backup (prompts if multiple exist)
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Restore -Apply
#
#   # Restore most recent backup without prompting
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Restore -Apply -AutoSelectLatestBackup
#
#   # Restore a specific backup file
#   .\Set-MerakiNetworkACL_v2.10.ps1 -NetworkId 'N_xxxx' -Restore -Apply -BackupFile 'C:\...\2026.10.23.152000.ACL_Backup_N_xxxx.json'
#
# v2.10 changes:
#   Logging now starts before anything that can fail. In v2.9 a missing
#   -NetworkId threw before the log file existed, so that failure was on
#   the console only. Now the log file is created and the "started" and
#   "Log file" lines are written first, then the required-parameter check
#   runs and logs its failure at ERROR before it throws (Standards #22,
#   #34). The default log folder is now C:\Logs instead of C:\Logs\Azure
#   (Standard #46). No other behavior changed. Confirmed in PowerShell 7
#   with a mocked API: a run with no -NetworkId leaves a log file whose
#   last lines are the ERROR and "Missing required parameter(s)"; the
#   preview, backup, apply and restore runs still pass; not run on a live
#   network or Windows PowerShell 5.1 (#48).
# v2.9 changes:
#   A verified backup is now ALWAYS taken before anything is written to
#   the network. v2.8 skipped the backup when the network held only
#   default-allow rules (or no rules), so a first -Apply left nothing
#   to -Restore to; the test showed -Restore failing with "No backup
#   files found". Now:
#   - -Apply (policy or -Restore) re-reads the live ACL immediately
#     before the change and saves it, even if it is only the default
#     rule or empty (an empty ACL is saved as []).
#   - The backup file is read back and its rule count is compared to
#     what was read from the network. If the live read, the write or
#     the read-back check fails, the script stops before the PUT.
#   - Invoke-AclPut refuses to run unless that verified backup was made
#     in this run.
#   - In -Restore, a failed live read used to be a WARN and the restore
#     went ahead; it is now fatal.
#   - -Backup also saves an empty ACL instead of stopping with a WARN.
#   - Backups are written as a JSON array even for one rule.
#   How the changes were confirmed: run in PowerShell 7 against a mocked
#   Meraki API (default-only ACL, populated ACL, failed backup path);
#   not run against a live network or Windows PowerShell 5.1 (#48).
# v2.8 changes:
#   Brought the script in line with STANDARDS.md (security and format
#   only; the rule-building and validation logic is unchanged).
#   Security:
#   - Removed the plain-text -ApiKey parameter (#50). It put the key in
#     PSReadLine history, the process list and transcripts. Existing
#     key files made by v2.7 still work.
#   - The key now stays a SecureString. It is converted to plain text
#     only inside Invoke-MerakiRequest, and the BSTR is freed in a
#     finally block (#50).
#   - A non-interactive run with no usable key file now fails instead
#     of waiting on a prompt that nobody can answer (#50).
#   - Requests are HTTPS-only and TLS 1.2 is set for Windows
#     PowerShell 5.1 (#51).
#   - Removed the real network ID that was the -NetworkId default (#18).
#     -NetworkId is now required.
#   Format and behavior:
#   - Retry wrapper: HTTP 429, 5xx and connection failures retry with
#     exponential backoff, and API error text is included in failures
#     (#16, #17).
#   - Run log file with Write-Log levels and colors from the template,
#     run framing, and a Files written list (#19, #22, #45, #46).
#   - Backup files are named yyyy.MM.dd.HHmmss.ACL_Backup_<NetworkId>.json
#     (#21). -Restore still finds the old-style names.
#   - Fatal errors now throw (after logging at ERROR) and clean stops
#     exit 0 (#24). Preview ends with the standard WARN line (#23).
#   - Header sections, file name, version constant and examples now
#     match STANDARDS.md (#7, #8, #9, #32, #33, #35). Backtick line
#     continuations and += in loops removed (#12, #42).
#   How the changes were confirmed: not run against a live Meraki
#   network when written; test with a preview and a -Backup first (#48).
# v2.7 changes: Fixed remaining PropertyNotFoundException under
#   Set-StrictMode -Version Latest. $missing and $sources Where-Object
#   pipelines now wrapped in @() to guarantee array type when no items match.
# v2.6 changes: BackupDir default changed from user profile to
#   $PSScriptRoot\MerakiACLBackups (same folder as the script).
# v2.5 changes: Fixed PropertyNotFoundException under Set-StrictMode
#   -Version Latest when CSV or backup JSON contains only one row/rule.
#   Import-Csv and ConvertFrom-Json results now wrapped in @().
# v2.4 changes: PolicyCsv default changed from user profile to
#   $PSScriptRoot. Added POLICY CSV FILE header section and usage examples.
# v2.3 changes: Fixed port delimiter in CSV from comma to semicolon
#   (commas break CSV field parsing). Script rejoins with comma for the API.
# v2.2 changes: Port field accepts semicolon-separated ports and ranges.
#   Added -Backup for standalone ACL snapshots.
# v2.1 changes: Replaced -PromptOnMultipleBackups with
#   -AutoSelectLatestBackup (prompting is now the default).
# v2.0 changes: Redesigned as CSV-driven policy script (-PolicyCsv).
#   Added -Restore and -BackupFile. NetworkId is now a parameter.
# v1.2 changes: Fixed ACL endpoint to network-level
#   /switch/accessControlLists; removed -StackId; added vlan field.
# v1.1 changes: Added SecureString key resolution, IP/CIDR validation,
#   ACL backup, post-apply verification, null guards, Force confirmation.
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param (
    [string] $NetworkId     = "",
    [string] $KeyFile       = (Join-Path $env:USERPROFILE '.meraki_api_key'),
    [string] $PolicyCsv     = (Join-Path $PSScriptRoot 'MerakiACLPolicy.csv'),
    [string] $BackupDir     = (Join-Path $PSScriptRoot 'MerakiACLBackups'),
    [string] $BackupFile    = "",
    [switch] $Apply,
    [switch] $Force,
    [switch] $Restore,
    [switch] $Backup,
    [switch] $AutoSelectLatestBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================
$LogDir        = "C:\Logs"                       # default log folder (Standard #46)
$ScriptVersion = "2.10"
$baseUrl       = 'https://api.meraki.com/api/v1' # Meraki Dashboard API v1
$ruleLimit     = 64                              # Meraki maximum rules per network ACL
$maxRetries    = 4                               # retries for 429 / 5xx / connection errors
# ============================================================

# TLS 1.2 for Windows PowerShell 5.1, which may not negotiate it by default (#51)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# -- Folders, timestamp and log file
$stamp = Get-Date -Format "yyyy.MM.dd.HHmmss"
if (-not (Test-Path -Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$scriptName = $MyInvocation.MyCommand.Name -replace '\.ps1$', ''
$logFile    = Join-Path $LogDir "$stamp.$scriptName.log"

# Files this run wrote, listed at the end under "Files written:" (#45)
$script:FilesWritten = New-Object System.Collections.Generic.List[string]
$script:ApiKeySecure = $null
$script:BackupVerified = $false   # set only by Backup-LiveAcl


# ============================================================
# Functions
# ============================================================
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

function Stop-WithError {
    # Log at ERROR, then throw (#24)
    param([string]$Message = "")
    Write-Log $Message -Level ERROR
    throw $Message
}

function Exit-Clean {
    # Clean, non-error stop (#24): list files written, log the last line, exit 0
    if ($script:FilesWritten.Count -gt 0) {
        Write-Log "Files written:" -Level SUCCESS
        foreach ($written in $script:FilesWritten) { Write-Log "  $written" -Level SUCCESS }
    }
    Write-Log "$scriptName finished"
    exit 0
}

function Invoke-MerakiRequest {
    # The only place Invoke-RestMethod is called (#16). Retries 429, 5xx and
    # connection-level failures with exponential backoff (#17).
    param (
        [string]$Uri    = "",
        [string]$Method = 'GET',
        [object]$Body   = $null
    )
    if ($Uri -notmatch '^https://') { throw "Refusing non-HTTPS URI: $Uri" }

    # SecureString -> plain text only here, and free the BSTR straight away (#50).
    # The header value itself has to be a plain string for the Meraki API.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:ApiKeySecure)
    try     { $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = @{
            'X-Cisco-Meraki-API-Key' = $plainKey
            'Content-Type'           = 'application/json'
        }
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }

    $attempt = 0
    while ($true) {
        try {
            return (Invoke-RestMethod @params)
        }
        catch {
            $attempt++
            $status = $null
            $respProp = $_.Exception.PSObject.Properties['Response']
            if ($null -ne $respProp -and $null -ne $respProp.Value) {
                $status = [int]$respProp.Value.StatusCode
            }
            $statusText = if ($null -eq $status) { 'no response' } else { $status }
            $transient = ($null -eq $status) -or ($status -eq 429) -or ($status -ge 500)
            if ($transient -and $attempt -le $maxRetries) {
                $wait = [int][Math]::Pow(2, $attempt)
                Write-Log "$Method request failed (status: $statusText). Retry $attempt of $maxRetries in $wait second(s)." -Level WARN
                Start-Sleep -Seconds $wait
                continue
            }
            $detail = $_.Exception.Message
            if ($null -ne $_.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($_.ErrorDetails.Message)) {
                $detail = "{0} -- {1}" -f $detail, $_.ErrorDetails.Message
            }
            throw "Meraki API $Method $Uri failed (status: $statusText): $detail"
        }
    }
}

function Get-StoredApiKey {
    # Returns a SecureString (#50). Order: encrypted file, then masked prompt.
    param([string]$KeyFile = "")
    if (Test-Path -Path $KeyFile) {
        try {
            $fromFile = Get-Content -Path $KeyFile -ErrorAction Stop | ConvertTo-SecureString
            Write-Log "API key sourced from encrypted file: $KeyFile"
            return $fromFile
        }
        catch {
            Write-Log "Could not decrypt '$KeyFile' (made by another user or machine?): $_" -Level WARN
        }
    }
    if (-not [Environment]::UserInteractive) {
        Stop-WithError "No usable key file at '$KeyFile' and the session is not interactive. Run the script once interactively to create it."
    }
    Write-Log "No usable key file. Enter the API key interactively (input is masked)." -Level WARN
    $secure = Read-Host -Prompt "Meraki API Key" -AsSecureString
    if ($secure.Length -eq 0) { Stop-WithError "No API key entered." }
    $save = Read-Host "Save encrypted key to '$KeyFile' for future runs? (y/N)"
    if ($save -eq 'y') {
        try {
            $keyDir = Split-Path -Path $KeyFile -Parent
            if (-not (Test-Path -Path $keyDir)) { New-Item -ItemType Directory -Path $keyDir -Force | Out-Null }
            $secure | ConvertFrom-SecureString | Set-Content -Path $KeyFile -Encoding UTF8
            Write-Log "Key saved to $KeyFile (DPAPI: this user and machine only)." -Level SUCCESS
            $script:FilesWritten.Add($KeyFile)
        }
        catch { Write-Log "Could not save key file: $_" -Level WARN }
    }
    return $secure
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
    Write-Log ""
    $i = 1
    foreach ($rule in $Rules) {
        $policyText = $rule.policy.ToUpper()
        $ruleLine = "  [{0:D2}] [{1,-5}] {2,-4}  src={3}:{4}  dst={5}:{6}  # {7}" -f $i, $policyText, $rule.protocol, $rule.srcCidr, $rule.srcPort, $rule.dstCidr, $rule.dstPort, $rule.comment
        Write-Log $ruleLine
        $i++
    }
    Write-Log ""
}

function Save-AclBackup {
    # Writes the rules to a timestamped JSON backup, reads it back and checks
    # the rule count, then returns the path. Throws if anything is wrong.
    # Always writes a JSON array, so an empty ACL is saved as [].
    param ([object]$Rules)
    $ruleList = @($Rules | Where-Object { $null -ne $_ })
    if (-not (Test-Path -Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    $file = Join-Path $BackupDir "$stamp.ACL_Backup_$NetworkId.json"
    ConvertTo-Json -InputObject $ruleList -Depth 10 | Set-Content -Path $file -Encoding UTF8
    $script:FilesWritten.Add($file)

    $readBack = @(Get-Content -Path $file -Raw -ErrorAction Stop | ConvertFrom-Json)
    if ($readBack.Count -ne $ruleList.Count) {
        throw "Backup check failed: $file holds $($readBack.Count) rule(s) but the network has $($ruleList.Count)."
    }
    return $file
}

function Backup-LiveAcl {
    # Reads the live ACL right now, saves a verified backup, and records that
    # it happened. Invoke-AclPut will not run without it.
    $script:BackupVerified = $false
    try {
        $live = Invoke-MerakiRequest -Uri $aclUri
        if ($null -eq $live) { throw "The API returned nothing for the current ACL." }
        $liveRules = @()
        if ($null -ne $live.PSObject.Properties['rules'] -and $null -ne $live.rules) { $liveRules = @($live.rules) }
        $file = Save-AclBackup -Rules $liveRules
        Write-Log "Existing ACL ($($liveRules.Count) rule(s)) backed up and verified: $file" -Level SUCCESS
        $script:BackupVerified = $true
    }
    catch {
        Stop-WithError "No valid backup of the current ACL, so nothing was changed: $_"
    }
}

function Invoke-AclPut {
    param (
        [string]$Uri = "",
        [System.Collections.Generic.List[hashtable]]$Rules
    )
    if (-not $script:BackupVerified) {
        Stop-WithError 'Refusing to write: no verified backup of the current ACL was made in this run.'
    }
    Write-Log 'Pushing ACL to network...'
    try {
        $body       = @{ rules = $Rules.ToArray() }
        $result     = Invoke-MerakiRequest -Uri $Uri -Method PUT -Body $body
        $reported   = @($result.rules).Count
        Write-Log "PUT accepted -- $reported rule(s) reported by API." -Level SUCCESS
    }
    catch {
        Stop-WithError "Failed to apply ACL: $_"
    }

    Write-Log 'Verifying applied ACL...'
    try {
        $live      = Invoke-MerakiRequest -Uri $Uri
        $liveRules = @($live.rules)
        $expCount  = $Rules.Count

        if ($liveRules.Count -ne $expCount) {
            Write-Log "Rule count mismatch: expected $expCount, live network reports $($liveRules.Count)." -Level WARN
            Write-Log 'Review the ACL in the Meraki dashboard.' -Level WARN
            return
        }

        $mismatch = $false
        for ($j = 0; $j -lt $expCount; $j++) {
            $exp       = $Rules[$j]
            $live_rule = $liveRules[$j]
            if ($exp.policy   -ne $live_rule.policy   -or
                $exp.srcCidr  -ne $live_rule.srcCidr   -or
                $exp.dstCidr  -ne $live_rule.dstCidr   -or
                $exp.dstPort  -ne $live_rule.dstPort   -or
                $exp.protocol -ne $live_rule.protocol) {
                $ruleNo = $j + 1
                $mmLine = "Rule [{0:D2}] mismatch: expected [{1}] {2} src={3} dst={4}:{5}" -f $ruleNo, $exp.policy, $exp.protocol, $exp.srcCidr, $exp.dstCidr, $exp.dstPort
                Write-Log $mmLine -Level WARN
                $mismatch = $true
            }
        }
        if (-not $mismatch) {
            Write-Log "Verification passed -- all $($liveRules.Count) rule(s) confirmed on network." -Level SUCCESS
        }
        else {
            Write-Log 'One or more rules did not match. Review the ACL in the Meraki dashboard.' -Level WARN
        }
    }
    catch {
        Write-Log "Verification GET failed: $_" -Level WARN
        Write-Log 'Could not confirm live state -- check the Meraki dashboard.' -Level WARN
    }
}

function Confirm-Overwrite {
    if ([System.Environment]::UserInteractive) {
        $confirm = Read-Host 'Type YES to confirm overwrite of existing rules'
        if ($confirm -ne 'YES') {
            Write-Log 'Overwrite not confirmed. Exiting.' -Level WARN
            Exit-Clean
        }
    }
}

# ============================================================
# Start of run, then required parameters (logged before any check can fail)
# ============================================================
Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log "Log file: $logFile"

$missing = @()
if ([string]::IsNullOrWhiteSpace($NetworkId)) { $missing += "-NetworkId" }
if ($missing.Count -gt 0) { Stop-WithError ("Missing required parameter(s): {0}" -f ($missing -join ", ")) }

# ============================================================
# Parameter validation
# ============================================================
$validationErrors = New-Object System.Collections.Generic.List[string]

if (-not $Restore) {
    if ([string]::IsNullOrWhiteSpace($PolicyCsv)) {
        $validationErrors.Add('PolicyCsv is required when not using -Restore.')
    }
    elseif (-not (Test-Path -Path $PolicyCsv)) {
        $validationErrors.Add("PolicyCsv not found: $PolicyCsv")
    }
}

if ($validationErrors.Count -gt 0) {
    foreach ($verr in $validationErrors) { Write-Log $verr -Level ERROR }
    throw ("Parameter validation failed: {0}" -f ($validationErrors -join ' '))
}

# ============================================================
# Run framing
# ============================================================
$mode    = if ($Apply) { 'APPLY - changes will be made' } else { 'PREVIEW - no changes will be made' }
$opLabel = if ($Backup) { 'BACKUP' } elseif ($Restore) { 'RESTORE' } else { 'POLICY' }
$aclUri  = "$baseUrl/networks/$NetworkId/switch/accessControlLists"

Write-Log "Mode: $mode | Operation: $opLabel"
Write-Log "Network ID  : $NetworkId"
Write-Log "ACL endpoint: $aclUri"
Write-Log "Backup dir  : $BackupDir"

# ============================================================
# API key resolution (Standard #50)
# ============================================================
$script:ApiKeySecure = Get-StoredApiKey -KeyFile $KeyFile
if ($null -eq $script:ApiKeySecure -or $script:ApiKeySecure.Length -eq 0) {
    Stop-WithError 'API key could not be resolved.'
}

# ============================================================
# BACKUP path
# ============================================================
if ($Backup) {
    Write-Log 'Reading current network switch ACL for snapshot...'
    try {
        $snapExisting = Invoke-MerakiRequest -Uri $aclUri
    }
    catch {
        Stop-WithError "Failed to read ACL: $_"
    }

    $snapRules = @()
    if ($null -ne $snapExisting -and $null -ne $snapExisting.PSObject.Properties['rules'] -and $null -ne $snapExisting.rules) {
        $snapRules = @($snapExisting.rules)
    }

    try {
        $snapFile = Save-AclBackup -Rules $snapRules
        Write-Log "ACL snapshot saved and verified ($($snapRules.Count) rule(s)): $snapFile" -Level SUCCESS
    }
    catch {
        Stop-WithError "Failed to save backup: $_"
    }
    Exit-Clean
}

# ============================================================
# RESTORE path
# ============================================================
if ($Restore) {

    # Resolve backup file to restore
    if (-not [string]::IsNullOrWhiteSpace($BackupFile)) {
        if (-not (Test-Path -Path $BackupFile)) {
            Stop-WithError "BackupFile not found: $BackupFile"
        }
        $resolvedBackup = $BackupFile
        Write-Log "Restore source (explicit): $resolvedBackup"
    }
    else {
        # Auto-select from BackupDir. New names: <stamp>.ACL_Backup_<id>.json
        # Old (v2.7 and earlier) names: ACL_Backup_<id>_<stamp>.json
        $newPattern = Join-Path $BackupDir "*.ACL_Backup_$NetworkId.json"
        $oldPattern = Join-Path $BackupDir "ACL_Backup_${NetworkId}_*.json"
        $backups    = @(Get-ChildItem -Path $newPattern, $oldPattern -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending)

        if ($backups.Count -eq 0) {
            Write-Log "No backup files found for network '$NetworkId' in: $BackupDir" -Level ERROR
            Stop-WithError 'Use -BackupFile to specify a backup explicitly.'
        }

        if ($backups.Count -gt 1 -and -not $AutoSelectLatestBackup) {
            Write-Log "$($backups.Count) backup(s) found. Select one:"
            for ($k = 0; $k -lt $backups.Count; $k++) {
                $bkTime = $backups[$k].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                Write-Log ("  [{0}] {1}  ({2})" -f $k, $backups[$k].Name, $bkTime)
            }
            $pick = Read-Host 'Enter number'
            if ($pick -notmatch '^\d+$' -or [int]$pick -ge $backups.Count) {
                Stop-WithError 'Invalid selection.'
            }
            $resolvedBackup = $backups[[int]$pick].FullName
        }
        else {
            $resolvedBackup = $backups[0].FullName
            if ($backups.Count -gt 1) {
                Write-Log "$($backups.Count) backup(s) found -- auto-selecting most recent (-AutoSelectLatestBackup)."
            }
        }
        Write-Log "Restore source (auto): $resolvedBackup"
    }

    # Load backup
    try {
        $backupRules = @(Get-Content -Path $resolvedBackup -Raw | ConvertFrom-Json)
    }
    catch {
        Stop-WithError "Failed to read backup file: $_"
    }

    # Convert to List[hashtable] for display and PUT
    $restoreList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($r in $backupRules) { $restoreList.Add((ConvertTo-PlainRule $r)) }

    Write-Log "=== Rules to be restored ($($restoreList.Count) total) ==="
    Show-Ruleset $restoreList

    if (-not $Apply) {
        Write-Log 'Preview only. No changes were made. Re-run with -Restore -Apply to push the restored ruleset.' -Level WARN
        Exit-Clean
    }

    # Read the live ACL and save a verified backup before overwriting
    Backup-LiveAcl

    Invoke-AclPut -Uri $aclUri -Rules $restoreList
    Exit-Clean
}

# ============================================================
# POLICY path -- read and validate CSV
# ============================================================
Write-Log "Reading policy CSV: $PolicyCsv"
try {
    $policyRows = @(Import-Csv -Path $PolicyCsv)
}
catch {
    Stop-WithError "Failed to read policy CSV: $_"
}

if ($policyRows.Count -eq 0) {
    Stop-WithError 'Policy CSV contains no rows.'
}

# Validate required columns
$requiredCols = @('ServerIp','Port','Protocol','AllowedSources','Comment')
$csvCols      = $policyRows[0].PSObject.Properties.Name
$missingCols  = @($requiredCols | Where-Object { $_ -notin $csvCols })
if ($missingCols.Count -gt 0) {
    Stop-WithError "Policy CSV is missing required column(s): $($missingCols -join ', ')"
}

$csvErrors = New-Object System.Collections.Generic.List[string]
foreach ($row in $policyRows) {
    if ($row.ServerIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $csvErrors.Add("Row '$($row.Comment)': ServerIp '$($row.ServerIp)' is not a valid IPv4 address.")
    }
    if ($row.Port -notmatch '^[\d;\-]+$') {
        $csvErrors.Add("Row '$($row.Comment)': Port '$($row.Port)' must be a number, semicolon-separated list (80;443), or range (8080-8090). Do not use commas -- they break CSV parsing.")
    }
    if ($row.Protocol -notin @('tcp','udp','any')) {
        $csvErrors.Add("Row '$($row.Comment)': Protocol '$($row.Protocol)' must be tcp, udp, or any.")
    }
    $sources = @($row.AllowedSources -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($sources.Count -eq 0) {
        $csvErrors.Add("Row '$($row.Comment)': AllowedSources is empty.")
    }
    foreach ($cidr in $sources) {
        if ($cidr -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') {
            $csvErrors.Add("Row '$($row.Comment)': AllowedSources entry '$cidr' is not a valid CIDR.")
        }
    }
}
if ($csvErrors.Count -gt 0) {
    foreach ($cerr in $csvErrors) { Write-Log $cerr -Level ERROR }
    throw "Policy CSV validation failed with $($csvErrors.Count) error(s). See the log."
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
    Stop-WithError "Failed to read existing ACL: $_"
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
    Write-Log "$($meaningfulRules.Count) existing meaningful rule(s) on network:" -Level WARN
    foreach ($rule in $meaningfulRules) {
        $exLine = "  [{0,-5}] {1,-4}  src={2}:{3}  dst={4}:{5}" -f $rule.policy.ToUpper(), $rule.protocol, $rule.srcCidr, $rule.srcPort, $rule.dstCidr, $rule.dstPort
        Write-Log $exLine -Level WARN
    }
    if ($Apply -and -not $Force) {
        Stop-WithError 'Existing rules will be replaced. Re-run with -Apply -Force to confirm.'
    }
    if ($Apply -and $Force) {
        Write-Log 'Existing rules will be overwritten (-Force supplied).' -Level WARN
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
    $sources    = @($row.AllowedSources -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    # Semicolons are used in the CSV to avoid breaking the field delimiter.
    # The Meraki API expects commas for multi-port values, so translate here.
    $apiPort    = (@($row.Port -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) -join ','

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
# Rule limit check
# ============================================================
if ($newRules.Count -gt $ruleLimit) {
    Write-Log "Ruleset has $($newRules.Count) rules but Meraki supports a maximum of $ruleLimit per network." -Level ERROR
    Write-Log 'Reduce the number of policy rows or consolidate allowed sources into larger CIDRs.' -Level ERROR
    throw "Ruleset exceeds the Meraki limit of $ruleLimit rules."
}
Write-Log "Ruleset: $($newRules.Count) rule(s) (limit: $ruleLimit)."

# ============================================================
# Preview
# ============================================================
Write-Log '=== Proposed ruleset ==='
Show-Ruleset $newRules

if (-not $Apply) {
    Write-Log 'Preview only. No changes were made. Re-run with -Apply to push the ruleset to the network.' -Level WARN
    Exit-Clean
}

# ============================================================
# Backup then apply
# ============================================================
Backup-LiveAcl
Invoke-AclPut -Uri $aclUri -Rules $newRules
Exit-Clean

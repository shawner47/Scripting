# PowerShell Script Standards

**Effective:** 2026-10-02
*Rule numbers never change, because scripts cite them (for example
"Standard 13"). A merged rule keeps its number and points to the rule it
was folded into. New rules get the next free number. Each section lists
rules by topic, so the numbers inside a section are not always in order.*

**Applies to:**
- **Azure / admin scripts** - every rule.
- **Interactive diagnostic monitors** (`Test-*Connection`, `Test-Ldap*`) -
  every rule, with the reduced logging profile in #49.
- **Meraki scripts** - every rule, plus section 7.
- **Throwaway debug snippets** - exempt until kept. A kept snippet must meet
  every rule.

---

## 1. Encoding

> Checked on every script, no exceptions.

| # | Check | Detail |
|---|-------|--------|
| 1 | **CRLF line endings** | Every line must end `\r\n`. LF-only (`\n`) fails. `.gitattributes` stores `.ps1` files byte-for-byte so git never converts them. |
| 2 | **UTF-8 BOM** | File must begin with `\xef\xbb\xbf`. |
| 3 | **Double-BOM** | Only one BOM, at byte offset 0. A second embedded BOM in content fails. |
| 4 | **Non-ASCII characters** | Zero bytes > 127 after the BOM. Em-dashes, curly quotes, and any other non-ASCII fail. Replace with `--`, straight quotes, etc. |
| 5 | **Trailing CRLF** | The final line must have a line terminator. A file with N lines must have exactly N CRLFs. |

---

## 2. Naming, Structure and Versioning

| # | Check | Detail |
|---|-------|--------|
| 32 | **File name** | `Verb-Noun_vMAJOR.MINOR.ps1` (for example `Export-NSG-Rules_v1.0.ps1`): an approved verb, an underscore before the version, and two parts in the version number. Spell acronyms the same way in every file name (decide `LDAP` vs `Ldap` once). A new version is a new file. |
| 6 | **`# Version X.X` line** | Must be present near the top of the header block. |
| 7 | **Version history block** | Every version must have a `# vX.X changes:` entry explaining what changed and why. Any change to a file = version increment + new history entry. List versions newest first, ending with `# v1.0: Initial release.` A bug-fix entry says how the bug showed up and how the fix was confirmed. |
| 8 | **Stale version references** | Any script filename references in EXAMPLES, DESCRIPTION, or log line calls must match the current version. `v1.0.ps1` in examples when the file is v1.1 fails. Set the version once, as `$ScriptVersion` in CONFIGURATION, and get the script name at runtime (`$scriptName = $MyInvocation.MyCommand.Name -replace '\.ps1$', ''`). Log lines use those two variables and never type the name or version in. |
| 9 | **Standard header block** | Scripts use the `# ============================================================` wrapper format. Comment-based help (`<# .SYNOPSIS #>`) is acceptable only when `[CmdletBinding()]` is used and `Get-Help` is intentional. |
| 33 | **Header sections** | In this order, wherever they apply: summary; `WHAT THIS SCRIPT COLLECTS:` (read-only scripts); `WHAT THIS SCRIPT CHANGES:` (**always**, with `Azure:` / `Your PS session:` / `Your computer:` sub-items, saying "Nothing" where that is true); `HANDLE THE OUTPUT AS SENSITIVE:` (when output contains IPs, rules or identities); `WHAT THE RESULTS DO NOT SHOW:`; `PREREQUISITES:` (modules, sign-in, minimum role); `RECOMMENDED EXECUTION ORDER:` (multi-phase scripts); `PARAMETERS:` (each one with its default); `OUTPUT:` (every file and its name pattern); `EXAMPLES:`; version history. Diagnostic monitors also include `PURPOSE:` with a table of outcomes and what each one means, and `INTERPRETING RESULTS:`. |
| 35 | **CONFIGURATION block** | Fixed values (`$LogDir`, `$ScriptVersion`, address lists, and so on) go in a single block between `# ====` banners, right after `param()` and the required-parameter check. Each non-obvious value has a comment saying where it came from. |

---

## 3. PowerShell Syntax and Safety

| # | Check | Detail |
|---|-------|--------|
| 10 | **Nested double-quotes in `$()` inside double-quoted strings** | `"text $($var["key"]) more"` causes a parser error (`The string is missing the terminator`). Extract to an intermediate variable first. |
| 11 | **`$variable:` scope ambiguity** | A variable name immediately followed by a colon in a string (`"$TargetHost:$Port"`) is parsed as a scoped variable reference. Fix with `"${TargetHost}:$Port"`. |
| 12 | **No backtick line continuations** | Replace with PowerShell splatting (`$params = @{...}; Cmdlet @params`). Inline backtick escaping (e.g. `` `n `` for newline inside a string) is acceptable. *(Also covers #25.)* |
| 13 | **`[Parameter(Mandatory)]` on `[string]` params** | Mandatory validation rejects empty strings at runtime, breaking any caller that passes `""`. Use `[string]$Param = ""` instead, or omit Mandatory entirely. |
| 34 | **Required-parameter check** | Required parameters default to `""` (see #13) and are checked right after `param()`. Collect every missing name and throw once: `throw "Missing required parameter(s): -A, -B"`. Check parameters that take one of a fixed set of values against an explicit list (`$validPhases -notcontains $Phase`). |
| 14 | **No dangerous constructs** | `Invoke-Expression`, `iex`, `cmd /c`, and `Start-Process` with user input are prohibited. *(Also covers #28.)* |
| 15 | **Balanced braces** | Open `{` count must equal close `}` count. |
| 41 | **Loading JSON arrays (PS 5.1)** | Use three separate statements: `$raw = Get-Content -Path $f -Raw`, then `$parsed = $raw \| ConvertFrom-Json`, then `$items = @($parsed)`. On 5.1, `ConvertFrom-Json` returns a whole JSON array as a single pipeline object. `@(... \| ConvertFrom-Json)` therefore makes an array of one item, and reading a property on it gathers the value from every entry into one space-joined string. Found in Move-Subnet-Delegation-Fix v1.7/v1.8. |
| 42 | **Collections** | Inside loops, use `New-Object System.Collections.Generic.List[object]` and `.Add()`. Don't use `$array +=`, which copies the whole array on every add. Wrap any result whose `.Count` you read in `@()`. |
| 43 | **No assigning to automatic variables** | `$matches`, `$input`, `$args`, `$error`, `$host`, `$event`, `$_`/`$PSItem`. Variable names aren't case-sensitive, so `$matches` is the same variable as `$Matches`. |
| 44 | **Error handling discipline** | Use `-ErrorAction Stop` inside `try`. Use `-ErrorAction SilentlyContinue` only when "not found" is an expected answer that is checked on the next line. Check each level is non-null before reading below it (`$nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id`). Enumerating a hashtable with `GetEnumerator()` gives `.Key`/`.Value`, not `.Name`. |

---

## 4. Logging and Output

| # | Check | Detail |
|---|-------|--------|
| 19 | **`Write-Log` with color by level** | ERROR=Red, WARN=Yellow, SUCCESS=Green, INFO=White. All scripts with a `Write-Log` function must apply this. Use the template's `Write-Log` exactly as written (section 8). Log lines only use the level colors. |
| 20 | **No `[Parameter(Mandatory)]` on `Write-Log $Message`** | `Write-Log ""` for blank line spacing breaks at runtime. Use `[string]$Message = ""`. |
| 21 | **Timestamped output filenames** | CSV and log files use `yyyy.MM.dd.HHmmss` prefix. Fixed filenames that get overwritten on re-run are a defect. Each run takes **one** timestamp (`$stamp`) and uses it for the log and every output file. The log file is `Join-Path $LogDir "$stamp.$scriptName.log"`. *Exception:* state files that one run writes for a later run to read (e.g. `subnet-migration-state.json`) have fixed names on purpose. |
| 22 | **Log file written in addition to console** | Meaningful runs produce a log file, not console-only output. Tables also go to the log, through `Write-LogTable` (`Format-Table` piped to `Out-String -Width 250`, then one `Write-Log` per line). Never write a bare `Format-Table` or `Write-Host` that skips the log. |
| 45 | **Run framing** | The first line is `"$scriptName started (version $ScriptVersion)"`, followed by the mode, targets, output folder and log path. When the run writes files, it lists them under `Files written:` (SUCCESS). The last line is `"$scriptName finished"`. A script that scans several scopes logs a count per scope so you can check nothing was skipped. |
| 46 | **Folders and default locations** | Create the log and output folders before the first log line. Defaults: logs go to `C:\Logs\Azure` and state files to `C:\Logs\Azure\State`. Report output goes to `C:\Temp`, and the `-OutputDirectory` parameter overrides it. |
| 26 | **`-Encoding UTF8` on file writes** | Required in PowerShell 5.1 on `Export-Csv`, `Out-File` and `Set-Content` (JSON state files included). Without it, 5.1 uses Windows-1252 or UTF-16. |
| 47 | **Empty results** | When nothing matches, stop cleanly: log a WARN, write no files, and `exit 0` (see #24). If an empty file is still wanted, write the column names yourself. `"" \| Export-Csv` writes a `Length` column, not the dataset's headers. CSV columns are PascalCase and keep the same names across versions. Values that are lists are sorted before joining, so the same data always gives the same text. |
| 49 | **Diagnostic monitor profile** | The main output is the CSV data log `$stamp.<test-name>-log.csv`, which `-LogPath` can override. CSV timestamps use `Get-Date -Format "yyyy-MM-dd HH:mm:ss"`, not the machine's regional format. Console colors may show connection state (Green = healthy, Red = lost, Yellow = notice). New monitors also write a `Write-Log` run log (#22). |

---

## 5. Conventions

| # | Check | Detail |
|---|-------|--------|
| 23 | **Dry runs: never `-WhatIf`** | `-WhatIf` is a reserved PowerShell common parameter. **Preferred:** scripts that change things only preview by default and need an `[switch]$Apply` to make changes (see New-BaselineNSG, Move-Subnet-Delegation-Fix). Without `-Apply`, the script prints exactly what it would do, logs `Preview only. No changes were made...` at WARN, and `exit 0`. **Also acceptable:** the older opt-in `[switch]$Preview`. Either way, preview and apply use the same plan, so what you see is what runs. |
| 24 | **`throw` for fatal errors, `exit 0` for normal non-error stops** | Scripts that fail should `throw` with a clear message. Use `exit 0` for clean, non-error stops only. Log the message at ERROR before throwing. |
| 25 | *Merged into #12* | Splatting over backtick continuations. |
| 27 | **`Join-Path` for all file path construction** | Not string concatenation. |

---

## 6. Azure Scripts

| # | Check | Detail |
|---|-------|--------|
| 36 | **Existing session only** | Never call `Connect-AzAccount`. Check `Get-AzContext`. If there's no session, log an ERROR and throw `"No Azure session found. Run Connect-AzAccount first."` |
| 37 | **Subscription context contained and restored** | Save `$originalContext`. Switch subscriptions with `Set-AzContext -SubscriptionId ... -Scope Process -WarningAction SilentlyContinue`, then **check** the switch worked before reading or writing anything. Wrap all subscription work in `try/finally` and restore `$originalContext` in the `finally`. Only consider `Enabled` subscriptions, and remove duplicates by Id. A requested subscription that isn't found is a WARN. None found is an ERROR. |
| 38 | **Check before every write** | Immediately before each change, check its precondition (the target exists or doesn't, the subnet is empty, and so on). If a check fails, throw with "No changes made". Check the RBAC role before any `-Apply` and stop before touching anything. |
| 39 | **One item at a time** | When changing many items (VMs, NICs), give each one its own `try/catch` and a status (`Success` / `Failed-*` / `Skipped-*`). Roll back partial work when it is safe to. End with a results table. |
| 40 | **Multi-phase, snapshot and compare** | Split long risky operations into phases you can verify one at a time, with a JSON state file between them. Each phase ends by logging the next step. For changes that should end where they started, take BEFORE and AFTER snapshots of the properties that matter, compare them field by field, and leave out fields that change on every write (ETag, ProvisioningState). |

Use Resource Graph (`Search-AzGraph` with paging) for inventory across the
whole tenant, and per-subscription cmdlets for targeted work.

---

## 7. API and External Calls (Meraki Scripts)

| # | Check | Detail |
|---|-------|--------|
| 16 | **`Invoke-RestMethod` only inside the wrapper** | All API calls must go through `Invoke-MerakiRequest`, never directly. Zero direct calls outside the wrapper. |
| 17 | **`Invoke-MerakiRequest` retry wrapper** | Must handle HTTP 429, 5xx transient errors, and connection-level failures (null status code) with exponential backoff. |
| 30 | **Security helper functions present where applicable** | `Test-ValidSerial`, `Test-ValidSwitchConfig`, `ConvertTo-NormalizedMac` in the migration script family. |

---

## 8. Security

| # | Check | Detail |
|---|-------|--------|
| 18 | **Placeholder config values preserved** | Credentials and secrets (API keys, org IDs, tenant IDs, thumbprints, etc.) must remain as `your_xxx_here` placeholders in delivered scripts. A file with real credentials in plain text fails. Subscription names, subnet ranges and hostnames are not secrets and may be defaults. *(Also covers #29.)* |
| 28 | *Merged into #14* | Dangerous constructs. |
| 29 | *Merged into #18* | Placeholder config values. |
| 31 | **Read-only unless explicitly destructive** | Scripts that only read data should only use `Get-*` / `GET` API calls (switching context in your own session per #37 is allowed). Any write operation must be clearly documented and gated behind `-Apply` or `-Preview` (#23). |

---

## 9. Verification

| # | Check | Detail |
|---|-------|--------|
| 48 | **Test the way it runs** | Test fixes by running the script as a **file** on the PowerShell version it targets (5.1 Desktop vs 7), not by typing commands into the console. Some bugs only show up one way. Reproduce a bug with a standalone diagnostic before calling it fixed, and check the fix the same way. Run a preview and read it before every `-Apply`. |

---

## 10. Correct Script Template

```powershell
# ============================================================
# Verb-Noun_v1.0.ps1
# Version 1.0
#
# [Summary: what it does and why]
#
# WHAT THIS SCRIPT CHANGES:
#   Azure:           Nothing. / With -Apply, ...
#   Your PS session: ...
#   Your computer:   Creates ... Writes ...
#
# WHAT THE RESULTS DO NOT SHOW: / PREREQUISITES: / PARAMETERS: /
# OUTPUT: / EXAMPLES:
#
# v1.0: Initial release.
# ============================================================

[CmdletBinding()]
param(
    [string]$TargetName = "",   # required; never [Parameter(Mandatory)] (#13)
    [switch]$Apply              # preview by default; never -WhatIf (#23)
)

$missing = @()
if ($TargetName -eq "") { $missing += "-TargetName" }
if ($missing.Count -gt 0) { throw ("Missing required parameter(s): {0}" -f ($missing -join ", ")) }

# ============================================================
# CONFIGURATION -- placeholders only for secrets (#18)
# ============================================================
$LogDir        = "C:\Logs\Azure"
$ScriptVersion = "1.0"
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


Write-Log "$scriptName started (version $ScriptVersion)"
Write-Log ("Mode: {0}" -f $(if ($Apply) { "APPLY - changes will be made" } else { "PREVIEW - no changes will be made" }))
Write-Log "Log file: $logFile"

# Azure: session check, context save/switch/verify, try/finally restore (#36, #37)
# Build the plan once; show it; exit 0 if not -Apply (#23)
# Check before every write (#38); one item at a time (#39)

Write-Log "$scriptName finished"
```

---

## Revision history

- **2026-10-02** - Merged the 2026-09-28 17:11:46 review standards (#1-#31)
  with conventions taken from the scripts in this repo (#32-#49). #25, #28
  and #29 were duplicates and are now merged into #12, #14 and #18. Rules
  #8, #19, #21, #22, #23 and #26 were expanded to match how the scripts
  already use them. #23 now prefers preview-by-default with `-Apply`. The
  template's `Write-Log` drops the unused `-Color` override.
- **2026-09-28 17:11:46** - Original review standards, #1-#31.

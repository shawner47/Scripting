# PowerShell Scripting Standards

These standards are taken from the scripts already in this repo. The most
consistent examples are `Inventory-NSG-Associations_v1.3.ps1`,
`Export-NSG-Rules_v1.0.ps1`, `New-BaselineNSG_v1.0.ps1` and
`Move-Subnet-Delegation-Fix_v1.8.ps1`. Use them as templates.

> **Numbering note:** some scripts cite standards by number (8, 13, 19, 21,
> 22, 27). That numbered list is not in this repo yet. The table at the end
> maps the known numbers to sections here. Once the original list is added,
> this document should be renumbered to match it.

Scripts come in two kinds, and some rules only apply to one:

- **Azure / admin scripts** read or change Azure or other infrastructure.
  Every section applies.
- **Interactive diagnostic monitors** (the `Test-*Connection` /
  `Test-Ldap*` family) run in a console until something happens. Sections
  1-5 apply. Section 6 (logging) applies in the reduced form described there.

Throwaway debug snippets (like `Diagnose-StateFileLoad-v2.ps1`) are exempt
until they are kept. A kept snippet becomes a real script and must meet the
standards.

---

## 1. File naming, versioning, encoding

- **Name:** `Verb-Noun_vMAJOR.MINOR.ps1`, for example
  `Export-NSG-Rules_v1.0.ps1`. Use an approved PowerShell verb. Put an
  underscore before the version (not `-v2`) and always use a two-part
  version.
- **Casing:** acronyms in names should be cased the same way every time
  (decide `LDAP` vs `Ldap` once; currently both are used).
- **One version, set once (std 8):** `$ScriptVersion = "X.Y"` in the
  CONFIGURATION block. Log lines read it from there and never type the
  version in.
- **New version = new file.** A change bumps the version in the file name,
  the header, and `$ScriptVersion`, and adds a `vX.Y changes:` entry.
- **Encoding:** UTF-8 **with BOM**, **CRLF** line endings. The BOM matters on
  Windows PowerShell 5.1, which otherwise reads non-ASCII characters
  incorrectly. `.gitattributes` keeps git from changing these bytes.

## 2. Header block

Every script starts with a `# ====` banner comment block, in this order:

1. File name, then `Version X.Y`
2. A plain-English summary of what the script does and why
3. `WHAT THIS SCRIPT COLLECTS:` (read-only scripts) - numbered list
4. `WHAT THIS SCRIPT CHANGES:` - **always present**, with three sub-headings:
   - `Azure:` (or the system being targeted) - say "Nothing" if that's true
   - `Your PS session:` - context switches and how they are restored
   - `Your computer:` - folders created and files written
5. `HANDLE THE OUTPUT AS SENSITIVE:` - when output contains IPs, rules,
   identities, etc.
6. `WHAT THE RESULTS DO NOT SHOW:` - known blind spots, so results are not
   over-read
7. `PREREQUISITES:` - modules, sign-in, minimum RBAC role
8. `RECOMMENDED EXECUTION ORDER:` - for multi-phase scripts
9. `PARAMETERS:` - every parameter, its default, and what happens when a
   value is invalid
10. `OUTPUT:` - every file written, with the full name pattern
11. `EXAMPLES:` - runnable command lines, with a short note under each one
    when what it does isn't obvious
12. Version history, newest first: `vX.Y changes:` bullets, ending with
    `v1.0: Initial release.` Each entry gives what changed and **why**. For
    bug fixes, include how the bug showed up and how the fix was confirmed.

Diagnostic monitors also include `PURPOSE:` (with an interpretation table
covering each possible outcome) and `INTERPRETING RESULTS:`.

## 3. Parameters and configuration

- Start with `[CmdletBinding()]` followed by `param(...)`.
- **No `[Parameter(Mandatory)]` (std 13).** Mandatory rejects `""` when the
  script runs and prompts interactively. Give required parameters a default
  of `""` and check them right after `param()`, collecting every missing one
  into a single `throw "Missing required parameter(s): ..."`. This also
  applies to helper functions: `Write-Log ""` must work.
- Fixed values (paths, address lists, version) go in a single block:

  ```powershell
  # ============================================================
  # CONFIGURATION
  # ============================================================
  $LogDir        = "C:\Logs\Azure"
  $ScriptVersion = "1.0"
  # ============================================================
  ```

  Each non-obvious value gets a comment saying where it came from.
- Defaults that list scope (for example `-SubscriptionName`) name the real
  in-scope items. When a requested item isn't found, log a WARN and keep
  going. When nothing is found, stop with an ERROR.
- Choose phase values from a fixed list and check them explicitly
  (`$validPhases -notcontains $Phase`).

## 4. Safety for anything that changes something

- **Preview is the default.** A change only happens with `-Apply`. Without
  it, the script prints exactly what it would do, logs
  `Preview only. No changes were made...` at WARN, and `exit 0`.
- **Build the plan once and use it for both modes.** What the preview shows
  must be exactly what `-Apply` does (see `New-BaselineNSG`).
- **Check before every write.** Do the matching check immediately before
  each change (the target exists or doesn't, the subnet is empty, the
  permission is held). If it fails, throw with "No changes made".
- **Fail fast on permissions.** Before any `-Apply`, check the RBAC role
  and stop before touching anything.
- **Isolate each item.** When processing many items (VMs, NICs), give each
  one its own `try/catch`. Record a status per item (`Success`, `Failed-*`,
  `Skipped-*`), roll back partial work where it is safe to, and finish with
  a results table.
- **Snapshot and compare.** For round-trip changes, take a BEFORE snapshot
  of the specific meaningful properties, then an AFTER snapshot, and compare
  them field by field. Leave out fields that change on every write (ETag,
  ProvisioningState).
- **Multi-phase over monolithic.** Split long, risky operations into phases
  that can each be verified separately. Save state to a JSON file between
  phases.
- **Say what's next.** Every phase finishes by logging the next step.

## 5. Azure session handling

- Never call `Connect-AzAccount` from the script. Check for an existing
  session and stop with a clear instruction if there isn't one:

  ```powershell
  $originalContext = Get-AzContext
  if (-not $originalContext) {
      Write-Log "No Azure session found. Run Connect-AzAccount first, then run this script again." -Level ERROR
      throw "No Azure session found. Run Connect-AzAccount first."
  }
  ```

- Switch subscriptions with `Set-AzContext -Scope Process
  -WarningAction SilentlyContinue`, then **confirm** the switch
  (`(Get-AzContext).Subscription.Id -ne $sub.Id`) before reading or writing.
- Put all subscription work in `try { } finally { }` and restore
  `$originalContext` in the `finally`, then log that it was restored.
- Only look at `Enabled` subscriptions. Remove duplicate subscriptions by Id.
- Use Resource Graph (`Search-AzGraph`, with paging) for tenant-wide
  inventory. Use per-subscription cmdlets for targeted work.

## 6. Logging and console output

- **Folders first.** Create `$LogDir` and the output folders before the
  first log line is written.
- **One timestamp per run (std 21):** `$stamp = Get-Date -Format
  "yyyy.MM.dd.HHmmss"`, shared by the log file and every output file.
- **Log file name (std 21):** `Join-Path $LogDir "$stamp.$scriptName.log"`,
  where `$scriptName` is the file name without `.ps1`.
- **Default locations:** logs go to `C:\Logs\Azure` (state files go to
  `C:\Logs\Azure\State`). Report output defaults to `C:\Temp`, and the
  `-OutputDirectory` parameter overrides it.
- **Standard `Write-Log`.** Copy this function word for word. Levels are
  `INFO`, `WARN`, `ERROR` and `SUCCESS`. Console colors come from the level
  only (std 19): INFO=White, WARN=Yellow, SUCCESS=Green, ERROR=Red.

  ```powershell
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
  ```

- **Tables go to the log too (std 22).** Use `Write-LogTable` (Format-Table
  → Out-String -Width 250 → one `Write-Log` per line). Never write a bare
  `Format-Table` or `Write-Host` that bypasses the log.
- **Run framing.** First line: `"$scriptName started (version
  $ScriptVersion)"`, followed by mode, targets, output folder and log path.
  Last line: `"$scriptName finished"`. Before the end, list every file
  written under `Files written:` (SUCCESS).
- **Completeness tally.** When scanning many scopes, log a count per scope so
  you can see at a glance that the scan covered everything.
- **Diagnostic monitors:** the CSV data log is the primary output. Name it
  `$stamp.<test-name>-log.csv` and allow a `-LogPath` override. Console
  colors may show connection state (Green healthy / Red lost / Yellow
  notice). New monitors should also write a `Write-Log` run log, so the
  start, the parameters and the outcome are recorded.

## 7. Output files

- CSV: `Join-Path $OutputDirectory "$stamp.<dataset>.csv"`, written with
  `Export-Csv -NoTypeInformation -Encoding UTF8`.
- **Build every path with `Join-Path` (std 27)**, never by joining strings.
- Name CSV columns in PascalCase and keep them stable across versions. When
  a value is a list, sort it and join it (`Join-Sorted`) so that the same
  data always produces the same text.
- When nothing matches, that's a clean stop, not an error: log WARN, write
  nothing, `exit 0`. If an empty file is wanted, write a header-only CSV
  correctly (`"" | Export-Csv` does **not** do this, see the README review).
- JSON state: `ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8`.

## 8. PowerShell coding rules

- **Load JSON arrays in three statements (Windows PowerShell 5.1):**

  ```powershell
  $raw    = Get-Content -Path $File -Raw
  $parsed = $raw | ConvertFrom-Json
  $items  = @($parsed)
  ```

  Root cause: on 5.1, `ConvertFrom-Json` outputs a JSON array as a **single**
  pipeline object. `@(... | ConvertFrom-Json)` wraps that whole array as one
  element, so `.Count` is 1. Reading a property on it (`$x[0].NicName`)
  gathers the value from every entry, which prints as a space-joined string.
  Assigning to a variable first and then applying `@()` avoids this.
- **Collections:** use `System.Collections.Generic.List[object]` and `.Add()`
  inside loops. Avoid `$array +=`, which copies the whole array on every add.
- **Force arrays:** wrap results whose count you need in `@()`:
  `@(Get-AzX | Where-Object ...)`.
- **Null-safe navigation:** check each level before using it
  (`if ($nic.NetworkSecurityGroup -and $nic.NetworkSecurityGroup.Id)`).
- **Hashtable enumeration:** `GetEnumerator()` returns `.Key` / `.Value`,
  not `.Name`.
- **Don't assign to automatic variables** (`$matches`, `$input`, `$args`,
  `$error`, `$_`, `$PSItem`, `$host`, `$event`). Variable names are not case
  sensitive, so `$matches` is the same variable as `$Matches`.
- **Errors:** use `-ErrorAction Stop` inside `try` blocks, and
  `-ErrorAction SilentlyContinue` only when a missing object is an expected
  answer and is checked straight after. Log the message, then `throw` on
  fatal errors.
- **Comments say why, not what.** When a non-obvious pattern exists because
  of a bug that was found, the comment says so and gives the version.
- Reuse helper functions word for word between scripts (`Write-Log`,
  `Write-LogTable`, `Get-LastSegment`, `Join-Sorted`). If they ever move into
  a shared module, that move is a separate, deliberate change.

## 9. Verification before release

- Run a bug fix the same way it is really used: as a **file** on the target
  PowerShell version (5.1 Desktop vs 7), not typed into the console. Some
  bugs only show up one way.
- Reproduce a bug with a standalone diagnostic before claiming it is fixed,
  and check the fix the same way.
- Run every change in preview first and read the output before running with
  `-Apply`.

---

## Known standard numbers referenced in scripts

| No. | Rule (as cited)                                              | Section |
|-----|--------------------------------------------------------------|---------|
| 8   | Version set once in `$ScriptVersion`                         | 1       |
| 13  | No `[Parameter(Mandatory)]`; it rejects `""` at runtime      | 3       |
| 19  | Log lines use level colors only                              | 6       |
| 21  | Log file `yyyy.MM.dd.HHmmss.<script name>.log`, one stamp/run | 6       |
| 22  | Tables written to the log as well as the console             | 6       |
| 27  | Paths built with `Join-Path`                                 | 7       |

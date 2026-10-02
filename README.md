# Scripting

PowerShell scripts for Azure network and governance work, plus tools for
diagnosing network connections. Every script follows [STANDARDS.md](STANDARDS.md).

> **Layout:** everything sits at the top level for now. How to organize the
> folders hasn't been decided yet.

## Inventory

| Script | Kind | Changes things? | Purpose |
|---|---|---|---|
| `Inventory-NSG-Associations_v1.3.ps1` | Azure | No | NSG / subnet / NIC attachment inventory and NIC coverage classification |
| `Export-NSG-Rules_v1.0.ps1` | Azure | No | Exports custom NSG rules and finds identical / shared / unique rule sets |
| `Get-AzureGovernanceReport_v1.0.ps1` | Azure | No | Tenant-wide subscriptions, MGs, RGs, resources, RBAC, policy via Resource Graph |
| `New-BaselineNSG_v1.0.ps1` | Azure | With `-Apply` | Creates the baseline NSG (not attached anywhere) |
| `Move-Subnet-Delegation-Fix_v1.8.ps1` | Azure | With `-Apply` | Multi-phase fix that clears a stuck delegation on subnet1/subnet2 |
| `Test-IdleConnection_v1.0.ps1` | Monitor | No | Raw TCP socket left idle; logs when it drops |
| `Test-ActiveConnection_v1.0.ps1` | Monitor | No | Raw TCP socket with a 1-byte keepalive |
| `Test-LDAPBindConnection_v1.0.ps1` | Monitor | No | Real LDAP bind (Negotiate), then left idle |
| `Test-LdapPeriodicActivity_v1.0.ps1` | Monitor | No | Real LDAP bind and a RootDSE search at a set interval |
| `Diagnose-StateFileLoad-v2.ps1` | Scratch | No | Reproduction of the PS 5.1 `@(... \| ConvertFrom-Json)` bug |
| `Baseline-NSG-Rule-List.md` | Doc | - | The baseline NSG rule set and where each rule came from |

## Standards review (2026-10-02)

These findings come from reading the code. No script was run. The scripts
have **not** been changed. Each fix below is planned for that script's next
version.

### Bugs

1. **`Get-AzureGovernanceReport_v1.0.ps1` - `Write-Log ""` fails.**
   `Write-Log` declares `[Parameter(Mandatory)][string]$Message`, and a
   Mandatory string parameter rejects an empty string. The ~8 calls like
   `Write-Log "" ; Write-Log "Phase 1..."` each raise a parameter-binding
   error (the script carries on, but shows red errors). This is the
   standard 13 rule; swap in the standard `Write-Log`.
2. **`Get-AzureGovernanceReport_v1.0.ps1` - empty CSVs are not header-only.**
   `"" | Export-Csv` exports the *string's* properties, so the file ends up
   with a `"Length"` column and a `0` row instead of the dataset's headers.
   To get a true header-only file, write the known column names directly
   (or build an empty object with those properties, `ConvertTo-Csv`, and
   keep only the first line).
3. **`Move-Subnet-Delegation-Fix_v1.8.ps1` - `$matches` in
   `Test-SufficientPermission`** overwrites the automatic `$Matches`
   variable. It does no harm here, but rename it (for example
   `$qualifying`).
4. **`Test-LdapPeriodicActivity_v1.0.ps1` - result can be misread.**
   `LdapConnection` reconnects on its own by default. If the original TCP
   session drops, the next `SendRequest` can open a *new* connection on a
   different local port and report `[SEARCH OK]`, while the script is still
   watching the old port. When a search succeeds, check that the local port
   hasn't changed (or set `SessionOptions.AutoReconnect = $false`) so that
   "real activity kept it alive" isn't confused with "it reconnected".

### Places where scripts don't follow the standards

| Script | Gaps |
|---|---|
| `Get-AzureGovernanceReport_v1.0.ps1` | Calls `Connect-AzAccount` itself (§5); log named `Get-AzureGovernanceReport_<stamp>.log` instead of `<stamp>.<script>.log` (std 21); no level colors (std 19); no `$ScriptVersion`, version typed into log lines (std 8); `$Script:Config` hashtable instead of a CONFIGURATION variable block; log dir `C:\Logs\AzureGovernanceReport` and output `C:\Reports\...` instead of the standard locations; `$all +=` / `$mgRows +=` array growth; final `Write-Host` bypasses the log; header has no `WHAT THIS SCRIPT CHANGES` section; `[WARN]` appears twice in a WARN line. |
| `Test-*` monitors (all four) | No `[CmdletBinding()]`; `C:\Temp` typed into the code instead of using `Join-Path`; no run log; the timestamp in the CSV uses the machine's regional date format (use `Get-Date -Format "yyyy-MM-dd HH:mm:ss"`). `Test-LdapPeriodicActivity` is ASCII/LF with no BOM, and its header calls the companion `Test-LdapBindConnection` while the file is named `Test-LDAPBindConnection` (decide on one casing). |
| `Diagnose-StateFileLoad-v2.ps1` | Scratch file: no header, LF, no BOM, `-v2` naming. Keep it as a record of the bug, or delete it now that `Move-Subnet-Delegation-Fix` v1.8 fixes the bug and documents why. |
| `Move-Subnet-Delegation-Fix_v1.8.ps1` | JSON state files are written with `Set-Content` and no `-Encoding`, so 5.1 writes them in ANSI (§7). |

### Already following the standards

`Inventory-NSG-Associations_v1.3`, `Export-NSG-Rules_v1.0`,
`New-BaselineNSG_v1.0` and `Move-Subnet-Delegation-Fix_v1.8` match the
standards apart from the items above. Use them as templates.

## Organization options (to decide later)

- **By platform:** `Azure/Network`, `Azure/Governance`, `Network-Diagnostics/`, `Docs/`
- **By lifecycle:** `Current/` and `Archive/` (older versions once a newer one replaces them)
- **Shared module:** move `Write-Log`, `Write-LogTable`, `Get-LastSegment` and `Join-Sorted` into one `.psm1`. That would remove the copied code, but scripts would no longer run as a single file on their own.

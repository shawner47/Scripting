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
| `Add-MerakiThreatIPs_v3.5.ps1` | Meraki | Yes (omit with `-Preview`) | Adds threat IPs as Meraki policy objects and to the org-level policy object group |
| `Test-IdleConnection_v1.0.ps1` | Monitor | No | Raw TCP socket left idle; logs when it drops |
| `Test-ActiveConnection_v1.0.ps1` | Monitor | No | Raw TCP socket with a 1-byte keepalive |
| `Test-LDAPBindConnection_v1.0.ps1` | Monitor | No | Real LDAP bind (Negotiate), then left idle |
| `Test-LdapPeriodicActivity_v1.0.ps1` | Monitor | No | Real LDAP bind and a RootDSE search at a set interval |
| `Diagnose-StateFileLoad-v2.ps1` | Scratch | No | Reproduction of the PS 5.1 `@(... \| ConvertFrom-Json)` bug |
| `Baseline-NSG-Rule-List.md` | Doc | - | The baseline NSG rule set and where each rule came from |

## Standards review (2026-10-02)

These findings come from reading each script against [STANDARDS.md](STANDARDS.md)
(#1-#49). A script also checked bytes for the encoding rules (#1-#5),
backtick continuations (#12), balanced braces (#15), dangerous constructs
(#14) and quoting (#10, #11). No script was run. The scripts have **not**
been changed. Each fix below is planned for that script's next version.

### Bugs

1. **`Get-AzureGovernanceReport_v1.0.ps1` - `Write-Log ""` fails (#20).**
   `Write-Log` declares `[Parameter(Mandatory)][string]$Message`, so the ~8
   `Write-Log ""` calls each raise a parameter-binding error. The script
   carries on, but shows red errors.
2. **`Get-AzureGovernanceReport_v1.0.ps1` - empty CSVs are not header-only (#47).**
   `"" | Export-Csv` writes a `Length` column with a `0` row instead of the
   dataset's column names.
3. **`Move-Subnet-Delegation-Fix_v1.8.ps1` - `$matches` (#43)** in
   `Test-SufficientPermission` overwrites the automatic `$Matches`. It does
   no harm here, but rename it.
4. **`Test-LdapPeriodicActivity_v1.0.ps1` - result can be misread.**
   `LdapConnection` reconnects on its own by default, so `[SEARCH OK]` can be
   reported on a *new* TCP connection while the script is still watching the
   old port. When a search succeeds, check that the local port hasn't
   changed (or set `SessionOptions.AutoReconnect = $false`).

### Rule violations

| Script | Rules broken |
|---|---|
| `Get-AzureGovernanceReport_v1.0.ps1` | #12 backtick continuations (4, in Phase 1 `Select-Object`); #19 no level colors; #8 version typed into log lines, no `$ScriptVersion`; #21 log named `Get-AzureGovernanceReport_<stamp>.log`; #22 final `Write-Host` skips the log; #33 no `WHAT THIS SCRIPT CHANGES`; #35 `$Script:Config` hashtable; #36 calls `Connect-AzAccount`; #42 `+=` inside loops; #46 non-standard log/output folders. |
| `Test-LdapPeriodicActivity_v1.0.ps1` | #1 LF line endings; #2 no BOM; #5 no trailing CRLF; #32 `Ldap` vs `LDAP` casing differs from its companion file; plus the monitor items below. |
| `Test-*` monitors (all four) | #9 no `[CmdletBinding()]`; #27 `C:\Temp` typed into the code instead of using `Join-Path`; #49 CSV timestamp uses the regional date format, and there's no run log. |
| `Move-Subnet-Delegation-Fix_v1.8.ps1` | #26 JSON state files written with `Set-Content` and no `-Encoding`. |
| All scripts with `Write-Log` | Optional cleanup on each script's next version: drop the unused `-Color` override so the function matches the template (#19). |
| `Diagnose-StateFileLoad-v2.ps1` | Scratch file (exempt), but would fail #1, #2, #5, #9, #32. Keep it as a record of the bug, or delete it. |

### Clean against #1-#15 and the core rules

`Inventory-NSG-Associations_v1.3`, `Export-NSG-Rules_v1.0`,
`New-BaselineNSG_v1.0` and `Move-Subnet-Delegation-Fix_v1.8` pass the
encoding and syntax checks and follow the standards apart from the items
above. Use them as templates.

## Organization options (to decide later)

- **By platform:** `Azure/Network`, `Azure/Governance`, `Network-Diagnostics/`, `Docs/`
- **By lifecycle:** `Current/` and `Archive/` (older versions once a newer one replaces them)
- **Shared module:** move `Write-Log`, `Write-LogTable`, `Get-LastSegment` and `Join-Sorted` into one `.psm1`. That would remove the copied code, but scripts would no longer run as a single file on their own.

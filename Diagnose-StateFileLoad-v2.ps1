$StateFile = "C:\Logs\Azure\State\subnet-migration-state.json"

Write-Host "=== Testing the corrected three-statement pattern ==="
$rawStateJson = Get-Content -Path $StateFile -Raw
$parsedState = $rawStateJson | ConvertFrom-Json
$savedState = @($parsedState)

Write-Host "savedState count: $($savedState.Count)"
Write-Host "First entry type: $($savedState[0].GetType().FullName)"
Write-Host "First entry NicName: $($savedState[0].NicName)"
Write-Host "Last entry NicName: $($savedState[-1].NicName)"
Write-Host ""
Write-Host "All NicName values:"
foreach ($entry in $savedState) {
    Write-Host "  $($entry.VM) -> $($entry.NicName)"
}

# Behavior checks for the path-root policy in scripts/security-acl.ps1.
# Run under Windows PowerShell 5.1 and PowerShell 7 by CI; exits non-zero on failure.
# The policy tables themselves are compared with csp_mcp/config.py by
# tests/test_config.py, so this file only checks how the audit applies them.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\security-acl.ps1')

$Base = 'C:\CspAclTest'
$Roots = [ordered]@{
    input = @{ id = 'input'; path = "$Base\Assets\Input"; read = $true; write = $false }
    working = @{ id = 'working'; path = "$Base\Assets\Working"; read = $true; write = $true }
    exports = @{ id = 'exports'; path = "$Base\Assets\Exports"; read = $true; write = $true }
    cst_copy = @{ id = 'cst_copy'; path = "$Base\.workspace\csps-cst-working-2026-10-14"; read = $true; write = $true }
    cst_ascii_copy = @{ id = 'cst_ascii_copy'; path = "$Base\Temp\csps-cst-ascii-20261014"; read = $true; write = $true }
}

function New-RootEntries {
    param([object[]]$Entries)
    # Round-trip through JSON so entries look exactly like a parsed config file.
    return (ConvertTo-Json -InputObject @($Entries) -Depth 4 | ConvertFrom-Json)
}

function Copy-Root {
    param([string]$Id, [hashtable]$Changes = @{})
    $Entry = @{}
    foreach ($Key in $Roots[$Id].Keys) { $Entry[$Key] = $Roots[$Id][$Key] }
    foreach ($Key in $Changes.Keys) { $Entry[$Key] = $Changes[$Key] }
    return $Entry
}

$Standard = @((Copy-Root 'input'), (Copy-Root 'working'), (Copy-Root 'exports'))
$Failures = [System.Collections.Generic.List[string]]::new()

$Accepted = [ordered]@{
    'standard three' = $Standard
    'standard + cst_copy' = $Standard + @((Copy-Root 'cst_copy'))
    'standard + both CST roots' = $Standard + @((Copy-Root 'cst_copy'), (Copy-Root 'cst_ascii_copy'))
}
foreach ($Name in $Accepted.Keys) {
    try {
        $Map = Get-CspPathRootMap -PathRoots (New-RootEntries $Accepted[$Name])
        $ExpectedIds = @($Accepted[$Name] | ForEach-Object { $_.id }) -join ','
        if ((@($Map.Keys) -join ',') -ne $ExpectedIds) {
            $Failures.Add("$Name`: returned ids $(@($Map.Keys) -join ',')")
        }
    } catch {
        $Failures.Add("$Name`: unexpectedly rejected: $($_.Exception.Message)")
    }
}

$Rejected = @(
    @{ Name = 'unknown id'; Entries = $Standard + @((Copy-Root 'cst_copy' @{ id = 'arbitrary' })); Message = 'unknown or duplicate id: arbitrary' },
    @{ Name = 'cst_ascii_copy without cst_copy'; Entries = $Standard + @((Copy-Root 'cst_ascii_copy')); Message = 'cst_ascii_copy only together with cst_copy' },
    @{ Name = 'duplicate cst_copy'; Entries = $Standard + @((Copy-Root 'cst_copy'), (Copy-Root 'cst_copy')); Message = 'unknown or duplicate id: cst_copy' },
    @{ Name = 'missing exports'; Entries = @((Copy-Root 'input'), (Copy-Root 'working')); Message = 'must define input, working, and exports' },
    @{ Name = 'writable input'; Entries = @((Copy-Root 'input' @{ write = $true }), (Copy-Root 'working'), (Copy-Root 'exports')); Message = 'input path root has an invalid write policy' },
    @{ Name = 'read-only cst_copy'; Entries = $Standard + @((Copy-Root 'cst_copy' @{ write = $false })); Message = 'cst_copy path root has an invalid write policy' },
    @{ Name = 'unreadable cst_ascii_copy'; Entries = $Standard + @((Copy-Root 'cst_copy'), (Copy-Root 'cst_ascii_copy' @{ read = $false })); Message = 'cst_ascii_copy path root must have read=true' },
    @{ Name = 'string write flag'; Entries = $Standard + @((Copy-Root 'cst_copy' @{ write = 'true' })); Message = 'cst_copy path root has an invalid write policy' },
    @{ Name = 'cst_copy inside working'; Entries = $Standard + @((Copy-Root 'cst_copy' @{ path = "$Base\Assets\Working\cst" })); Message = 'must not duplicate or contain one another' },
    @{ Name = 'CST roots share a path'; Entries = $Standard + @((Copy-Root 'cst_copy'), (Copy-Root 'cst_ascii_copy' @{ path = $Roots['cst_copy'].path })); Message = 'must not duplicate or contain one another' }
)
foreach ($Case in $Rejected) {
    try {
        [void](Get-CspPathRootMap -PathRoots (New-RootEntries $Case.Entries))
        $Failures.Add("$($Case.Name): unexpectedly accepted")
    } catch {
        if (-not $_.Exception.Message.Contains($Case.Message)) {
            $Failures.Add("$($Case.Name): wrong error: $($_.Exception.Message)")
        }
    }
}

$Total = $Accepted.Count + $Rejected.Count
if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { Write-Host "FAIL $_" }
    Write-Host "Path-root policy: $($Failures.Count) of $Total cases failed on PowerShell $($PSVersionTable.PSVersion)"
    exit 1
}
Write-Host "Path-root policy: $Total of $Total cases passed on PowerShell $($PSVersionTable.PSVersion)"

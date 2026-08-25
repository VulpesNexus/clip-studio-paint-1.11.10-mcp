[CmdletBinding()]
param(
    [switch]$AcceptInsecureAncestorRisk
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

. (Join-Path $PSScriptRoot 'security-acl.ps1')

function Get-CspCodexConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
        $CodexHome = Resolve-CspSafeLocalPath `
            -Value $env:CODEX_HOME `
            -FieldName 'CODEX_HOME'
    } else {
        $CodexHome = Resolve-CspSafeLocalPath `
            -Value (Join-Path $env:USERPROFILE '.codex') `
            -FieldName 'Codex home'
    }
    return Join-Path $CodexHome 'config.toml'
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $Hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return -join ($Hasher.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $Hasher.Dispose()
    }
}

$Configuration = Get-CspConfiguration -ProjectRoot $ProjectRoot
$AclTargets = [string[]](@(
    @($ProjectRoot) + @($Configuration.ExternalConfigRoots) + @($Configuration.AssetRoots) |
        Sort-Object -Unique
))
$ConfigPath = Get-CspCodexConfigPath

$AncestorIssues = @(
    Get-CspInsecureAncestors -LiteralPaths $AclTargets |
        Sort-Object Path, Reason, Sid -Unique
)
foreach ($Issue in $AncestorIssues) {
    Write-Warning "Untrusted ancestor remains: $($Issue.Path) [$($Issue.Reason) $($Issue.Sid) $($Issue.Rights)]"
}
if ($AncestorIssues.Count -gt 0 -and -not $AcceptInsecureAncestorRisk) {
    throw 'Unregistration refused below an untrusted ancestor. Review the report or rerun with -AcceptInsecureAncestorRisk.'
}
Assert-CspRestrictedAcl -LiteralPaths $AclTargets

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python does not exist: $Python"
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Codex config does not exist: $ConfigPath"
}
Assert-CspRestrictedFileLocation -LiteralPath $ConfigPath
foreach ($AssetRoot in $Configuration.AssetRoots) {
    if (-not (Test-Path -LiteralPath $AssetRoot -PathType Container)) {
        throw "Configured asset root does not exist: $AssetRoot"
    }
}

$Mutex = [System.Threading.Mutex]::new($false, 'Local\CspLocalMcpCodexConfig')
$Acquired = $false
$CandidatePath = $null
$BackupPath = $null
$Replaced = $false
try {
    try {
        $Acquired = $Mutex.WaitOne([TimeSpan]::FromSeconds(30))
    } catch [System.Threading.AbandonedMutexException] {
        $Acquired = $true
    }
    if (-not $Acquired) {
        throw 'Timed out waiting for the CSP Codex-config registration lock.'
    }

    $OriginalBytes = [System.IO.File]::ReadAllBytes($ConfigPath)
    $OriginalHash = Get-Sha256Hex $OriginalBytes
    $OriginalText = [System.Text.Encoding]::UTF8.GetString($OriginalBytes).TrimStart([char]0xFEFF)
    $OriginalLines = @($OriginalText -split '\r?\n')
    $ConfigLines = [System.Collections.Generic.List[string]]::new()
    $SkipCspSection = $false
    foreach ($Line in $OriginalLines) {
        if ($Line -match '^\s*\[') {
            $SkipCspSection = $Line -match '^\s*\[mcp_servers\.csp(?:\..*)?\]\s*$'
        }
        if (-not $SkipCspSection) {
            $ConfigLines.Add($Line)
        }
    }
    while ($ConfigLines.Count -gt 0 -and [string]::IsNullOrWhiteSpace($ConfigLines[$ConfigLines.Count - 1])) {
        $ConfigLines.RemoveAt($ConfigLines.Count - 1)
    }
    $ConfigLines.Add('')

    $ConfigDirectory = Split-Path -Parent $ConfigPath
    $Nonce = [Guid]::NewGuid().ToString('N')
    $CandidatePath = Join-Path $ConfigDirectory ".config.toml.csp-remove-$Nonce.tmp"
    [System.IO.File]::WriteAllLines(
        $CandidatePath,
        [string[]]$ConfigLines,
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-CspRestrictedFileLocation -LiteralPath $CandidatePath
    & $Python -X utf8 -c 'import sys,tomllib; d=tomllib.load(open(sys.argv[1], "rb")); assert "csp" not in d.get("mcp_servers", {})' $CandidatePath
    if ($LASTEXITCODE -ne 0) {
        throw 'Generated Codex config is invalid or still contains the CSP server.'
    }

    $CurrentHash = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($ConfigPath))
    if ($CurrentHash -ne $OriginalHash) {
        throw 'Codex config changed concurrently; no replacement was performed.'
    }

    $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupPath = "$ConfigPath.csp-local-mcp-remove-$Stamp.bak"
    [System.IO.File]::Replace($CandidatePath, $ConfigPath, $BackupPath, $true)
    $CandidatePath = $null
    $Replaced = $true

    try {
        Assert-CspRestrictedFileLocation -LiteralPath $ConfigPath
        Assert-CspRestrictedFileLocation -LiteralPath $BackupPath
        $ListOutput = @(& codex mcp list --json 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Codex could not validate the updated MCP list (exit code $LASTEXITCODE)."
        }
        try {
            $Servers = ([string]::Join([System.Environment]::NewLine, $ListOutput) | ConvertFrom-Json)
        } catch {
            throw 'Codex returned invalid JSON while validating the updated MCP list.'
        }
        if (@($Servers | Where-Object { $_.name -eq 'csp' }).Count -ne 0) {
            throw 'Codex still resolves csp after unregistration.'
        }
    } catch {
        $Failure = $_.Exception.Message
        if (-not ($Replaced -and $BackupPath -and (Test-Path -LiteralPath $BackupPath -PathType Leaf))) {
            throw "Codex validation failed and the rollback backup is unavailable. $Failure"
        }
        try {
            $FailedPath = "$ConfigPath.csp-local-mcp-remove-failed-$Stamp"
            [System.IO.File]::Replace($BackupPath, $ConfigPath, $FailedPath, $true)
            $Replaced = $false
        } catch {
            throw "Codex validation failed and rollback also failed. Validation: $Failure Rollback: $($_.Exception.Message)"
        }
        throw "Codex config validation failed; original restored. $Failure"
    }
} finally {
    if ($CandidatePath -and (Test-Path -LiteralPath $CandidatePath)) {
        Remove-Item -LiteralPath $CandidatePath -Force
    }
    if ($Acquired) {
        [void]$Mutex.ReleaseMutex()
    }
    $Mutex.Dispose()
}

Write-Host 'Unregistered MCP server: csp (atomic config replacement; backup retained).'
Write-Host 'Restart the Codex desktop app to unload the tools.'

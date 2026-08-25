[CmdletBinding()]
param(
    [switch]$AcceptInsecureAncestorRisk
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$Server = Join-Path $ProjectRoot 'server.py'

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

function ConvertTo-CspTomlBasicString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $Builder = [System.Text.StringBuilder]::new()
    [void]$Builder.Append('"')
    foreach ($Character in $Value.ToCharArray()) {
        $Code = [int][char]$Character
        $Escape = $null
        switch ($Code) {
            8 { $Escape = '\b'; break }
            9 { $Escape = '\t'; break }
            10 { $Escape = '\n'; break }
            12 { $Escape = '\f'; break }
            13 { $Escape = '\r'; break }
            34 { $Escape = '\"'; break }
            92 { $Escape = '\\'; break }
        }
        if ($null -ne $Escape) {
            [void]$Builder.Append($Escape)
            continue
        }
        if ($Code -lt 32 -or $Code -eq 127) {
            throw 'A path contains a control character that cannot be written safely to TOML.'
        }
        [void]$Builder.Append($Character)
    }
    [void]$Builder.Append('"')
    return $Builder.ToString()
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
if ($Configuration.IsTrackedTemplate) {
    throw 'config\config.json is a fail-closed reference template. Run scripts\configure.ps1 before registration.'
}
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
    throw 'Registration refused below an untrusted ancestor. Review the report or rerun with -AcceptInsecureAncestorRisk.'
}
Assert-CspRestrictedAcl -LiteralPaths $AclTargets

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Run scripts\install.ps1 first.'
}
if (-not (Test-Path -LiteralPath $Server -PathType Leaf)) {
    throw "MCP server entry point does not exist: $Server"
}
if (-not (Test-Path -LiteralPath $Configuration.CspExecutable -PathType Leaf)) {
    throw "Configured CSP executable does not exist: $($Configuration.CspExecutable)"
}
foreach ($AssetRoot in $Configuration.AssetRoots) {
    if (-not (Test-Path -LiteralPath $AssetRoot -PathType Container)) {
        throw "Configured asset root does not exist; run install.ps1 first: $AssetRoot"
    }
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Codex config does not exist: $ConfigPath"
}
Assert-CspRestrictedFileLocation -LiteralPath $ConfigPath

$TomlPython = ConvertTo-CspTomlBasicString $Python
$TomlServer = ConvertTo-CspTomlBasicString $Server
$TomlProjectRoot = ConvertTo-CspTomlBasicString $ProjectRoot
$TomlProfile = ConvertTo-CspTomlBasicString $Configuration.ConfigPath

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
    $ConfigLines.Add('[mcp_servers.csp]')
    $ConfigLines.Add("command = $TomlPython")
    $ConfigLines.Add("args = [`"-X`", `"utf8`", $TomlServer]")
    $ConfigLines.Add("cwd = $TomlProjectRoot")
    $ConfigLines.Add("env = { CSP_MCP_CONFIG = $TomlProfile }")
    $ConfigLines.Add('enabled = true')
    $ConfigLines.Add('required = false')
    $ConfigLines.Add('startup_timeout_sec = 20.0')
    $ConfigLines.Add('tool_timeout_sec = 45.0')
    $ConfigLines.Add('default_tools_approval_mode = "writes"')

    $AutoApprovedTokenConsumers = @(
        'csp_move_pointer',
        'csp_click',
        'csp_drag',
        'csp_scroll',
        'csp_type_text',
        'csp_navigation_key',
        'csp_run_command',
        'csp_run_auto_action',
        'csp_run_command_sequence',
        'csp_native_file_dialog'
    )
    foreach ($ToolName in $AutoApprovedTokenConsumers) {
        $ConfigLines.Add('')
        $ConfigLines.Add("[mcp_servers.csp.tools.$ToolName]")
        $ConfigLines.Add('approval_mode = "approve"')
    }

    $ConfigDirectory = Split-Path -Parent $ConfigPath
    $Nonce = [Guid]::NewGuid().ToString('N')
    $CandidatePath = Join-Path $ConfigDirectory ".config.toml.csp-$Nonce.tmp"
    [System.IO.File]::WriteAllLines(
        $CandidatePath,
        [string[]]$ConfigLines,
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-CspRestrictedFileLocation -LiteralPath $CandidatePath

    & $Python -X utf8 -c 'import sys,tomllib; tomllib.load(open(sys.argv[1], "rb"))' $CandidatePath
    if ($LASTEXITCODE -ne 0) {
        throw 'Generated Codex config is not valid TOML.'
    }

    $CurrentHash = Get-Sha256Hex ([System.IO.File]::ReadAllBytes($ConfigPath))
    if ($CurrentHash -ne $OriginalHash) {
        throw 'Codex config changed concurrently; no replacement was performed.'
    }

    $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $BackupPath = "$ConfigPath.csp-local-mcp-$Stamp.bak"
    [System.IO.File]::Replace($CandidatePath, $ConfigPath, $BackupPath, $true)
    $CandidatePath = $null
    $Replaced = $true

    try {
        Assert-CspRestrictedFileLocation -LiteralPath $ConfigPath
        Assert-CspRestrictedFileLocation -LiteralPath $BackupPath
        $Validation = & codex mcp get csp --json 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Codex rejected the generated MCP config (exit code $LASTEXITCODE)."
        }
    } catch {
        $ValidationFailure = $_.Exception.Message
        if (-not ($Replaced -and $BackupPath -and (Test-Path -LiteralPath $BackupPath -PathType Leaf))) {
            throw "Codex config validation failed and the rollback backup is unavailable. $ValidationFailure"
        }
        try {
            $FailedPath = "$ConfigPath.csp-local-mcp-failed-$Stamp"
            [System.IO.File]::Replace($BackupPath, $ConfigPath, $FailedPath, $true)
            $Replaced = $false
        } catch {
            throw "Codex config validation failed and rollback also failed. Validation: $ValidationFailure Rollback: $($_.Exception.Message)"
        }
        throw "Codex config validation failed; original restored. $ValidationFailure"
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

Write-Host 'Registered MCP server: csp (atomic config replacement; backup retained).'
Write-Host "Pinned runtime profile: $($Configuration.ConfigPath)"
Write-Host 'Restart the Codex desktop app to load newly registered tools.'

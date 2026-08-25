[CmdletBinding()]
param(
    [string]$Python,
    [switch]$AcceptInsecureAncestorRisk
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

. (Join-Path $PSScriptRoot 'security-acl.ps1')

function Test-CspPython313Candidate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [string[]]$PrefixArguments = @()
    )

    $ProbeCode = (
        'import json,sys; ' +
        'print(json.dumps({"executable":sys.executable,"major":sys.version_info.major,"minor":sys.version_info.minor}))'
    )
    try {
        $ProbeOutput = @(& $Command @PrefixArguments -c $ProbeCode 2>$null)
        $ProbeExitCode = $LASTEXITCODE
    } catch {
        return $null
    }
    if ($ProbeExitCode -ne 0) {
        return $null
    }
    $ProbeLine = $ProbeOutput |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -Last 1
    if ($null -eq $ProbeLine) {
        return $null
    }
    try {
        $Probe = [string]$ProbeLine | ConvertFrom-Json
    } catch {
        return $null
    }
    if ($Probe.major -ne 3 -or $Probe.minor -ne 13) {
        return $null
    }
    try {
        $Executable = Resolve-CspSafeLocalPath `
            -Value ([string]$Probe.executable) `
            -FieldName 'Python 3.13 executable'
    } catch {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        return $null
    }
    return [pscustomobject]@{
        Command = $Command
        PrefixArguments = [string[]]$PrefixArguments
        Executable = $Executable
    }
}

function Resolve-CspPython313 {
    param([string]$RequestedPython)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPython)) {
        $RequestedCommand = $RequestedPython
        if (
            [System.IO.Path]::IsPathRooted($RequestedPython) -or
            $RequestedPython.Contains('\') -or
            $RequestedPython.Contains('/') -or
            $RequestedPython.Contains('%')
        ) {
            $RequestedCommand = Resolve-CspSafeLocalPath `
                -Value $RequestedPython `
                -FieldName 'Python'
            if (-not (Test-Path -LiteralPath $RequestedCommand -PathType Leaf)) {
                throw "Requested Python executable does not exist: $RequestedCommand"
            }
        } else {
            $ResolvedCommand = Get-Command $RequestedPython -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($null -eq $ResolvedCommand) {
                throw "Requested Python command was not found: $RequestedPython"
            }
            $RequestedCommand = $ResolvedCommand.Source
        }
        $Prefix = @()
        if ([System.IO.Path]::GetFileName($RequestedCommand) -ieq 'py.exe') {
            $Prefix = @('-3.13')
        }
        $Selection = Test-CspPython313Candidate `
            -Command $RequestedCommand `
            -PrefixArguments $Prefix
        if ($null -eq $Selection) {
            throw 'The requested Python command is not a working Python 3.13 interpreter.'
        }
        return $Selection
    }

    $Candidates = [System.Collections.Generic.List[object]]::new()
    $Seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $PyLauncher = Get-Command 'py.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $PyLauncher -and $Seen.Add($PyLauncher.Source + '|-3.13')) {
        $Candidates.Add([pscustomobject]@{
            Command = $PyLauncher.Source
            PrefixArguments = [string[]]@('-3.13')
        })
    }

    foreach ($CandidatePath in @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
        (Join-Path $env:ProgramFiles 'Python313\python.exe')
    )) {
        if (
            -not [string]::IsNullOrWhiteSpace($CandidatePath) -and
            (Test-Path -LiteralPath $CandidatePath -PathType Leaf) -and
            $Seen.Add($CandidatePath)
        ) {
            $Candidates.Add([pscustomobject]@{
                Command = $CandidatePath
                PrefixArguments = [string[]]@()
            })
        }
    }

    foreach ($CommandName in @('python3.13.exe', 'python.exe')) {
        foreach ($CommandInfo in @(Get-Command $CommandName -CommandType Application -ErrorAction SilentlyContinue)) {
            if ($Seen.Add($CommandInfo.Source)) {
                $Candidates.Add([pscustomobject]@{
                    Command = $CommandInfo.Source
                    PrefixArguments = [string[]]@()
                })
            }
        }
    }

    foreach ($Candidate in $Candidates) {
        $Selection = Test-CspPython313Candidate `
            -Command $Candidate.Command `
            -PrefixArguments $Candidate.PrefixArguments
        if ($null -ne $Selection) {
            return $Selection
        }
    }
    throw 'Python 3.13 was not found. Install it or pass -Python with a Python 3.13 executable.'
}

$Configuration = Get-CspConfiguration -ProjectRoot $ProjectRoot
if ($Configuration.IsTrackedTemplate) {
    throw 'config\config.json is a fail-closed reference template. Run scripts\configure.ps1 before installation.'
}
$AclTargets = [string[]](@(
    @($ProjectRoot) + @($Configuration.ExternalConfigRoots) + @($Configuration.AssetRoots) |
        Sort-Object -Unique
))
$AncestorIssues = @(
    Get-CspInsecureAncestors -LiteralPaths $AclTargets |
        Sort-Object Path, Reason, Sid -Unique
)
foreach ($Issue in $AncestorIssues) {
    Write-Warning "Untrusted ancestor remains: $($Issue.Path) [$($Issue.Reason) $($Issue.Sid) $($Issue.Rights)]"
}
if ($AncestorIssues.Count -gt 0 -and -not $AcceptInsecureAncestorRisk) {
    throw 'Installation refused below an untrusted ancestor. Review the report or rerun with -AcceptInsecureAncestorRisk.'
}

if (-not (Test-Path -LiteralPath $Configuration.CspExecutable -PathType Leaf)) {
    throw (
        "Configured CSP executable does not exist: $($Configuration.CspExecutable). " +
        'Configure config\config.local.json or CSP_MCP_CONFIG before installation.'
    )
}
foreach ($ShortcutFile in $Configuration.ShortcutProfileFiles) {
    if (-not (Test-Path -LiteralPath $ShortcutFile -PathType Leaf)) {
        throw (
            "Configured shortcut profile does not exist: $ShortcutFile. " +
            'Configure the production profile before installation.'
        )
    }
}

foreach ($Path in @($Configuration.AssetRoots) + @((Join-Path $ProjectRoot 'logs'))) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

# If an untrusted ancestor exists, every audited root must already have a
# protected ACL. This audit never changes ACLs automatically.
Assert-CspRestrictedAcl -LiteralPaths $AclTargets

$PythonSelection = Resolve-CspPython313 -RequestedPython $Python
if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    $VenvArguments = @($PythonSelection.PrefixArguments) + @(
        '-m',
        'venv',
        (Join-Path $ProjectRoot '.venv')
    )
    & $PythonSelection.Command @VenvArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Python 3.13 virtual-environment creation failed.'
    }
}

$VenvVersion = & $VenvPython -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
if ($LASTEXITCODE -ne 0 -or ([string]$VenvVersion).Trim() -ne '3.13') {
    throw 'The existing project virtual environment is not based on Python 3.13.'
}

& $VenvPython -m pip install `
    --disable-pip-version-check `
    --require-hashes `
    --requirement (Join-Path $ProjectRoot 'requirements.lock.txt')
if ($LASTEXITCODE -ne 0) {
    throw 'Hash-verified dependency installation failed.'
}
& $VenvPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw 'pip check failed.'
}

$PreviousConfigEnvironment = $env:CSP_MCP_CONFIG
try {
    $env:CSP_MCP_CONFIG = $Configuration.ConfigPath
    Push-Location -LiteralPath $ProjectRoot
    try {
        & $VenvPython -X utf8 -c 'from csp_mcp.config import load_settings; load_settings()'
        if ($LASTEXITCODE -ne 0) {
            throw 'The configured production profile failed runtime validation.'
        }
    } finally {
        Pop-Location
    }
} finally {
    if ($null -eq $PreviousConfigEnvironment) {
        Remove-Item Env:CSP_MCP_CONFIG -ErrorAction SilentlyContinue
    } else {
        $env:CSP_MCP_CONFIG = $PreviousConfigEnvironment
    }
}

Assert-CspRestrictedAcl -LiteralPaths $AclTargets

Write-Host "Installed: $ProjectRoot"
Write-Host "Runtime:   $VenvPython"
Write-Host "Profile:   $($Configuration.ConfigPath)"

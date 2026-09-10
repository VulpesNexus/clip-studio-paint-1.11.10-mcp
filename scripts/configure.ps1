[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CspExecutable,

    [string[]]$ShortcutProfileFiles,

    [string]$AssetsRoot,

    # '*' allows any Windows culture. Dialog language is checked separately.
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedLocale = '*',

    # Selects one of the validated profiles below; any other build is rejected.
    [ValidateSet('5.1.2.0', '1.11.10.0')]
    [string]$ExpectedVersion = '5.1.2.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One entry per validated CSP build.  commands.json and auto_actions.json declare
# the profile ids they are valid for, and Dpi is the effective CSP window DPI the
# profile was validated at.  CSP 1.x keeps user settings under Documents\CELSYS;
# later builds keep them under %APPDATA%\CELSYSUserData.
$KnownProfiles = @{
    '5.1.2.0' = @{ ProfileId = 'csp-5.1.2-zh-CN-dpi120-v1'; Dpi = 120; SettingsRoot = 'AppData' }
    '1.11.10.0' = @{ ProfileId = 'csp-1.11.10-dpi96-v1'; Dpi = 96; SettingsRoot = 'Documents' }
}
# Not $Profile: PowerShell variables are case-insensitive and $PROFILE is automatic.
$SelectedProfile = $KnownProfiles[$ExpectedVersion]
$ExpectedPublisher = 'CELSYS'
$ExpectedDpi = $SelectedProfile.Dpi
$ProjectRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$ConfigDirectory = Join-Path $ProjectRoot 'config'
$OutputPath = Join-Path $ConfigDirectory 'config.local.json'
$TemporaryPath = $null
$BackupPath = $null
$Mutex = $null
$MutexOwned = $false

function Get-NormalizedAbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($LiteralPath) -or $LiteralPath.IndexOf([char]0) -ge 0) {
        throw "$Label must be a non-empty path without NUL bytes."
    }
    if (-not [System.IO.Path]::IsPathRooted($LiteralPath)) {
        throw "$Label must be an absolute path."
    }
    return [System.IO.Path]::GetFullPath($LiteralPath)
}

function Assert-NoReparseAncestor {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $Cursor = $LiteralPath
    while (-not (Test-Path -LiteralPath $Cursor)) {
        $Parent = [System.IO.Directory]::GetParent($Cursor)
        if ($null -eq $Parent) {
            throw "$Label has no existing filesystem ancestor: $LiteralPath"
        }
        $Cursor = $Parent.FullName
    }

    while ($null -ne $Cursor) {
        $Item = Get-Item -LiteralPath $Cursor -Force
        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label traverses a reparse point, which is not accepted for a path allowlist: $($Item.FullName)"
        }
        if ($Item -is [System.IO.DirectoryInfo]) {
            $Parent = $Item.Parent
        } else {
            $Parent = $Item.Directory
        }
        if ($null -eq $Parent) {
            break
        }
        $Cursor = $Parent.FullName
    }
}

function Resolve-TrustedLeaf {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $FullPath = Get-NormalizedAbsolutePath -LiteralPath $LiteralPath -Label $Label
    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "$Label does not exist or is not a file: $FullPath"
    }
    Assert-NoReparseAncestor -LiteralPath $FullPath -Label $Label
    $Item = Get-Item -LiteralPath $FullPath -Force
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a symbolic link or another reparse point: $FullPath"
    }
    return $Item.FullName
}

function Test-PathNestedOrEqual {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate,

        [Parameter(Mandatory = $true)]
        [string]$Parent
    )

    $Separator = [System.IO.Path]::DirectorySeparatorChar
    $NormalizedCandidate = $Candidate.TrimEnd($Separator)
    $NormalizedParent = $Parent.TrimEnd($Separator)
    if ($NormalizedCandidate.Equals($NormalizedParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $NormalizedCandidate.StartsWith(
        $NormalizedParent + $Separator,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

try {
    if (-not $PSBoundParameters.ContainsKey('ShortcutProfileFiles')) {
        if ($SelectedProfile.SettingsRoot -eq 'Documents') {
            $SettingsDocuments = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
            if ([string]::IsNullOrWhiteSpace($SettingsDocuments)) {
                throw 'The Documents folder is unavailable; pass -ShortcutProfileFiles explicitly.'
            }
            $ShortcutDirectory = Join-Path $SettingsDocuments 'CELSYS\CLIPStudioPaintVer1_5_0\Shortcut'
        } else {
            if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
                throw 'APPDATA is unavailable; pass -ShortcutProfileFiles explicitly.'
            }
            $ShortcutDirectory = Join-Path $env:APPDATA 'CELSYSUserData\CELSYS\CLIPStudioPaintVer1_5_0\Shortcut'
        }
        $ShortcutProfileFiles = @(
            (Join-Path $ShortcutDirectory 'default.khc'),
            (Join-Path $ShortcutDirectory 'DefaultToolModifyKey.tomd')
        )
    }
    if ($null -eq $ShortcutProfileFiles -or $ShortcutProfileFiles.Count -eq 0) {
        throw 'At least one shortcut profile file is required.'
    }

    if (-not $PSBoundParameters.ContainsKey('AssetsRoot')) {
        $Documents = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
        if ([string]::IsNullOrWhiteSpace($Documents)) {
            if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
                throw 'The Documents folder is unavailable; pass -AssetsRoot explicitly.'
            }
            $Documents = Join-Path $env:USERPROFILE 'Documents'
        }
        $AssetsRoot = Join-Path $Documents 'CSP-MCP-Assets'
    }

    $ResolvedExecutable = Resolve-TrustedLeaf -LiteralPath $CspExecutable -Label 'CSP executable'
    $ExecutableItem = Get-Item -LiteralPath $ResolvedExecutable -Force
    $FileVersion = ([string]$ExecutableItem.VersionInfo.FileVersion).Trim()
    if ($FileVersion -ne $ExpectedVersion) {
        throw "Unsupported CSP file version $FileVersion; this profile requires $ExpectedVersion."
    }
    $CompanyName = [string]$ExecutableItem.VersionInfo.CompanyName
    if ($CompanyName.IndexOf($ExpectedPublisher, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "The executable CompanyName is not CELSYS: $CompanyName"
    }

    $Signature = Get-AuthenticodeSignature -LiteralPath $ResolvedExecutable
    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "The CSP Authenticode signature is not valid: $($Signature.Status)"
    }
    if ($null -eq $Signature.SignerCertificate) {
        throw 'The CSP signature has no signer certificate.'
    }
    $SignerSubject = [string]$Signature.SignerCertificate.Subject
    if ($SignerSubject.IndexOf($ExpectedPublisher, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "The valid signature is not issued to CELSYS: $SignerSubject"
    }
    $ExecutableHash = (Get-FileHash -LiteralPath $ResolvedExecutable -Algorithm SHA256).Hash.ToUpperInvariant()

    $SeenShortcutPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $ShortcutEntries = @()
    foreach ($ShortcutPath in $ShortcutProfileFiles) {
        $ResolvedShortcut = Resolve-TrustedLeaf -LiteralPath $ShortcutPath -Label 'Shortcut profile file'
        if (-not $SeenShortcutPaths.Add($ResolvedShortcut)) {
            throw "Duplicate shortcut profile file: $ResolvedShortcut"
        }
        $ShortcutEntries += [ordered]@{
            path = $ResolvedShortcut
            sha256 = (Get-FileHash -LiteralPath $ResolvedShortcut -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    }

    $ResolvedAssetsRoot = Get-NormalizedAbsolutePath -LiteralPath $AssetsRoot -Label 'Assets root'
    $VolumeRoot = [System.IO.Path]::GetPathRoot($ResolvedAssetsRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    if ($ResolvedAssetsRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar).Equals(
        $VolumeRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'AssetsRoot must not be a volume root.'
    }
    if ((Test-PathNestedOrEqual -Candidate $ResolvedAssetsRoot -Parent $ProjectRoot) -or
        (Test-PathNestedOrEqual -Candidate $ProjectRoot -Parent $ResolvedAssetsRoot)) {
        throw 'AssetsRoot and the source repository must not contain one another.'
    }
    Assert-NoReparseAncestor -LiteralPath $ResolvedAssetsRoot -Label 'Assets root'

    $RootSpecifications = @(
        [ordered]@{ id = 'input'; path = (Join-Path $ResolvedAssetsRoot 'Input'); read = $true; write = $false },
        [ordered]@{ id = 'working'; path = (Join-Path $ResolvedAssetsRoot 'Working'); read = $true; write = $true },
        [ordered]@{ id = 'exports'; path = (Join-Path $ResolvedAssetsRoot 'Exports'); read = $true; write = $true }
    )
    [System.IO.Directory]::CreateDirectory($ResolvedAssetsRoot) | Out-Null
    foreach ($RootSpecification in $RootSpecifications) {
        [System.IO.Directory]::CreateDirectory([string]$RootSpecification.path) | Out-Null
        Assert-NoReparseAncestor -LiteralPath ([string]$RootSpecification.path) -Label "Asset root '$($RootSpecification.id)'"
    }

    $AcceptanceFixtureSource = Resolve-TrustedLeaf `
        -LiteralPath (Join-Path $ProjectRoot 'tests\fixtures\mcp-dialog-smoke.svg') `
        -Label 'Interactive acceptance fixture'
    $AcceptanceFixtureTarget = Join-Path ([string]$RootSpecifications[0].path) 'mcp-dialog-smoke.svg'
    if (Test-Path -LiteralPath $AcceptanceFixtureTarget) {
        if (-not (Test-Path -LiteralPath $AcceptanceFixtureTarget -PathType Leaf)) {
            throw "Interactive acceptance fixture target is not a file: $AcceptanceFixtureTarget"
        }
        Assert-NoReparseAncestor -LiteralPath $AcceptanceFixtureTarget -Label 'Interactive acceptance fixture target'
    } else {
        Copy-Item -LiteralPath $AcceptanceFixtureSource -Destination $AcceptanceFixtureTarget
        Assert-NoReparseAncestor -LiteralPath $AcceptanceFixtureTarget -Label 'Interactive acceptance fixture target'
    }

    $Configuration = [ordered]@{
        schema_version = 1
        profile_id = $SelectedProfile.ProfileId
        csp_executable = $ResolvedExecutable
        expected_company_contains = $ExpectedPublisher
        allowed_file_versions = @($ExpectedVersion)
        allowed_sha256 = @($ExecutableHash)
        expected_dpi = $ExpectedDpi
        expected_locale = $ExpectedLocale
        strict_profile_for_input = $true
        shortcut_profile_files = @($ShortcutEntries)
        quiet_period_ms = 2000
        quiet_wait_timeout_ms = 8000
        capture_ttl_seconds = 30
        confirmation_ttl_seconds = 45
        max_capture_width = 1600
        max_text_chars = 4096
        max_macro_steps = 12
        max_drag_seconds = 5.0
        path_roots = @($RootSpecifications)
        input_extensions = @(
            '.clip', '.lip', '.cmc', '.psd', '.psb', '.png', '.jpg', '.jpeg',
            '.webp', '.tif', '.tiff', '.bmp', '.tga', '.svg'
        )
        output_extensions = @(
            '.clip', '.psd', '.psb', '.png', '.jpg', '.jpeg', '.webp', '.tif',
            '.tiff', '.bmp', '.tga'
        )
    }

    Assert-NoReparseAncestor -LiteralPath $ConfigDirectory -Label 'Configuration directory'
    $Mutex = [System.Threading.Mutex]::new($false, 'Local\CspMcpConfigureV1')
    try {
        $MutexOwned = $Mutex.WaitOne([System.TimeSpan]::FromSeconds(30))
    } catch [System.Threading.AbandonedMutexException] {
        $MutexOwned = $true
    }
    if (-not $MutexOwned) {
        throw 'Timed out waiting for another configure process to finish.'
    }

    $TemporaryPath = Join-Path $ConfigDirectory ('.config.local.' + [System.Guid]::NewGuid().ToString('N') + '.tmp')
    $Json = ($Configuration | ConvertTo-Json -Depth 8) + [System.Environment]::NewLine
    $Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($TemporaryPath, $Json, $Utf8NoBom)
    $null = Get-Content -LiteralPath $TemporaryPath -Raw -Encoding UTF8 | ConvertFrom-Json

    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
        $BackupPath = Join-Path $ConfigDirectory ('.config.local.' + [System.Guid]::NewGuid().ToString('N') + '.bak')
        [System.IO.File]::Replace($TemporaryPath, $OutputPath, $BackupPath, $true)
    } elseif (Test-Path -LiteralPath $OutputPath) {
        throw "Configuration target exists but is not a file: $OutputPath"
    } else {
        [System.IO.File]::Move($TemporaryPath, $OutputPath)
    }
    $TemporaryPath = $null
    if ($null -ne $BackupPath -and (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        Remove-Item -LiteralPath $BackupPath -Force
    }
    $BackupPath = $null

    $null = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "Configured CSP MCP: $OutputPath"
    Write-Host "CSP version:        $FileVersion"
    Write-Host "CSP SHA-256:        $ExecutableHash"
    Write-Host "Shortcut files:     $($ShortcutEntries.Count)"
    Write-Host "Asset root:         $ResolvedAssetsRoot"
    Write-Host "Acceptance fixture: $AcceptanceFixtureTarget"
} finally {
    if ($null -ne $TemporaryPath -and (Test-Path -LiteralPath $TemporaryPath -PathType Leaf)) {
        Remove-Item -LiteralPath $TemporaryPath -Force
    }
    if ($null -ne $BackupPath -and (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        Remove-Item -LiteralPath $BackupPath -Force
    }
    if ($MutexOwned -and $null -ne $Mutex) {
        $Mutex.ReleaseMutex()
    }
    if ($null -ne $Mutex) {
        $Mutex.Dispose()
    }
}

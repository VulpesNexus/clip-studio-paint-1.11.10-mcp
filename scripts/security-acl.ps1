[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Resolve-CspSafeLocalPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [string]$RelativeTo,

        [switch]$AllowRelative
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -ne $Value.Trim()) {
        throw "$FieldName must be a non-empty path without leading or trailing whitespace."
    }
    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Value)) {
        throw "$FieldName must not contain wildcard characters."
    }

    $TokenPattern = '%(?<name>[A-Za-z_][A-Za-z0-9_]*)%'
    foreach ($Match in [System.Text.RegularExpressions.Regex]::Matches($Value, $TokenPattern)) {
        $VariableName = $Match.Groups['name'].Value
        $VariableValue = [System.Environment]::GetEnvironmentVariable($VariableName)
        if ([string]::IsNullOrEmpty($VariableValue)) {
            throw "$FieldName references an undefined or empty environment variable: %$VariableName%"
        }
        if ($VariableValue.Contains('%')) {
            throw "$FieldName references an environment variable with a nested or malformed token: %$VariableName%"
        }
    }
    $NonTokens = [System.Text.RegularExpressions.Regex]::Replace($Value, $TokenPattern, '')
    if ($NonTokens.Contains('%')) {
        throw "$FieldName contains an invalid environment-variable token. Only %NAME% is supported."
    }

    $Expanded = [System.Environment]::ExpandEnvironmentVariables($Value)
    if ($Expanded.Contains('%')) {
        throw "$FieldName contains an unresolved environment-variable token."
    }
    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Expanded)) {
        throw "$FieldName expands to a path containing wildcard characters."
    }
    if ($Expanded.StartsWith('\\', [System.StringComparison]::Ordinal)) {
        throw "$FieldName must be a local path; UNC and device paths are not allowed."
    }
    if (-not [System.IO.Path]::IsPathRooted($Expanded)) {
        if (-not $AllowRelative -or [string]::IsNullOrWhiteSpace($RelativeTo)) {
            throw "$FieldName must resolve to an absolute local path."
        }
        $Expanded = [System.IO.Path]::Combine($RelativeTo, $Expanded)
    }

    try {
        $FullPath = [System.IO.Path]::GetFullPath($Expanded)
    } catch {
        throw "$FieldName is not a valid local path: $($_.Exception.Message)"
    }
    if ($FullPath -notmatch '^[A-Za-z]:\\') {
        throw "$FieldName must resolve to an absolute local drive path."
    }
    if ($FullPath.Substring(2).Contains(':')) {
        throw "$FieldName must not contain an alternate data stream."
    }
    if ($FullPath.Length -gt 3) {
        $FullPath = $FullPath.TrimEnd('\')
    }
    return $FullPath
}

# Path-root policy, mirrored from csp_mcp/config.py (PATH_ROOT_WRITE_POLICY and
# ALLOWED_PATH_ROOT_SETS), which is authoritative; tests/test_config.py fails if
# the two drift apart. Every root must be readable; write must equal this table.
# config.py alone also pins where the CST copy roots may live.
$CspPathRootWritePolicy = [ordered]@{
    'input' = $false
    'working' = $true
    'exports' = $true
    'cst_copy' = $true
    'cst_ascii_copy' = $true
}
$CspAllowedPathRootSets = @(
    'input,working,exports',
    'input,working,exports,cst_copy',
    'input,working,exports,cst_copy,cst_ascii_copy'
)

function Get-CspPathRootMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$PathRoots
    )

    $RootMap = [ordered]@{}
    foreach ($Entry in @($PathRoots)) {
        if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) {
            throw 'Every path_roots entry must be a JSON object.'
        }
        $RootId = [string]$Entry.id
        if (-not $CspPathRootWritePolicy.Contains($RootId) -or $RootMap.Contains($RootId)) {
            throw "path_roots contains an unknown or duplicate id: $RootId"
        }
        if ($Entry.read -isnot [bool] -or -not $Entry.read) {
            throw "The $RootId path root must have read=true."
        }
        $ExpectedWrite = $CspPathRootWritePolicy[$RootId]
        if ($Entry.write -isnot [bool] -or $Entry.write -ne $ExpectedWrite) {
            throw "The $RootId path root has an invalid write policy."
        }
        $RootMap[$RootId] = Resolve-CspSafeLocalPath `
            -Value ([string]$Entry.path) `
            -FieldName "path_roots[$RootId].path"
    }
    $ConfiguredSet = (@($CspPathRootWritePolicy.Keys | Where-Object { $RootMap.Contains($_) })) -join ','
    if ($CspAllowedPathRootSets -notcontains $ConfiguredSet) {
        throw (
            'path_roots must define input, working, and exports exactly once; ' +
            'cst_copy may be added, and cst_ascii_copy only together with cst_copy.'
        )
    }

    $NormalizedRoots = @($RootMap.Values)
    for ($LeftIndex = 0; $LeftIndex -lt $NormalizedRoots.Count; $LeftIndex++) {
        for ($RightIndex = $LeftIndex + 1; $RightIndex -lt $NormalizedRoots.Count; $RightIndex++) {
            $Left = $NormalizedRoots[$LeftIndex]
            $Right = $NormalizedRoots[$RightIndex]
            $LeftPrefix = $Left.TrimEnd('\') + '\'
            $RightPrefix = $Right.TrimEnd('\') + '\'
            if (
                [string]::Equals($Left, $Right, [System.StringComparison]::OrdinalIgnoreCase) -or
                $Left.StartsWith($RightPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
                $Right.StartsWith($LeftPrefix, [System.StringComparison]::OrdinalIgnoreCase)
            ) {
                throw 'Configured asset roots must not duplicate or contain one another.'
            }
        }
    }
    return $RootMap
}

function Get-CspConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectRoot
    )

    $ResolvedProjectRoot = Resolve-CspSafeLocalPath `
        -Value $ProjectRoot `
        -FieldName 'project root'

    if (-not [string]::IsNullOrWhiteSpace($env:CSP_MCP_CONFIG)) {
        $ConfigPath = Resolve-CspSafeLocalPath `
            -Value $env:CSP_MCP_CONFIG `
            -FieldName 'CSP_MCP_CONFIG' `
            -RelativeTo $ResolvedProjectRoot `
            -AllowRelative
    } else {
        $LocalConfigPath = Join-Path $ResolvedProjectRoot 'config\config.local.json'
        if (Test-Path -LiteralPath $LocalConfigPath -PathType Leaf) {
            $ConfigPath = [System.IO.Path]::GetFullPath($LocalConfigPath)
        } else {
            $ConfigPath = [System.IO.Path]::GetFullPath(
                (Join-Path $ResolvedProjectRoot 'config\config.json')
            )
        }
    }

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw (
            "No configured CSP profile exists at $ConfigPath. " +
            'Create config\config.local.json or set CSP_MCP_CONFIG before running this script.'
        )
    }
    $ConfigItem = Get-Item -LiteralPath $ConfigPath -Force
    if (($ConfigItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The selected CSP configuration must not be a reparse point: $ConfigPath"
    }

    try {
        $Raw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Cannot parse CSP configuration $ConfigPath`: $($_.Exception.Message)"
    }
    if ($null -eq $Raw -or $Raw -isnot [pscustomobject]) {
        throw 'The CSP configuration must be a JSON object.'
    }
    if ($Raw.schema_version -ne 1) {
        throw 'The CSP configuration must use schema_version 1.'
    }

    $CspExecutable = Resolve-CspSafeLocalPath `
        -Value ([string]$Raw.csp_executable) `
        -FieldName 'csp_executable'

    $ShortcutFiles = @()
    foreach ($Entry in @($Raw.shortcut_profile_files)) {
        if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) {
            throw 'Every shortcut_profile_files entry must be a JSON object.'
        }
        $ShortcutFiles += Resolve-CspSafeLocalPath `
            -Value ([string]$Entry.path) `
            -FieldName 'shortcut_profile_files.path'
    }
    if ($ShortcutFiles.Count -eq 0) {
        throw 'shortcut_profile_files must contain at least one configured file.'
    }

    $RootMap = Get-CspPathRootMap -PathRoots $Raw.path_roots

    $TrackedConfigPath = [System.IO.Path]::GetFullPath(
        (Join-Path $ResolvedProjectRoot 'config\config.json')
    )
    $ProjectPrefix = $ResolvedProjectRoot.TrimEnd('\') + '\'
    $ExternalConfigRoots = @()
    if (-not $ConfigPath.StartsWith($ProjectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $ExternalConfigRoots = @([System.IO.Path]::GetDirectoryName($ConfigPath))
    }
    return [pscustomobject]@{
        ConfigPath = $ConfigPath
        IsTrackedTemplate = [string]::Equals(
            $ConfigPath,
            $TrackedConfigPath,
            [System.StringComparison]::OrdinalIgnoreCase
        )
        ExternalConfigRoots = [string[]]$ExternalConfigRoots
        Raw = $Raw
        CspExecutable = $CspExecutable
        ShortcutProfileFiles = [string[]]$ShortcutFiles
        InputRoot = $RootMap['input']
        WorkingRoot = $RootMap['working']
        ExportsRoot = $RootMap['exports']
        CstCopyRoot = $RootMap['cst_copy']
        CstAsciiCopyRoot = $RootMap['cst_ascii_copy']
        # Every configured root, CST copies included: the server writes into all
        # of them except input, so each gets the same ACL audit.
        AssetRoots = [string[]]@($RootMap.Values)
    }
}

function Get-CspSidValue {
    param([Parameter(Mandatory = $true)]$IdentityReference)
    try {
        return $IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        return $IdentityReference.Value
    }
}

function Get-CspAclContext {
    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if (-not $CurrentSid) {
        throw 'Cannot resolve the current Windows user SID.'
    }
    $DangerousRights =
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $AncestorReplacementRights =
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $AllowedSids = @($CurrentSid, 'S-1-5-18', 'S-1-5-32-544')
    $TrustedOwnerSids = [System.Collections.Generic.List[string]]::new()
    foreach ($Sid in $AllowedSids) {
        $TrustedOwnerSids.Add($Sid)
    }
    try {
        $TrustedInstallerSid = ([System.Security.Principal.NTAccount]'NT SERVICE\TrustedInstaller').Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        if (-not $TrustedOwnerSids.Contains($TrustedInstallerSid)) {
            $TrustedOwnerSids.Add($TrustedInstallerSid)
        }
    } catch {
        # TrustedInstaller is absent on some stripped-down Windows images.
    }
    return @{
        CurrentSid = $CurrentSid
        AllowedSids = $AllowedSids
        TrustedOwnerSids = [string[]]$TrustedOwnerSids
        DangerousRights = $DangerousRights
        AncestorReplacementRights = $AncestorReplacementRights
    }
}

function Get-CspInsecureAncestors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LiteralPaths
    )

    $Context = Get-CspAclContext
    foreach ($LiteralPath in $LiteralPaths) {
        $FullPath = Resolve-CspSafeLocalPath -Value $LiteralPath -FieldName 'ACL audit path'
        $Current = [System.IO.Directory]::GetParent($FullPath)
        while ($null -ne $Current -and -not (Test-Path -LiteralPath $Current.FullName)) {
            $Current = $Current.Parent
        }
        while ($null -ne $Current) {
            $Item = Get-Item -LiteralPath $Current.FullName -Force
            if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                [pscustomobject]@{ Path = $Item.FullName; Reason = 'reparsePoint'; Sid = ''; Rights = '' }
            }
            $Acl = Get-Acl -LiteralPath $Item.FullName
            $OwnerSid = try {
                ([System.Security.Principal.NTAccount]$Acl.Owner).Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            } catch { $Acl.Owner }
            if ($Context.TrustedOwnerSids -notcontains $OwnerSid) {
                [pscustomobject]@{ Path = $Item.FullName; Reason = 'untrustedOwner'; Sid = $OwnerSid; Rights = '' }
            }
            foreach ($Rule in $Acl.Access) {
                $Sid = Get-CspSidValue $Rule.IdentityReference
                if (
                    $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    ($Rule.FileSystemRights -band $Context.AncestorReplacementRights) -ne 0 -and
                    $Context.AllowedSids -notcontains $Sid
                ) {
                    [pscustomobject]@{
                        Path = $Item.FullName
                        Reason = 'untrustedDangerousAllow'
                        Sid = $Sid
                        Rights = [string]$Rule.FileSystemRights
                    }
                }
            }
            $Current = $Current.Parent
        }
    }
}

function Set-CspRestrictedAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LiteralPaths
    )

    [void]$LiteralPaths
    throw (
        'Automatic recursive ACL mutation is intentionally disabled. ' +
        'It cannot be made transaction-safe beneath a replaceable parent. ' +
        'Use Get-CspInsecureAncestors and have an administrator harden the volume/parents explicitly.'
    )
}

function Assert-CspRestrictedAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$LiteralPaths
    )

    $Context = Get-CspAclContext
    foreach ($LiteralPath in $LiteralPaths) {
        if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
            throw "Audited directory does not exist: $LiteralPath"
        }
        $Resolved = (Resolve-Path -LiteralPath $LiteralPath).Path
        $RootHasUntrustedAncestor = @(
            Get-CspInsecureAncestors -LiteralPaths @($Resolved)
        ).Count -gt 0
        $Items = @((Get-Item -LiteralPath $Resolved -Force)) + @(
            Get-ChildItem -LiteralPath $Resolved -Force -Recurse
        )
        $Reparse = $Items | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        } | Select-Object -First 1
        if ($Reparse) {
            throw "Reparse point exists inside audited tree: $($Reparse.FullName)"
        }
        foreach ($Item in $Items) {
            $Acl = Get-Acl -LiteralPath $Item.FullName
            $OwnerSid = try {
                ([System.Security.Principal.NTAccount]$Acl.Owner).Translate(
                    [System.Security.Principal.SecurityIdentifier]
                ).Value
            } catch { $Acl.Owner }
            if ($Context.TrustedOwnerSids -notcontains $OwnerSid) {
                throw "Untrusted ACL owner on $($Item.FullName): $OwnerSid"
            }
            $FullControlSids = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($Rule in $Acl.Access) {
                $Sid = Get-CspSidValue $Rule.IdentityReference
                $AppliesToObject =
                    ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
                if (
                    $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    $AppliesToObject -and
                    ($Rule.FileSystemRights -band $Context.DangerousRights) -ne 0 -and
                    $Context.AllowedSids -notcontains $Sid
                ) {
                    throw "Untrusted dangerous ACL remains on $($Item.FullName) for ${Sid}: $($Rule.FileSystemRights)"
                }
                if (
                    $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    $AppliesToObject -and
                    ($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                        [System.Security.AccessControl.FileSystemRights]::FullControl
                ) {
                    [void]$FullControlSids.Add($Sid)
                }
                if (
                    $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                    $AppliesToObject -and
                    ($Rule.FileSystemRights -band $Context.DangerousRights) -ne 0 -and
                    $Context.AllowedSids -contains $Sid
                ) {
                    throw "Dangerous deny ACL affects a required principal on $($Item.FullName) for ${Sid}: $($Rule.FileSystemRights)"
                }
            }
            foreach ($RequiredSid in $Context.AllowedSids) {
                if (-not $FullControlSids.Contains($RequiredSid)) {
                    throw "Required FullControl ACL is missing on $($Item.FullName) for $RequiredSid"
                }
            }
            if (
                $RootHasUntrustedAncestor -and
                [string]::Equals(
                    $Item.FullName.TrimEnd('\'),
                    $Resolved.TrimEnd('\'),
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -and
                -not $Acl.AreAccessRulesProtected
            ) {
                throw "Audited root must protect its ACL because an untrusted ancestor exists: $Resolved"
            }
        }
    }
}

function Assert-CspRestrictedFileLocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $Context = Get-CspAclContext
    $FullPath = Resolve-CspSafeLocalPath -Value $LiteralPath -FieldName 'sensitive file path'
    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        throw "Sensitive file does not exist: $FullPath"
    }
    $ParentPath = [System.IO.Path]::GetDirectoryName($FullPath)
    if (-not (Test-Path -LiteralPath $ParentPath -PathType Container)) {
        throw "Sensitive file parent does not exist: $ParentPath"
    }

    $Cursor = Get-Item -LiteralPath $ParentPath -Force
    while ($null -ne $Cursor) {
        if (($Cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Sensitive file path traverses a reparse point: $($Cursor.FullName)"
        }
        $Cursor = $Cursor.Parent
    }

    $ParentHasUntrustedAncestor = @(
        Get-CspInsecureAncestors -LiteralPaths @($ParentPath)
    ).Count -gt 0
    $Items = @(
        (Get-Item -LiteralPath $ParentPath -Force),
        (Get-Item -LiteralPath $FullPath -Force)
    )
    foreach ($Item in $Items) {
        if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Sensitive file location contains a reparse point: $($Item.FullName)"
        }
        $Acl = Get-Acl -LiteralPath $Item.FullName
        $OwnerSid = try {
            ([System.Security.Principal.NTAccount]$Acl.Owner).Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        } catch { $Acl.Owner }
        if ($Context.TrustedOwnerSids -notcontains $OwnerSid) {
            throw "Untrusted ACL owner on $($Item.FullName): $OwnerSid"
        }
        $FullControlSids = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($Rule in $Acl.Access) {
            $Sid = Get-CspSidValue $Rule.IdentityReference
            $AppliesToObject =
                ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
            if (
                $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $AppliesToObject -and
                ($Rule.FileSystemRights -band $Context.DangerousRights) -ne 0 -and
                $Context.AllowedSids -notcontains $Sid
            ) {
                throw "Untrusted dangerous ACL remains on $($Item.FullName) for ${Sid}: $($Rule.FileSystemRights)"
            }
            if (
                $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $AppliesToObject -and
                ($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                    [System.Security.AccessControl.FileSystemRights]::FullControl
            ) {
                [void]$FullControlSids.Add($Sid)
            }
            if (
                $Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
                $AppliesToObject -and
                ($Rule.FileSystemRights -band $Context.DangerousRights) -ne 0 -and
                $Context.AllowedSids -contains $Sid
            ) {
                throw "Dangerous deny ACL affects a required principal on $($Item.FullName) for ${Sid}: $($Rule.FileSystemRights)"
            }
        }
        foreach ($RequiredSid in $Context.AllowedSids) {
            if (-not $FullControlSids.Contains($RequiredSid)) {
                throw "Required FullControl ACL is missing on $($Item.FullName) for $RequiredSid"
            }
        }
        if (
            $ParentHasUntrustedAncestor -and
            [string]::Equals(
                $Item.FullName.TrimEnd('\'),
                $ParentPath.TrimEnd('\'),
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            -not $Acl.AreAccessRulesProtected
        ) {
            throw "Sensitive file parent must protect its ACL because an untrusted ancestor exists: $ParentPath"
        }
    }
}

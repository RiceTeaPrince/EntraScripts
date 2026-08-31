<#
.SYNOPSIS
    Creates a new Entra ID cloud administrator account (username.azr@tenant).

.DESCRIPTION
    Creates a single cloud-only admin account following the "username.azr" naming
    convention (see Admin Audit\Build-CloudAdminReview.ps1, which reads accounts
    back out by matching this same pattern). Idempotent - re-running with the same
    -BaseUsername/-TenantDomain checks for an existing account by UPN first and
    skips creation instead of erroring, so the script is safe to re-run after a
    partial failure or as part of a repeatable onboarding step.

    Generates a cryptographically random initial password if none is supplied,
    forces a password change at next sign-in, and leaves the account unlicensed
    (cloud admin accounts don't need a mailbox). Optionally assigns one Entra ID
    directory role directly (not PIM-eligible) if -RoleName is given, and/or adds
    the account to one or more static (assigned-membership) groups if -GroupNames
    is given.

    Role assignment and group membership are also checked/applied when the
    account already exists, not only on first creation - so re-running the
    script after a partial failure (e.g. account created but group membership
    never got applied) converges to the same end state instead of being a no-op.

    Supports -WhatIf/-Confirm and -Verbose for dry-run and step-by-step tracing.

.PARAMETER BaseUsername
    The account owner's base username, e.g. "jsmith". The admin UPN becomes
    "jsmith.azr@<TenantDomain>".

.PARAMETER DisplayName
    Display name for the account, e.g. "John Smith (Cloud Admin)".

.PARAMETER TenantDomain
    UPN domain to create the account in, e.g. "contoso.onmicrosoft.com". If
    omitted, the script uses the verified default domain of the connected tenant.

.PARAMETER Password
    Initial password as a SecureString. If omitted, a random 24-character
    password is generated and printed once - it is not recoverable afterward.

.PARAMETER NoForcePasswordChange
    Skip forcing a password change at next sign-in. Off by default; cloud admin
    accounts should normally require it.

.PARAMETER Disabled
    Create the account with sign-in blocked (AccountEnabled = $false). Useful
    when the account shouldn't be usable until role assignment / access review
    is complete.

.PARAMETER RoleName
    Display name of one built-in Entra ID directory role to assign directly to
    the new account, e.g. "Security Administrator". Optional - if omitted, no
    role is assigned and the account is created with no privilege.

.PARAMETER GroupNames
    Display name(s) or object ID(s) of one or more static (assigned-membership)
    groups to add the account to, in addition to $DefaultGroupNames (see the
    Config section near the top of the script). Dynamic-membership groups are
    skipped with a warning, since members can't be added to those manually.

.PARAMETER SkipDefaultGroups
    Don't add the account to the groups listed in $DefaultGroupNames - only
    -GroupNames (if any) are applied.

.PARAMETER Department
.PARAMETER JobTitle
    Optional metadata written to the account.

.EXAMPLE
    .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)"

.EXAMPLE
    .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" `
        -RoleName "Security Administrator" -Verbose

.EXAMPLE
    .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" `
        -GroupNames "Privileged Identity Management Admins", "Break-Glass Monitoring"

.EXAMPLE
    .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" -SkipDefaultGroups

.EXAMPLE
    .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" -WhatIf

.NOTES
    Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users
             (+ Microsoft.Graph.Identity.DirectoryManagement if -RoleName is used)
             (+ Microsoft.Graph.Groups if -GroupNames is used)

    Graph scopes:
        User.ReadWrite.All
        RoleManagement.ReadWrite.Directory   (only if -RoleName is used)
        GroupMember.ReadWrite.All            (only if -GroupNames is used)

    READ-WRITE. Creates a real account. Use -WhatIf first if unsure.
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

# ==============================================================================
# EXAMPLES
# ------------------------------------------------------------------------------
#   Basic account, no role, no extra groups:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)"
#
#   Assign a directory role on creation:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" `
#         -RoleName "Security Administrator" -Verbose
#
#   Add extra static groups, on top of $DefaultGroupNames below:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" `
#         -GroupNames "Privileged Identity Management Admins", "Break-Glass Monitoring"
#
#   Skip the hardcoded default groups entirely:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" -SkipDefaultGroups
#
#   Re-run against an account that already exists - converges role/group state
#   instead of erroring or duplicating:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" `
#         -RoleName "Security Administrator" -GroupNames "Break-Glass Monitoring"
#
#   Preview what would happen without making any changes:
#     .\New-CloudAdminAccount.ps1 -BaseUsername jsmith -DisplayName "John Smith (Cloud Admin)" -WhatIf
# ==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9._-]*$')]
    [string]$BaseUsername,

    [Parameter(Mandatory)]
    [string]$DisplayName,

    [string]$TenantDomain,

    [securestring]$Password,

    [switch]$NoForcePasswordChange,

    [switch]$Disabled,

    [string]$RoleName,

    [string[]]$GroupNames,

    [switch]$SkipDefaultGroups,

    [string]$Department,

    [string]$JobTitle
)

$ErrorActionPreference = 'Stop'

# ── Config: groups every cloud admin account should always join ─────────────
# Edit this list for your tenant. Merged with -GroupNames at runtime unless
# -SkipDefaultGroups is passed. Accepts display names or object IDs, same as
# -GroupNames.
$DefaultGroupNames = @(
    "00000000-0000-0000-0000-000000000000"   # <ObjectId> - or a display name instead, e.g. "<Group Display Name>"
    "11111111-1111-1111-1111-111111111111"   # <ObjectId> - or a display name instead, e.g. "<Group Display Name>"
)

# ── Helper: cryptographically random password ───────────────────────────────
function New-RandomPassword {
    param([int]$Length = 24)

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = 'abcdefghijkmnopqrstuvwxyz'
    $digits  = '23456789'
    $special = '!@#$%^&*-_=+'
    $all     = $upper + $lower + $digits + $special

    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)

    # Guarantee at least one char from each required class, fill the rest randomly.
    $chars = @(
        $upper[$bytes[0] % $upper.Length]
        $lower[$bytes[1] % $lower.Length]
        $digits[$bytes[2] % $digits.Length]
        $special[$bytes[3] % $special.Length]
    )
    for ($i = 4; $i -lt $Length; $i++) {
        $chars += $all[$bytes[$i] % $all.Length]
    }

    -join ($chars | Sort-Object { [guid]::NewGuid() })
}

# ── Helper: resolve a group by display name or object ID ────────────────────
function Resolve-CloudAdminGroup {
    param([Parameter(Mandatory)][string]$NameOrId)

    if ($NameOrId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $group = Get-MgGroup -GroupId $NameOrId -ErrorAction SilentlyContinue
    } else {
        $group = Get-MgGroup -Filter "displayName eq '$NameOrId'" -Property Id, DisplayName, GroupTypes -ErrorAction SilentlyContinue
    }

    if (-not $group) {
        Write-Warning "Group not found, skipping: $NameOrId"
        return $null
    }
    if (@($group).Count -gt 1) {
        Write-Warning "Group name '$NameOrId' is ambiguous ($(@($group).Count) matches) - use the object ID instead. Skipping."
        return $null
    }
    if ($group.GroupTypes -contains 'DynamicMembership') {
        Write-Warning "'$($group.DisplayName)' is a dynamic-membership group - members can't be added manually. Skipping."
        return $null
    }
    $group
}

# ── Connect ───────────────────────────────────────────────────────────────
$needsGroupScope = $GroupNames -or (-not $SkipDefaultGroups -and $DefaultGroupNames)
$scopes = @('User.ReadWrite.All')
if ($RoleName)         { $scopes += 'RoleManagement.ReadWrite.Directory' }
if ($needsGroupScope)  { $scopes += 'GroupMember.ReadWrite.All' }

if (-not (Get-MgContext)) {
    Write-Verbose "No active Graph session - connecting with scopes: $($scopes -join ', ')"
    Connect-MgGraph -Scopes $scopes | Out-Null
}
$ctx = Get-MgContext
Write-Verbose "Connected to tenant $($ctx.TenantId) as $($ctx.Account)"

if (-not $TenantDomain) {
    Write-Verbose "No -TenantDomain given, resolving default verified domain..."
    $TenantDomain = (Get-MgDomain | Where-Object { $_.IsDefault }).Id
    if (-not $TenantDomain) {
        Write-Error "Could not resolve a default domain for this tenant. Pass -TenantDomain explicitly."
        return
    }
    Write-Verbose "Resolved tenant domain: $TenantDomain"
}

$upn          = "$BaseUsername.azr@$TenantDomain"
$mailNickname = "$BaseUsername.azr"

Write-Host "Target account: $upn" -ForegroundColor Cyan

# ── Idempotency check ────────────────────────────────────────────────────
Write-Verbose "Checking whether $upn already exists..."
$existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

$targetUser        = $null
$accountCreated     = $false
$generatedPassword  = $null

if ($existing) {
    Write-Warning "Account already exists, skipping creation: $upn (Id: $($existing.Id))"
    $targetUser = $existing
} else {
    # ── Password ─────────────────────────────────────────────────────────
    if (-not $Password) {
        Write-Verbose "No -Password supplied, generating a random 24-character password."
        $generatedPassword = New-RandomPassword -Length 24
        $Password = ConvertTo-SecureString $generatedPassword -AsPlainText -Force
    }
    $plainPasswordForBody = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    )

    $userParams = @{
        AccountEnabled    = -not $Disabled.IsPresent
        DisplayName       = $DisplayName
        MailNickname      = $mailNickname
        UserPrincipalName = $upn
        UserType          = 'Member'
        PasswordProfile   = @{
            Password                             = $plainPasswordForBody
            ForceChangePasswordNextSignIn        = -not $NoForcePasswordChange.IsPresent
            ForceChangePasswordNextSignInWithMfa = $false
        }
    }
    if ($Department) { $userParams.Department = $Department }
    if ($JobTitle)   { $userParams.JobTitle   = $JobTitle }

    # ── Create ──────────────────────────────────────────────────────────
    if ($PSCmdlet.ShouldProcess($upn, "Create cloud admin account")) {
        Write-Verbose "Creating account $upn ..."
        try {
            $targetUser = New-MgUser @userParams
            $accountCreated = $true
            Write-Host "[+] Created: $upn (Id: $($targetUser.Id))" -ForegroundColor Green
        } catch {
            Write-Error "Failed to create $upn : $($_.Exception.Message)"
            return
        } finally {
            $plainPasswordForBody = $null
        }
    }
}

# ── Optional role assignment (applied whether the account is new or existing) ──
if ($targetUser -and $RoleName) {
    if ($PSCmdlet.ShouldProcess($upn, "Assign directory role '$RoleName'")) {
        Write-Verbose "Resolving directory role '$RoleName'..."
        try {
            $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'" -ErrorAction Stop
            if (-not $roleDef) {
                Write-Warning "Role '$RoleName' not found - no role assignment made."
            } else {
                $already = Get-MgRoleManagementDirectoryRoleAssignment `
                    -Filter "principalId eq '$($targetUser.Id)' and roleDefinitionId eq '$($roleDef.Id)'" `
                    -ErrorAction SilentlyContinue
                if ($already) {
                    Write-Verbose "Role '$RoleName' already assigned, skipping."
                } else {
                    $body = @{
                        '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
                        RoleDefinitionId = $roleDef.Id
                        PrincipalId      = $targetUser.Id
                        DirectoryScopeId = '/'
                    }
                    New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $body | Out-Null
                    Write-Host "[+] Assigned role: $RoleName" -ForegroundColor Green
                }
            }
        } catch {
            Write-Warning "Role assignment failed: $($_.Exception.Message)"
        }
    }
}

# ── Optional group membership (applied whether the account is new or existing) ──
$groupResults = @()
$effectiveGroupNames = @()
if (-not $SkipDefaultGroups) { $effectiveGroupNames += $DefaultGroupNames }
$effectiveGroupNames += $GroupNames
$effectiveGroupNames = $effectiveGroupNames | Where-Object { $_ } | Select-Object -Unique

if ($targetUser -and $effectiveGroupNames) {
    foreach ($name in $effectiveGroupNames) {
        $group = Resolve-CloudAdminGroup -NameOrId $name
        if (-not $group) { continue }

        if ($PSCmdlet.ShouldProcess($upn, "Add to group '$($group.DisplayName)'")) {
            try {
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $targetUser.Id -ErrorAction Stop
                Write-Host "[+] Added to group: $($group.DisplayName)" -ForegroundColor Green
                $groupResults += $group.DisplayName
            } catch {
                if ($_.Exception.Message -match 'already exist') {
                    Write-Verbose "Already a member of $($group.DisplayName), skipping."
                    $groupResults += $group.DisplayName
                } else {
                    Write-Warning "Failed to add to group '$($group.DisplayName)': $($_.Exception.Message)"
                }
            }
        }
    }
}

# ── Result ────────────────────────────────────────────────────────────────
if ($targetUser) {
    if ($generatedPassword) {
        Write-Host "`nGenerated password (shown once, store it now): $generatedPassword" -ForegroundColor Yellow
    }
    [pscustomobject]@{
        UserPrincipalName = $targetUser.UserPrincipalName
        Id                = $targetUser.Id
        DisplayName       = $targetUser.DisplayName
        AccountEnabled    = $targetUser.AccountEnabled
        RoleAssigned      = $RoleName
        Groups            = $groupResults
        Created           = $accountCreated
        GeneratedPassword = $generatedPassword
    }
}

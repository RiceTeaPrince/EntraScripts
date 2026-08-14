<#
.SYNOPSIS
    Populates the Graph import zone of all three identity tabs in the Entra ID
    Service Identity Inventory workbook.

.DESCRIPTION
    Produces three CSVs whose columns match the import zones exactly:

        Inventory-Accounts.csv            -> Accounts tab,            paste at A2 (columns A-R)
        Inventory-ServicePrincipals.csv   -> Service Principals tab,  paste at A2 (columns A-Q)
        Inventory-ManagedIdentities.csv   -> Managed Identities tab,  paste at A2 (columns A-H)

    READ-ONLY. Makes no changes to the tenant.

    Deliberately NOT collected, because a script cannot know them:
    exclusion justification, approver, expiry, compensating controls,
    business criticality, cost centre, confirmed owner.

.PARAMETER OutputFolder
    Folder for the CSVs. Defaults to the current directory.

.PARAMETER Identification
    Which USER accounts to include. Service principals and managed identities are
    non-human by definition and are always collected in full, so this affects the
    Accounts tab only.

      All       - every user account. Default. Widest, noisiest.
      Group     - members of the groups named in -SourceGroup. Most defensible.
      Naming    - accounts matching -NamePattern.
      Both      - union of Group and Naming. Recommended starting point.
      Heuristic - Both, plus accounts with non-interactive sign-in activity but no
                  interactive sign-in ever. Catches unlabelled service accounts;
                  flags them for review rather than asserting them.

    However you filter, the Account Category column records HOW each account
    qualified, so the list can be defended or challenged on its definition.

.PARAMETER SourceGroup
    One or more group display names or object IDs whose members are service accounts.
    Expanded transitively, so nested groups are included.

.PARAMETER NamePattern
    Regex matched against display name and UPN. Adjust to your naming convention.

.PARAMETER ExcludeMicrosoftFirstParty
    Drop Microsoft-owned service principals. These are usually several hundred rows
    of noise you neither own nor can meaningfully govern.

.PARAMETER ExcludeDisabled
    Drop disabled accounts and service principals. Off by default, because
    disabled-but-still-present is itself a finding.

.PARAMETER SkipSignInActivity
    Skip sign-in activity collection. Useful if you lack Entra ID P1, or want a fast run.

.PARAMETER MaxObjects
    Safety cap per object type. Default 5000.

.EXAMPLE
    # Everything - widest net
    .\Build-IdentityInventory.ps1 -OutputFolder .\inventory -Verbose

.EXAMPLE
    # Service accounts only, defined by a maintained group plus naming convention
    .\Build-IdentityInventory.ps1 -OutputFolder .\inventory `
        -Identification Both -SourceGroup 'SG-Service-Accounts' `
        -ExcludeMicrosoftFirstParty -Verbose

.EXAMPLE
    # Widest service-account net, including unlabelled candidates for review
    .\Build-IdentityInventory.ps1 -Identification Heuristic `
        -SourceGroup 'SG-Service-Accounts','SG-Batch-Accounts' -Verbose

.NOTES
    Install-Module Microsoft.Graph -Scope CurrentUser

    Scopes (all read-only):
        User.Read.All, Application.Read.All, Directory.Read.All,
        AuditLog.Read.All, RoleManagement.Read.Directory, Organization.Read.All

    Requires Entra ID P1 for user signInActivity and the authentication methods
    registration report. Service principal sign-in activity uses a BETA endpoint
    (/beta/reports/servicePrincipalSignInActivities) which Microsoft does not
    support for production use - treat that column as indicative.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = ".",

    # How to decide which USER accounts belong in the inventory.
    # Service principals and managed identities are non-human by definition and
    # are always included in full - this parameter affects the Accounts tab only.
    [ValidateSet('All','Group','Naming','Both','Heuristic')]
    [string]$Identification = 'All',

    [string[]]$SourceGroup,

    [string]$NamePattern = '^(svc|sa|srv|app|int|auto)[-_. ]|service.?account|automation|integration|daemon|batch|scheduler',

    [switch]$ExcludeMicrosoftFirstParty,
    [switch]$ExcludeDisabled,
    [switch]$SkipSignInActivity,
    [int]$MaxObjects = 5000,
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'
$Scopes = @('User.Read.All','Application.Read.All','Directory.Read.All','AuditLog.Read.All',
            'RoleManagement.Read.Directory','Organization.Read.All')

if (-not (Get-MgContext)) {
    if ($TenantId) { Connect-MgGraph -Scopes $Scopes -TenantId $TenantId | Out-Null }
    else           { Connect-MgGraph -Scopes $Scopes | Out-Null }
}
$ctx = Get-MgContext
$missing = $Scopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missing) { Write-Warning "Missing scopes: $($missing -join ', '). Some columns will be blank." }
Write-Host "Tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Cyan

if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }
function Out-Path([string]$n) { Join-Path $OutputFolder $n }
function D([object]$v) { if ($v) { ([datetime]$v).ToString('dd/MM/yyyy') } else { '' } }

# Microsoft's own tenants - anything owned by these is a first-party app
$MicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a','72f988bf-86f1-41af-91ab-2d7cd011db47')

# Application permissions worth flagging. Extend to taste.
$HighRiskPermissions = @(
    'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All','Group.ReadWrite.All','User.ReadWrite.All','GroupMember.ReadWrite.All',
    'Mail.ReadWrite','Mail.Send','MailboxSettings.ReadWrite','Files.ReadWrite.All','Sites.FullControl.All',
    'Policy.ReadWrite.ConditionalAccess','PrivilegedAccess.ReadWrite.AzureAD','UserAuthenticationMethod.ReadWrite.All',
    'Domain.ReadWrite.All','Device.ReadWrite.All','Chat.ReadWrite.All','Exchange.ManageAsApp'
)
$MediumRiskPermissions = @(
    'Directory.Read.All','User.Read.All','Group.Read.All','Application.Read.All','Mail.Read',
    'Files.Read.All','Sites.Read.All','AuditLog.Read.All','Policy.Read.All','Reports.Read.All'
)
function Get-PermissionRisk([string[]]$perms) {
    if (-not $perms -or $perms.Count -eq 0) { return 'None' }
    if ($perms | Where-Object { $_ -in $HighRiskPermissions })   { return 'High' }
    if ($perms | Where-Object { $_ -in $MediumRiskPermissions }) { return 'Medium' }
    return 'Low'
}

# --------------------------------------------------------------------------
# Shared lookups
# --------------------------------------------------------------------------
Write-Verbose "Building resource service principal map for permission resolution..."
$resourceSpCache = @{}
function Resolve-AppRole([string]$resourceSpId, [string]$appRoleId) {
    if (-not $resourceSpCache.ContainsKey($resourceSpId)) {
        try   { $resourceSpCache[$resourceSpId] = (Get-MgServicePrincipal -ServicePrincipalId $resourceSpId -Property Id,AppRoles).AppRoles }
        catch { $resourceSpCache[$resourceSpId] = @() }
    }
    $role = $resourceSpCache[$resourceSpId] | Where-Object { $_.Id -eq $appRoleId }
    if ($role) { return $role.Value }
    return $appRoleId
}

Write-Verbose "Retrieving SKU catalogue..."
$skuMap = @{}
try { Get-MgSubscribedSku -All | ForEach-Object { $skuMap[$_.SkuId] = $_.SkuPartNumber } } catch { }

# --------------------------------------------------------------------------
# ACCOUNTS
# --------------------------------------------------------------------------
Write-Host "`nCollecting users..." -ForegroundColor Cyan
$userProps = @('Id','DisplayName','UserPrincipalName','AccountEnabled','CreatedDateTime','UserType',
               'OnPremisesSyncEnabled','AssignedLicenses',
               'OnPremisesSecurityIdentifier','OnPremisesSamAccountName')
if (-not $SkipSignInActivity) { $userProps += 'SignInActivity' }

$users = Get-MgUser -All -Property $userProps -PageSize 999 |
         Select-Object -First $MaxObjects
if ($ExcludeDisabled) { $users = $users | Where-Object { $_.AccountEnabled } }
Write-Host "  $($users.Count) user(s) retrieved"

# --------------------------------------------------------------------------
# Filter users down to service accounts, if asked
# --------------------------------------------------------------------------
$GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$script:identifiedBy = @{}

if ($Identification -ne 'All') {

    # Expand the designated source group(s) transitively
    $groupMembership = @{}
    if ($Identification -in @('Group','Both','Heuristic')) {
        if (-not $SourceGroup) {
            Write-Warning "-Identification $Identification was requested but no -SourceGroup supplied. Naming pattern only."
        }
        foreach ($sg in @($SourceGroup)) {
            $grp = if ($sg -match $GuidPattern) { Get-MgGroup -GroupId $sg -ErrorAction SilentlyContinue }
                   else { Get-MgGroup -Filter "displayName eq '$($sg -replace "'","''")'" -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if (-not $grp) { Write-Warning "Source group not found: $sg"; continue }
            Write-Verbose "  Expanding source group '$($grp.DisplayName)'"
            foreach ($m in (Get-MgGroupTransitiveMember -GroupId $grp.Id -All)) {
                if ($m.AdditionalProperties['@odata.type'] -match 'group$') { continue }
                $groupMembership[$m.Id] = $grp.DisplayName
            }
        }
        Write-Host "  $($groupMembership.Keys.Count) member(s) across designated source group(s)"
    }

    $kept = foreach ($u in $users) {
        $how = @()
        if ($Identification -in @('Group','Both','Heuristic') -and $groupMembership.ContainsKey($u.Id)) {
            $how += "group: $($groupMembership[$u.Id])"
        }
        if ($Identification -in @('Naming','Both','Heuristic') -and
            "$($u.DisplayName) $($u.UserPrincipalName)" -match $NamePattern) {
            $how += 'naming'
        }
        if ($Identification -eq 'Heuristic' -and $how.Count -eq 0) {
            $sa = $u.SignInActivity
            if ($sa -and -not $sa.LastSignInDateTime -and $sa.LastNonInteractiveSignInDateTime) {
                $how += 'heuristic - REVIEW'
            }
        }
        if ($how.Count -gt 0) {
            $script:identifiedBy[$u.Id] = ($how -join ' + ')
            $u
        }
    }
    $users = @($kept)
    Write-Host "  $($users.Count) user(s) identified as service accounts" -ForegroundColor Cyan

    if ($users.Count -eq 0) {
        Write-Warning "No users matched. Check -SourceGroup spelling and -NamePattern before assuming the tenant is clean."
    }
}

# MFA registration - one tenant-wide report beats one call per user
Write-Verbose "Retrieving authentication method registration report..."
$mfaMap = @{}
try {
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object {
        $methods = @($_.MethodsRegistered)
        $phishResistant = $methods | Where-Object { $_ -match 'fido2|windowsHelloForBusiness|passKey|certificate' }
        $status = if (-not $_.IsMfaRegistered)   { 'Not Registered' }
                  elseif ($phishResistant)       { 'Registered - Phishing Resistant' }
                  else                           { 'Registered - Standard' }
        $mfaMap[$_.Id] = $status
    }
} catch { Write-Warning "Could not read the registration report (needs Entra ID P1 + AuditLog.Read.All): $($_.Exception.Message)" }

# Directory role assignments - active and PIM-eligible
Write-Verbose "Retrieving directory role assignments..."
$roleDefNames = @{}
try { Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleDefNames[$_.Id] = $_.DisplayName } } catch { }

$activeRoles = @{}; $eligibleRoles = @{}
try {
    Get-MgRoleManagementDirectoryRoleAssignment -All | ForEach-Object {
        $n = $roleDefNames[$_.RoleDefinitionId]; if (-not $n) { $n = $_.RoleDefinitionId }
        if (-not $activeRoles.ContainsKey($_.PrincipalId)) { $activeRoles[$_.PrincipalId] = @() }
        $activeRoles[$_.PrincipalId] += $n
    }
} catch { Write-Warning "Could not read active role assignments: $($_.Exception.Message)" }
try {
    Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All | ForEach-Object {
        $n = $roleDefNames[$_.RoleDefinitionId]; if (-not $n) { $n = $_.RoleDefinitionId }
        if (-not $eligibleRoles.ContainsKey($_.PrincipalId)) { $eligibleRoles[$_.PrincipalId] = @() }
        $eligibleRoles[$_.PrincipalId] += $n
    }
} catch { Write-Verbose "No PIM eligibility data (needs Entra ID P2): $($_.Exception.Message)" }

# Managers - one call per user, so only for accounts that look like they need an owner
Write-Verbose "Resolving managers..."
$managerMap = @{}
foreach ($u in $users) {
    try {
        $m = Get-MgUserManager -UserId $u.Id -ErrorAction Stop
        $managerMap[$u.Id] = [PSCustomObject]@{
            Name  = $m.AdditionalProperties['displayName']
            Email = $m.AdditionalProperties['userPrincipalName']
        }
    } catch { }
}

function Get-AccountCategory($u, $mfa, $active, $eligible, $lastInteractive, $lastNonInteractive) {
    $name = "$($u.DisplayName) $($u.UserPrincipalName)".ToLower()

    # Break-glass detection wins regardless of how the account was selected -
    # these need to be visible even inside a filtered service-account list.
    if ($name -match 'break[\s\-_]?glass|emergency|firecall') { return 'Break-Glass (inferred - VERIFY)' }

    # If a filter selected this account, record HOW. That is what makes the list
    # defensible when someone challenges an inclusion or an absence.
    if ($script:identifiedBy.ContainsKey($u.Id)) {
        return "Service Account ($($script:identifiedBy[$u.Id]))"
    }

    if ($u.UserType -eq 'Guest') { return 'Guest (B2B)' }
    if ($name -match '^svc[\-_]|^sa[\-_]|service|automation|^app[\-_]|integration|daemon') { return 'Service Account (inferred)' }
    if ($name -match 'shared|mailbox|reception|team[\-_]') { return 'Shared / Departmental (inferred)' }
    if ($name -match 'test|uat|dummy|temp') { return 'Test Account (inferred)' }
    if ($active -or $eligible) { return 'Privileged / Admin' }
    # No interactive sign-in ever, but non-interactive activity = almost certainly a service account
    if (-not $lastInteractive -and $lastNonInteractive) { return 'Service Account (inferred)' }
    if ($mfa -eq 'Not Registered' -and -not $lastInteractive) { return 'Service Account (inferred)' }
    return 'Standard User'
}

$accountRows = foreach ($u in $users) {
    $sa   = $u.SignInActivity
    $li   = if ($sa) { $sa.LastSignInDateTime } else { $null }
    $lni  = if ($sa) { $sa.LastNonInteractiveSignInDateTime } else { $null }
    $mfa  = if ($mfaMap.ContainsKey($u.Id)) { $mfaMap[$u.Id] } else { 'Unknown' }
    $act  = if ($activeRoles.ContainsKey($u.Id))   { ($activeRoles[$u.Id]   | Sort-Object -Unique) -join '; ' } else { '' }
    $elig = if ($eligibleRoles.ContainsKey($u.Id)) { ($eligibleRoles[$u.Id] | Sort-Object -Unique) -join '; ' } else { '' }
    $lic  = (@($u.AssignedLicenses | ForEach-Object { if ($skuMap.ContainsKey($_.SkuId)) { $skuMap[$_.SkuId] } else { $_.SkuId } }) | Sort-Object -Unique) -join '; '
    $mgr  = $managerMap[$u.Id]

    [PSCustomObject][ordered]@{
        'Display Name'                 = $u.DisplayName
        'User Principal Name'          = $u.UserPrincipalName
        'Object ID'                    = $u.Id
        'Account Category'             = Get-AccountCategory $u $mfa $act $elig $li $lni
        'User Type'                    = $u.UserType
        'Identity Source'              = if ($u.OnPremisesSyncEnabled) { 'Hybrid Synced' } else { 'Cloud-only' }
        'Account Enabled?'             = if ($u.AccountEnabled) { 'Yes' } else { 'No' }
        'Created Date'                 = D $u.CreatedDateTime
        'Last Interactive Sign-In'     = D $li
        'Last Non-Interactive Sign-In' = D $lni
        'MFA / Strong Auth Status'     = $mfa
        'Privileged Roles (Active)'    = if ($act)  { $act }  else { 'None' }
        'Privileged Roles (PIM Eligible)' = if ($elig) { $elig } else { 'None' }
        'Licence Assigned'             = $lic
        'Manager (Graph)'              = if ($mgr) { $mgr.Name }  else { '' }
        'Manager Email (Graph)'        = if ($mgr) { $mgr.Email } else { '' }
        # Join key to the AD Accounts tab. Populated for synced accounts only.
        'On-Prem SID'                  = $u.OnPremisesSecurityIdentifier
        'On-Prem SamAccountName'       = $u.OnPremisesSamAccountName
    }
}
$accountRows | Export-Csv (Out-Path 'Inventory-Accounts.csv') -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# SERVICE PRINCIPALS + MANAGED IDENTITIES
# --------------------------------------------------------------------------
Write-Host "`nCollecting service principals..." -ForegroundColor Cyan
$allSps = Get-MgServicePrincipal -All -PageSize 999 -Property Id,AppId,DisplayName,ServicePrincipalType,`
    SignInAudience,AccountEnabled,KeyCredentials,PasswordCredentials,AppOwnerOrganizationId,`
    ApplicationTemplateId,AlternativeNames,Tags,CreatedDateTime | Select-Object -First $MaxObjects

$managedIdentities = $allSps | Where-Object { $_.ServicePrincipalType -eq 'ManagedIdentity' }
$servicePrincipals = $allSps | Where-Object { $_.ServicePrincipalType -ne 'ManagedIdentity' }
if ($ExcludeDisabled) { $servicePrincipals = $servicePrincipals | Where-Object { $_.AccountEnabled } }
if ($ExcludeMicrosoftFirstParty) {
    $before = $servicePrincipals.Count
    $servicePrincipals = $servicePrincipals | Where-Object { $_.AppOwnerOrganizationId -notin $MicrosoftTenants }
    Write-Host "  dropped $($before - $servicePrincipals.Count) Microsoft first-party service principal(s)"
}
Write-Host "  $($servicePrincipals.Count) service principal(s), $($managedIdentities.Count) managed identity/identities"

# SP sign-in activity - BETA endpoint, keyed on appId
$spSignIn = @{}
if (-not $SkipSignInActivity) {
    Write-Verbose "Retrieving service principal sign-in activity (beta)..."
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
        do {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($a in $resp.value) {
                $last = $a.lastSignInActivity.lastSignInDateTime
                if ($last) { $spSignIn[$a.appId] = $last }
            }
            $uri = $resp.'@odata.nextLink'
        } while ($uri)
    } catch { Write-Warning "Service principal sign-in activity unavailable (beta endpoint): $($_.Exception.Message)" }
}

# App role assignments granted TO each service principal
Write-Verbose "Retrieving application permission grants..."
$grantedPerms = @{}
foreach ($sp in $allSps) {
    try {
        $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
        if ($assignments) {
            $grantedPerms[$sp.Id] = @($assignments | ForEach-Object { Resolve-AppRole $_.ResourceId $_.AppRoleId })
        }
    } catch { }
}

# Delegated grants
$delegatedCount = @{}
try {
    Get-MgOauth2PermissionGrant -All | ForEach-Object {
        $n = @($_.Scope -split ' ' | Where-Object { $_ }).Count
        if (-not $delegatedCount.ContainsKey($_.ClientId)) { $delegatedCount[$_.ClientId] = 0 }
        $delegatedCount[$_.ClientId] += $n
    }
} catch { }

# Registered owners
Write-Verbose "Resolving registered owners..."
$ownerMap = @{}
foreach ($sp in $servicePrincipals) {
    try {
        $o = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All -ErrorAction Stop | Select-Object -First 1
        if ($o) {
            $ownerMap[$sp.Id] = [PSCustomObject]@{
                Name  = $o.AdditionalProperties['displayName']
                Email = $o.AdditionalProperties['userPrincipalName']
            }
        }
    } catch { }
}

function Get-AppOrigin($sp, $tenantId) {
    if ($sp.AppOwnerOrganizationId -in $MicrosoftTenants) { return 'Microsoft First-party' }
    if ($sp.AppOwnerOrganizationId -eq $tenantId) { return 'In-house' }
    if ($sp.ApplicationTemplateId) { return 'Third-party Gallery (SaaS)' }
    if ($sp.AppOwnerOrganizationId) { return 'Third-party Non-gallery' }
    return 'Legacy / Unknown'
}

$spRows = foreach ($sp in $servicePrincipals) {
    $certs   = @($sp.KeyCredentials)
    $secrets = @($sp.PasswordCredentials)
    $types = @()
    if ($secrets.Count -gt 0) { $types += 'Client Secret' }
    if ($certs.Count   -gt 0) { $types += 'Certificate' }
    $credType = if ($types.Count -gt 0) { $types -join ' + ' } else { 'None (SSO only)' }

    $future = @($certs + $secrets | Where-Object { $_.EndDateTime -and [datetime]$_.EndDateTime -gt (Get-Date) } |
                Sort-Object EndDateTime)
    $nextExpiry = if ($future.Count -gt 0) { $future[0].EndDateTime }
                  else { (@($certs + $secrets | Sort-Object EndDateTime -Descending) | Select-Object -First 1).EndDateTime }

    $perms = if ($grantedPerms.ContainsKey($sp.Id)) { $grantedPerms[$sp.Id] } else { @() }
    $risk  = Get-PermissionRisk $perms
    $highest = if ($perms | Where-Object { $_ -in $HighRiskPermissions }) {
                   (($perms | Where-Object { $_ -in $HighRiskPermissions }) | Sort-Object | Select-Object -First 1)
               } elseif ($perms.Count -gt 0) { ($perms | Sort-Object | Select-Object -First 1) } else { 'None' }
    $own = $ownerMap[$sp.Id]

    [PSCustomObject][ordered]@{
        'Display Name'                   = $sp.DisplayName
        'Application (Client) ID'        = $sp.AppId
        'Object ID (Enterprise App)'     = $sp.Id
        'App Origin'                     = Get-AppOrigin $sp $ctx.TenantId
        'Sign-in Audience'               = switch ($sp.SignInAudience) {
                                              'AzureADMyOrg' { 'Single tenant' }
                                              'AzureADMultipleOrgs' { 'Multi-tenant' }
                                              'AzureADandPersonalMicrosoftAccount' { 'Multi-tenant + Personal' }
                                              default { $sp.SignInAudience }
                                           }
        'Enabled?'                       = if ($sp.AccountEnabled) { 'Yes' } else { 'No' }
        'Created Date'                   = D $sp.CreatedDateTime
        'Last Sign-In'                   = D $spSignIn[$sp.AppId]
        'Credential Type'                = $credType
        'Next Credential Expiry'         = D $nextExpiry
        'Credential Count'               = $certs.Count + $secrets.Count
        'Highest Graph / API Permission' = $highest
        'Permission Risk'                = $risk
        'Delegated Permissions'          = if ($delegatedCount.ContainsKey($sp.Id)) { $delegatedCount[$sp.Id] } else { 0 }
        'Admin Consent Granted?'         = if ($perms.Count -gt 0) { 'Yes' } else { 'No' }
        'Registered Owner (Graph)'       = if ($own) { $own.Name }  else { '' }
        'Registered Owner Email'         = if ($own) { $own.Email } else { '' }
    }
}
$spRows | Export-Csv (Out-Path 'Inventory-ServicePrincipals.csv') -NoTypeInformation -Encoding UTF8

$miRows = foreach ($mi in $managedIdentities) {
    # alternativeNames carries isExplicit plus the ARM resource ID.
    # isExplicit=True  -> user-assigned
    # isExplicit=False -> system-assigned
    $alt      = @($mi.AlternativeNames)
    $isExplicit = ($alt | Where-Object { $_ -match 'isExplicit=True' }).Count -gt 0
    $perms    = if ($grantedPerms.ContainsKey($mi.Id)) { $grantedPerms[$mi.Id] } else { @() }

    [PSCustomObject][ordered]@{
        'Display Name'                 = $mi.DisplayName
        'Client ID'                    = $mi.AppId
        'Object (Principal) ID'        = $mi.Id
        'Managed Identity Type'        = if ($isExplicit) { 'User-assigned' } else { 'System-assigned' }
        'Created Date'                 = D $mi.CreatedDateTime
        'Last Sign-In'                 = D $spSignIn[$mi.AppId]
        'Graph / App Role Assignments' = if ($perms.Count -gt 0) { ($perms | Sort-Object -Unique) -join '; ' } else { 'None' }
        'Graph Permission Risk'        = Get-PermissionRisk $perms
    }
}
$miRows | Export-Csv (Out-Path 'Inventory-ManagedIdentities.csv') -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
Write-Host "`nWritten to $((Resolve-Path $OutputFolder).Path)" -ForegroundColor Green
Write-Host ("  Inventory-Accounts.csv           {0,6} rows  -> Accounts tab, cell A2 (columns A-R)" -f $accountRows.Count)
Write-Host ("  Inventory-ServicePrincipals.csv  {0,6} rows  -> Service Principals tab, cell A2 (columns A-Q)" -f $spRows.Count)
Write-Host ("  Inventory-ManagedIdentities.csv  {0,6} rows  -> Managed Identities tab, cell A2 (columns A-H)" -f $miRows.Count)

Write-Host "`nWorth a look before you paste:" -ForegroundColor Yellow
if ($Identification -ne 'All') {
    Write-Host "  Accounts tab filtered by -Identification $Identification. Service principals and managed identities are unfiltered."
    $byHow = $accountRows | Group-Object { ($_.'Account Category' -replace '^Service Account \(| \+ .*$|\)$','') } |
             Sort-Object Count -Descending
    foreach ($g in $byHow) { Write-Host ("    {0,-34} {1}" -f $g.Name, $g.Count) }
    $needReview = @($accountRows | Where-Object { $_.'Account Category' -like '*REVIEW*' })
    if ($needReview.Count) {
        Write-Host "  $($needReview.Count) account(s) matched heuristically only - verify before publishing." -ForegroundColor Yellow
    }
}
$inferred = @($accountRows | Where-Object { $_.'Account Category' -like '*inferred*' -or $_.'Account Category' -like '*VERIFY*' })
Write-Host "  $($inferred.Count) account category/categories need verification - check break-glass in particular."
$noOwner = @($spRows | Where-Object { -not $_.'Registered Owner (Graph)' })
Write-Host "  $($noOwner.Count) service principal(s) have no registered owner in the directory."
$highRisk = @($spRows | Where-Object { $_.'Permission Risk' -eq 'High' })
Write-Host "  $($highRisk.Count) service principal(s) hold a high-risk application permission."
$expiring = @($spRows | Where-Object { $_.'Next Credential Expiry' -and
    ([datetime]::ParseExact($_.'Next Credential Expiry','dd/MM/yyyy',$null) - (Get-Date)).Days -le 30 })
Write-Host "  $($expiring.Count) credential(s) expire within 30 days."

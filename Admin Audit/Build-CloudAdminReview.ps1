<#
.SYNOPSIS
    Collects privileged access held by cloud administrator accounts (username.azr)
    for the Privileged Access Review workbook.

.DESCRIPTION
    Finds accounts matching the cloud admin naming convention, then collects every
    privileged role they hold across two planes:

      - Entra ID directory roles, both permanently assigned and PIM-eligible
      - Azure RBAC role assignments, with the scope of each

    Roles assigned to role-assignable GROUPS are resolved as well. Graph reports the
    group's object ID as the principal, so a report matching only on the user's own
    object ID silently misses every group-derived role - and in most tenants that is
    a large share of them. Each group is expanded transitively, so nested membership
    counts, and both the group display name and object ID are carried through to the
    output alongside the route the role arrived by.

    Directory scope is captured too, so a role limited to one Administrative Unit is
    not reported as tenant-wide privilege.

    Also collects the authentication posture of each admin account (MFA registration,
    whether it is phishing-resistant) and links each admin account back to the
    person's standard account, so a leaver whose standard account is disabled but
    whose admin account is still live becomes visible.

    Also writes a second CSV - the "normal user accounts" comparison set. This is
    the exact list of non-admin-pattern Entra user accounts (respecting
    -StandardAccountDomain, if given) used internally to resolve each admin
    account's standard account and decide orphan status; previously it existed
    only as an in-memory lookup table with no output of its own. Exporting it lets
    a reviewer see and sanity-check the baseline the orphan check is run against,
    rather than trusting it silently - the same reasoning Build-OnPremAdminReview
    applies to its own Normal-Users.csv export.

    Roles are tiered. Tier 0 means control-plane: the holder can grant themselves
    anything else. The tiering is defined in the $RoleTiers table below and is
    intended to be edited to match your own model.

    READ-ONLY.

.PARAMETER AdminPattern
    Regex identifying cloud admin accounts by UPN. Default matches username.azr@...

.PARAMETER BaseUsernameCapture
    Regex with one capture group that extracts the base username from the admin UPN.
    Default takes everything before '.azr'.

.PARAMETER StandardAccountDomain
    UPN suffix of everyday accounts, e.g. 'corp.com.au'. Used to locate the person's
    standard account. If omitted the script matches on UPN prefix across all domains.

.PARAMETER NormalUsersOutputPath
    CSV path for the normal (non-admin) user account export - the comparison
    baseline used to determine orphaned admin accounts.

.PARAMETER SkipAzureRbac
    Skip Azure RBAC collection. Use if you only want the Entra directory role picture,
    or have no Azure access.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All','Group.Read.All'
    Connect-AzAccount
    .\Build-CloudAdminReview.ps1 -StandardAccountDomain 'corp.com.au' -Verbose

.NOTES
    Modules: Microsoft.Graph, and Az.Accounts + Az.ResourceGraph unless -SkipAzureRbac.

    Graph scopes (read-only):
        User.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
        AuditLog.Read.All, Group.Read.All

    PIM eligibility requires Entra ID P2. MFA registration detail requires P1.
    Without those licences the script still runs; the affected columns are blank.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\Cloud-Admins.csv",
    [string]$AdminPattern = '\.azr@',
    [string]$BaseUsernameCapture = '^(.+?)\.azr@',
    [string]$StandardAccountDomain,
    [string]$NormalUsersOutputPath = ".\Normal-CloudUsers.csv",
    [switch]$SkipAzureRbac,
    [switch]$UseTenantScope
)

$ErrorActionPreference = 'Stop'

# ==========================================================================
# Role tiering. Edit to match your model - this is the judgement layer.
# Tier 0 = control plane: the holder can grant themselves anything else.
# ==========================================================================
$RoleTiers = @{
    # ---- Entra ID directory roles ----
    'Global Administrator'                      = 0
    'Privileged Role Administrator'             = 0
    'Privileged Authentication Administrator'   = 0
    'Partner Tier2 Support'                     = 0
    # Application and Cloud Application Administrator can add credentials to any
    # service principal, including highly privileged ones. Microsoft treats these
    # as among the highest-privilege roles, and so should you.
    'Application Administrator'                 = 0
    'Cloud Application Administrator'           = 0
    'Hybrid Identity Administrator'             = 0
    'Domain Name Administrator'                 = 0

    'Security Administrator'                    = 1
    'Conditional Access Administrator'          = 1
    'Authentication Administrator'              = 1
    'User Administrator'                        = 1
    'Exchange Administrator'                    = 1
    'SharePoint Administrator'                  = 1
    'Intune Administrator'                      = 1
    'Teams Administrator'                       = 1
    'Groups Administrator'                      = 1
    'Helpdesk Administrator'                    = 1
    'Password Administrator'                    = 1
    'Billing Administrator'                     = 1
    'Compliance Administrator'                  = 1

    # ---- Azure RBAC ----
    'Owner'                                     = 0
    'User Access Administrator'                 = 0
    'Role Based Access Control Administrator'   = 0
    'Contributor'                               = 1
    'Key Vault Administrator'                   = 1
    'Key Vault Secrets Officer'                 = 1
    'Storage Blob Data Owner'                   = 1
    'Reader'                                    = 2
}
function Get-Tier([string]$role) {
    if (-not $role -or $role -eq 'None') { return $null }
    if ($RoleTiers.ContainsKey($role)) { return $RoleTiers[$role] }
    if ($role -match 'Administrator|Owner') { return 1 }
    return 2
}
function Get-HighestRole([string[]]$roles) {
    $ranked = $roles | Where-Object { $_ -and $_ -ne 'None' } |
              Sort-Object @{ E = { $t = Get-Tier $_; if ($null -eq $t) { 9 } else { $t } } }, @{ E = { $_ } }
    if ($ranked) { return @($ranked)[0] }
    return 'None'
}

# ==========================================================================
$Scopes = @('User.Read.All','Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All','Group.Read.All')
if (-not (Get-MgContext)) { Connect-MgGraph -Scopes $Scopes | Out-Null }
$ctx = Get-MgContext
Write-Host "Tenant $($ctx.TenantId)" -ForegroundColor Cyan

# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
$props = @('Id','DisplayName','UserPrincipalName','AccountEnabled','CreatedDateTime','UserType',
           'SignInActivity','AssignedLicenses','Department','JobTitle','OnPremisesSyncEnabled')
Write-Host "Retrieving users..." -ForegroundColor Cyan
$allUsers = try { Get-MgUser -All -Property $props -PageSize 999 }
            catch {
                Write-Warning "Retrying without signInActivity (needs Entra ID P1)."
                Get-MgUser -All -Property ($props | Where-Object { $_ -ne 'SignInActivity' }) -PageSize 999
            }

$admins = @($allUsers | Where-Object { $_.UserPrincipalName -match $AdminPattern })
Write-Host "  $($allUsers.Count) user(s), $($admins.Count) matching the cloud admin convention" -ForegroundColor Cyan
if ($admins.Count -eq 0) {
    Write-Warning "No accounts matched '$AdminPattern'. Check the pattern before assuming there are none."
}

# Index standard accounts by UPN prefix so admin accounts can be linked to a person
$standardByPrefix = @{}
foreach ($u in $allUsers) {
    if ($u.UserPrincipalName -match $AdminPattern) { continue }
    $prefix = ($u.UserPrincipalName -split '@')[0].ToLower()
    if ($StandardAccountDomain -and $u.UserPrincipalName -notlike "*@$StandardAccountDomain") { continue }
    if (-not $standardByPrefix.ContainsKey($prefix)) { $standardByPrefix[$prefix] = $u }
}

# Reverse of $standardByPrefix - which admin account(s), if any, belong to a given
# standard account prefix. Used to build the Normal-CloudUsers.csv comparison export.
$adminByPrefix = @{}
foreach ($a in $admins) {
    $b = if ($a.UserPrincipalName -match $BaseUsernameCapture) { $Matches[1].ToLower() } else { ($a.UserPrincipalName -split '@')[0].ToLower() }
    if (-not $adminByPrefix.ContainsKey($b)) { $adminByPrefix[$b] = [System.Collections.Generic.List[object]]::new() }
    $adminByPrefix[$b].Add($a)
}

# --------------------------------------------------------------------------
# Directory roles: active and PIM-eligible
# --------------------------------------------------------------------------
Write-Host "Retrieving directory role assignments..." -ForegroundColor Cyan
$roleDefs = @{}
try { Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleDefs[$_.Id] = $_.DisplayName } } catch { }

# --------------------------------------------------------------------------
# Group expansion cache.
#
# Roles are frequently assigned to role-assignable groups rather than directly
# to a user. Graph returns the GROUP's object ID as the principal, so matching
# only on the user's object ID silently misses every one of those assignments.
# Each excluding group is expanded transitively - nested groups included - and
# the role is attributed to every member, tagged with the group it came through.
# --------------------------------------------------------------------------
$groupCache = @{}   # groupId -> @{ Name; Members = @(objectIds) }

function Expand-AssignmentGroup {
    param([string]$GroupId)
    if ($groupCache.ContainsKey($GroupId)) { return $groupCache[$GroupId] }

    $name = "UNRESOLVED GROUP ($GroupId)"
    $members = @()
    try {
        $g = Get-MgGroup -GroupId $GroupId -Property Id,DisplayName -ErrorAction Stop
        $name = $g.DisplayName
        # Transitive expansion catches nesting, which is where surprise privilege lives
        $members = @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop |
                     Where-Object { $_.AdditionalProperties['@odata.type'] -notmatch 'group$' } |
                     ForEach-Object { $_.Id })
    } catch {
        Write-Warning "Could not expand role-assigned group $GroupId : $($_.Exception.Message)"
    }
    $groupCache[$GroupId] = [PSCustomObject]@{ Name = $name; Members = $members; Id = $GroupId }
    return $groupCache[$GroupId]
}

# Distinguishes a group principal from a user principal without a call per assignment
$principalTypeCache = @{}
function Test-IsGroupPrincipal {
    param([string]$PrincipalId)
    if ($principalTypeCache.ContainsKey($PrincipalId)) { return $principalTypeCache[$PrincipalId] }
    $isGroup = $false
    try {
        $o = Get-MgDirectoryObject -DirectoryObjectId $PrincipalId -ErrorAction Stop
        $isGroup = ($o.AdditionalProperties['@odata.type'] -match 'group$')
    } catch { }
    $principalTypeCache[$PrincipalId] = $isGroup
    return $isGroup
}

# Each entry: @{ Role; ViaGroup; ViaGroupId; Scope }
$activeRoles = @{}; $eligibleRoles = @{}

function Add-RoleGrant {
    param([hashtable]$Table, [string]$PrincipalId, [string]$Role, [string]$ViaGroup, [string]$ViaGroupId, [string]$Scope)
    if (-not $Table.ContainsKey($PrincipalId)) { $Table[$PrincipalId] = @() }
    $Table[$PrincipalId] += [PSCustomObject]@{
        Role = $Role; ViaGroup = $ViaGroup; ViaGroupId = $ViaGroupId; Scope = $Scope
    }
}

function Resolve-DirectoryScope {
    param([string]$ScopeId)
    if (-not $ScopeId -or $ScopeId -eq '/') { return 'Tenant-wide' }
    if ($ScopeId -match '^/administrativeUnits/(.+)$') {
        $auId = $Matches[1]
        try { return "AU: $((Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $auId -Property Id,DisplayName).DisplayName)" }
        catch { return "AU: $auId" }
    }
    return $ScopeId
}

function Import-RoleAssignments {
    param([object[]]$Assignments, [hashtable]$Table, [string]$Label)
    $direct = 0; $viaGroup = 0; $groupsSeen = @{}
    foreach ($ra in $Assignments) {
        $roleName = $roleDefs[$ra.RoleDefinitionId]
        if (-not $roleName) { $roleName = $ra.RoleDefinitionId }
        $scope = Resolve-DirectoryScope $ra.DirectoryScopeId

        if (Test-IsGroupPrincipal $ra.PrincipalId) {
            $g = Expand-AssignmentGroup $ra.PrincipalId
            $groupsSeen[$g.Id] = $g.Name
            foreach ($m in $g.Members) {
                Add-RoleGrant -Table $Table -PrincipalId $m -Role $roleName `
                              -ViaGroup $g.Name -ViaGroupId $g.Id -Scope $scope
                $viaGroup++
            }
        } else {
            Add-RoleGrant -Table $Table -PrincipalId $ra.PrincipalId -Role $roleName `
                          -ViaGroup '' -ViaGroupId '' -Scope $scope
            $direct++
        }
    }
    Write-Host ("  {0}: {1} direct, {2} via {3} group(s)" -f $Label, $direct, $viaGroup, $groupsSeen.Keys.Count)
}

try {
    Import-RoleAssignments -Assignments @(Get-MgRoleManagementDirectoryRoleAssignment -All) `
                           -Table $activeRoles -Label 'Active'
} catch { Write-Warning "Active role assignments unavailable: $($_.Exception.Message)" }

try {
    Import-RoleAssignments -Assignments @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All) `
                           -Table $eligibleRoles -Label 'PIM-eligible'
} catch { Write-Verbose "No PIM eligibility data (needs Entra ID P2): $($_.Exception.Message)" }

# --------------------------------------------------------------------------
# MFA registration
# --------------------------------------------------------------------------
Write-Host "Retrieving authentication method registration..." -ForegroundColor Cyan
$mfa = @{}
try {
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All | ForEach-Object {
        $methods = @($_.MethodsRegistered)
        $phish = @($methods | Where-Object { $_ -match 'fido2|windowsHelloForBusiness|passKey|certificateBasedAuthentication' })
        $mfa[$_.Id] = [PSCustomObject]@{
            Registered      = [bool]$_.IsMfaRegistered
            PhishResistant  = ($phish.Count -gt 0)
            Methods         = ($methods -join '; ')
        }
    }
} catch { Write-Warning "Registration report unavailable (needs Entra ID P1): $($_.Exception.Message)" }

# --------------------------------------------------------------------------
# Azure RBAC via Resource Graph
# --------------------------------------------------------------------------
$azByPrincipal = @{}
if (-not $SkipAzureRbac) {
    if (-not (Get-Module -ListAvailable -Name Az.ResourceGraph)) {
        Write-Warning "Az.ResourceGraph not installed - skipping Azure RBAC. Install-Module Az.ResourceGraph"
    } else {
        Import-Module Az.ResourceGraph -ErrorAction Stop
        if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
        Write-Host "Querying Azure role assignments..." -ForegroundColor Cyan
        $q = @'
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType),
         roleDefId = tolower(tostring(properties.roleDefinitionId)),
         scope = tostring(properties.scope)
| join kind=leftouter (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend roleDefId = tolower(id), roleName = tostring(properties.roleName)
    | project roleDefId, roleName
) on roleDefId
| project principalId, principalType, roleName, scope
'@
        $all = [System.Collections.Generic.List[object]]::new()
        $skip = $null
        do {
            $splat = @{ Query = $q; First = 1000 }
            if ($skip) { $splat.SkipToken = $skip }
            if ($UseTenantScope) { $splat.UseTenantScope = $true }
            $page = Search-AzGraph @splat
            if ($page) { $all.AddRange(@($page)) }
            $skip = $page.SkipToken
        } while ($skip)
        # Azure RBAC is just as often assigned to groups. Resource Graph gives us
        # principalType directly, so no extra lookup is needed to spot them.
        $azDirect = 0; $azViaGroup = 0; $azGroups = @{}
        foreach ($a in $all) {
            if ($a.principalType -eq 'Group') {
                $g = Expand-AssignmentGroup $a.principalId
                $azGroups[$g.Id] = $g.Name
                foreach ($m in $g.Members) {
                    if (-not $azByPrincipal.ContainsKey($m)) { $azByPrincipal[$m] = @() }
                    $azByPrincipal[$m] += [PSCustomObject]@{
                        roleName = $a.roleName; scope = $a.scope
                        ViaGroup = $g.Name; ViaGroupId = $g.Id
                    }
                    $azViaGroup++
                }
            } else {
                if (-not $azByPrincipal.ContainsKey($a.principalId)) { $azByPrincipal[$a.principalId] = @() }
                $azByPrincipal[$a.principalId] += [PSCustomObject]@{
                    roleName = $a.roleName; scope = $a.scope; ViaGroup = ''; ViaGroupId = ''
                }
                $azDirect++
            }
        }
        Write-Host ("  {0} assignment(s): {1} direct, {2} via {3} group(s)" -f $all.Count, $azDirect, $azViaGroup, $azGroups.Keys.Count)
    }
}

function Get-ScopeKind([string]$scope) {
    if ($scope -match '^/providers/Microsoft\.Management/managementGroups/') { return 'ManagementGroup' }
    if ($scope -match '^/subscriptions/[^/]+$')                              { return 'Subscription' }
    if ($scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$')         { return 'ResourceGroup' }
    return 'Resource'
}
function Get-ShortScope([string]$scope) {
    switch (Get-ScopeKind $scope) {
        'ManagementGroup' { "MG:$($scope -replace '.*/managementGroups/','')" }
        'Subscription'    { "SUBSCRIPTION:$($scope -replace '^/subscriptions/','')" }
        'ResourceGroup'   { "rg:$($scope -replace '.*/resourceGroups/','')" }
        default           { ($scope -split '/')[-1] }
    }
}

# --------------------------------------------------------------------------
# Shape
# --------------------------------------------------------------------------
$now = Get-Date
$rows = foreach ($a in $admins) {

    $base = if ($a.UserPrincipalName -match $BaseUsernameCapture) { $Matches[1].ToLower() }
            else { ($a.UserPrincipalName -split '@')[0].ToLower() }
    $std = $standardByPrefix[$base]

    $actGrants  = @(if ($activeRoles.ContainsKey($a.Id))   { $activeRoles[$a.Id] })
    $eligGrants = @(if ($eligibleRoles.ContainsKey($a.Id)) { $eligibleRoles[$a.Id] })

    # Render each grant as "Role (via Group)" or "Role [AU: name]" so the route
    # and the scope travel with the role rather than being lost in a bare name.
    function Format-Grant($g) {
        $t = $g.Role
        if ($g.Scope -and $g.Scope -ne 'Tenant-wide') { $t += " [$($g.Scope)]" }
        if ($g.ViaGroup) { $t += " (via $($g.ViaGroup))" }
        return $t
    }
    $act  = @($actGrants  | ForEach-Object { Format-Grant $_ } | Sort-Object -Unique)
    $elig = @($eligGrants | ForEach-Object { Format-Grant $_ } | Sort-Object -Unique)
    $highestEntra = Get-HighestRole @(($actGrants + $eligGrants).Role)

    $az = @(if ($azByPrincipal.ContainsKey($a.Id)) { $azByPrincipal[$a.Id] })
    $azStrings = @($az | ForEach-Object {
        $t = "$($_.roleName) @ $(Get-ShortScope $_.scope)"
        if ($_.ViaGroup) { $t += " (via $($_.ViaGroup))" }
        $t
    } | Sort-Object -Unique)
    $highestAz = Get-HighestRole @($az.roleName)
    $broad = if ($az | Where-Object { (Get-ScopeKind $_.scope) -in @('Subscription','ManagementGroup') }) { 'Yes' } else { 'No' }

    # Every distinct group granting this account any role, in either plane
    $allGroupGrants = @($actGrants + $eligGrants | Where-Object { $_.ViaGroupId }) +
                      @($az | Where-Object { $_.ViaGroupId })
    $groupNames = @($allGroupGrants | ForEach-Object { $_.ViaGroup } | Sort-Object -Unique)
    $groupIds   = @($allGroupGrants | ForEach-Object { $_.ViaGroupId } | Sort-Object -Unique)

    $directCount = @($actGrants + $eligGrants | Where-Object { -not $_.ViaGroupId }).Count +
                   @($az | Where-Object { -not $_.ViaGroupId }).Count
    $groupCount  = $allGroupGrants.Count

    # Non-tenant-wide directory scopes, e.g. a role limited to one Administrative Unit
    $scopes = @($actGrants + $eligGrants | Where-Object { $_.Scope -and $_.Scope -ne 'Tenant-wide' } |
                ForEach-Object { $_.Scope } | Sort-Object -Unique)

    $tiers = @(Get-Tier $highestEntra; Get-Tier $highestAz) | Where-Object { $null -ne $_ }
    $overallTier = if ($tiers) { ($tiers | Measure-Object -Minimum).Minimum } else { '' }

    $m  = $mfa[$a.Id]
    $sa = $a.SignInActivity
    $li = if ($sa -and $sa.LastSignInDateTime) { [datetime]$sa.LastSignInDateTime } else { $null }

    [PSCustomObject][ordered]@{
        'Admin UPN'              = $a.UserPrincipalName
        'Display Name'          = $a.DisplayName
        'Object ID'             = $a.Id
        'Base Username'         = $base
        'Enabled'               = if ($a.AccountEnabled) { 'Yes' } else { 'No' }
        'Created'               = if ($a.CreatedDateTime) { ([datetime]$a.CreatedDateTime).ToString('dd/MM/yyyy') } else { '' }
        'Last Sign-In'          = if ($li) { $li.ToString('dd/MM/yyyy') } else { '' }
        'MFA Registered'        = if ($m) { if ($m.Registered) { 'Yes' } else { 'No' } } else { 'Unknown' }
        'Phishing Resistant'    = if ($m) { if ($m.PhishResistant) { 'Yes' } else { 'No' } } else { 'Unknown' }
        'Auth Methods'          = if ($m) { $m.Methods } else { '' }
        'Entra Roles (Active)'  = if ($act.Count)  { $act -join '; ' }  else { 'None' }
        'Entra Roles (Eligible)'= if ($elig.Count) { $elig -join '; ' } else { 'None' }
        'Active Role Count'     = $act.Count
        'Eligible Role Count'   = $elig.Count
        'Highest Entra Role'    = $highestEntra
        'Azure RBAC Roles'      = if ($azStrings.Count) { $azStrings -join '; ' } else { 'None' }
        'Highest Azure Role'    = $highestAz
        'Sub or MG Scoped'      = $broad
        'Assignment Route'      = if ($groupCount -gt 0 -and $directCount -gt 0) { 'Direct + Group' }
                                  elseif ($groupCount -gt 0) { 'Group only' }
                                  elseif ($directCount -gt 0) { 'Direct only' } else { '' }
        'Granting Groups'       = if ($groupNames.Count) { $groupNames -join '; ' } else { '' }
        'Granting Group IDs'    = if ($groupIds.Count)   { $groupIds   -join '; ' } else { '' }
        'Direct Assignments'    = $directCount
        'Group Assignments'     = $groupCount
        'Directory Scopes'      = if ($scopes.Count) { $scopes -join '; ' } else { 'Tenant-wide' }
        'Overall Tier'          = $overallTier
        'Standard Account UPN'  = if ($std) { $std.UserPrincipalName } else { '' }
        'Standard Acct Enabled' = if ($std) { if ($std.AccountEnabled) { 'Yes' } else { 'No' } } else { 'NOT FOUND' }
        'Person Display Name'   = if ($std) { $std.DisplayName } else { '' }
        'Department'            = if ($std) { $std.Department } else { $a.Department }
        'Job Title'             = if ($std) { $std.JobTitle } else { $a.JobTitle }
    }
}

$rows | Sort-Object 'Overall Tier', @{E={$_.'Active Role Count'};Descending=$true}, 'Admin UPN' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Normal user accounts - the comparison baseline the orphan check above runs
# against. This is the same set as $standardByPrefix, exported so it can be
# reviewed on its own rather than trusted as an invisible lookup table.
# --------------------------------------------------------------------------
Write-Host "Building normal user account list..." -ForegroundColor Cyan
$normalUsers = @($allUsers | Where-Object {
    $_.UserPrincipalName -notmatch $AdminPattern -and
    (-not $StandardAccountDomain -or $_.UserPrincipalName -like "*@$StandardAccountDomain")
})

$normalRows = foreach ($u in $normalUsers) {
    $prefix = ($u.UserPrincipalName -split '@')[0].ToLower()
    $linkedAdmins = @(if ($adminByPrefix.ContainsKey($prefix)) { $adminByPrefix[$prefix] })
    $sa = $u.SignInActivity
    $li = if ($sa -and $sa.LastSignInDateTime) { [datetime]$sa.LastSignInDateTime } else { $null }

    [PSCustomObject][ordered]@{
        'UPN'                       = $u.UserPrincipalName
        'Display Name'              = $u.DisplayName
        'Object ID'                 = $u.Id
        'Enabled'                   = if ($u.AccountEnabled) { 'Yes' } else { 'No' }
        'User Type'                 = $u.UserType
        'On-Prem Synced'            = if ($u.OnPremisesSyncEnabled) { 'Yes' } else { 'No' }
        'Created'                   = if ($u.CreatedDateTime) { ([datetime]$u.CreatedDateTime).ToString('dd/MM/yyyy') } else { '' }
        'Last Sign-In'              = if ($li) { $li.ToString('dd/MM/yyyy') } else { '' }
        'Department'                = $u.Department
        'Job Title'                 = $u.JobTitle
        'Has Admin Account'         = if ($linkedAdmins.Count) { 'Yes' } else { 'No' }
        'Admin Accounts'            = ($linkedAdmins.UserPrincipalName -join '; ')
        'Any Admin Account Enabled' = if (@($linkedAdmins | Where-Object AccountEnabled).Count) { 'Yes' } elseif ($linkedAdmins.Count) { 'No' } else { '' }
    }
}

$normalRows | Sort-Object @{E={$_.Enabled};Descending=$true}, 'UPN' |
    Export-Csv -Path $NormalUsersOutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$t0        = @($rows | Where-Object { $_.'Overall Tier' -eq 0 })
$standing  = @($rows | Where-Object { [int]$_.'Active Role Count' -gt 0 })
$noPhish   = @($rows | Where-Object { $_.'Phishing Resistant' -ne 'Yes' -and $_.Enabled -eq 'Yes' })
$noMfa     = @($rows | Where-Object { $_.'MFA Registered' -eq 'No' -and $_.Enabled -eq 'Yes' })
$orphaned  = @($rows | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })
$dormant   = @($rows | Where-Object { -not $_.'Last Sign-In' -and $_.Enabled -eq 'Yes' })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  Cloud admin accounts                 : $($rows.Count)"
Write-Host "  Tier 0 (control plane)               : $($t0.Count)" -ForegroundColor Yellow
Write-Host "  Holding standing (permanent) roles   : $($standing.Count)" -ForegroundColor Yellow
Write-Host "  Enabled without phishing-resistant MFA : $($noPhish.Count)" -ForegroundColor Yellow
if ($noMfa.Count)    { Write-Host "  Enabled with NO MFA registered       : $($noMfa.Count)" -ForegroundColor Red }
if ($orphaned.Count) {
    Write-Host "  ORPHANED - admin enabled, standard account disabled or missing : $($orphaned.Count)" -ForegroundColor Red
    Write-Host "    Likely leavers. Admin accounts are separate objects and are routinely missed at offboarding."
}
if ($dormant.Count)  { Write-Host "  Enabled but never signed in          : $($dormant.Count)" }
$viaGroupOnly = @($rows | Where-Object { $_.'Assignment Route' -eq 'Group only' })
$anyGroup     = @($rows | Where-Object { [int]$_.'Group Assignments' -gt 0 })
$scoped       = @($rows | Where-Object { $_.'Directory Scopes' -ne 'Tenant-wide' })
if ($anyGroup.Count) {
    Write-Host "  Holding roles via group membership   : $($anyGroup.Count)" -ForegroundColor Yellow
    Write-Host "    $($viaGroupOnly.Count) of these hold NO direct assignment at all - they would have been"
    Write-Host "    invisible to a report that matched only on the user's own object ID."
}
if ($scoped.Count) {
    Write-Host "  Roles scoped to an Administrative Unit : $($scoped.Count)"
    Write-Host "    Narrower than tenant-wide. Do not read these as full-tenant privilege."
}

$normalDisabled = @($normalRows | Where-Object { $_.Enabled -eq 'No' })
$normalDisabledLiveAdmin = @($normalRows | Where-Object { $_.Enabled -eq 'No' -and $_.'Any Admin Account Enabled' -eq 'Yes' })

Write-Host "`nWritten to $NormalUsersOutputPath" -ForegroundColor Green
Write-Host "  Normal (non-admin-pattern) user accounts : $($normalRows.Count)"
Write-Host "  Disabled                                  : $($normalDisabled.Count)"
if ($normalDisabledLiveAdmin.Count) {
    Write-Host "  Disabled standard account, admin account still enabled : $($normalDisabledLiveAdmin.Count)" -ForegroundColor Red
    Write-Host "    Same leavers as the ORPHANED count above, seen from the standard-account side."
}

Write-Host "`nNext: paste Cloud Admins into the 'Cloud Admins' tab at cell A2 (columns A-AD)." -ForegroundColor Cyan
Write-Host "      paste Normal Users into a 'Normal Users' tab at cell A2 (columns A-M), if you want it in the workbook." -ForegroundColor Cyan

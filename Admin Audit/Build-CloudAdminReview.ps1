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

    The standard-account link is tried two ways, in order: first by matching the
    admin's base username against onPremisesSamAccountName (the on-prem
    SamAccountName, synced into Entra by Entra Connect for hybrid accounts), then
    by UPN prefix. The SAM path exists because some orgs name cloud admin accounts
    after the on-prem SamAccountName (e.g. 'wredmo.azr@...') while real people's
    own cloud UPN follows an entirely different convention (e.g.
    'wesley.redmond@...') - UPN-prefix matching alone then fails for every single
    admin, with no partial successes to hint at why. Without -StandardAccountDomain,
    the UPN-prefix path (only) also crosses every domain in the tenant. If a key
    - SAM or UPN prefix - belongs to more than one candidate account, that's
    ambiguous, not resolvable: 'Standard Acct Enabled' reads 'Ambiguous' rather
    than silently picking one, and 'Standard Account UPN' lists every candidate
    found. Ambiguous accounts are excluded from the ORPHANED count (neither
    confirmed clean nor confirmed orphaned) and reported as their own summary
    line instead.

    Writes THREE CSVs, not one, so Entra and Azure RBAC remediation can be worked as
    separate projects by separate owners:

      - Cloud-Admin-Accounts.csv: every account matching the admin pattern, with no
        filtering by privilege. This is the inventory - it is what catches an admin
        account that currently holds NO role in either plane (privilege was removed
        and the account wasn't, or the standard account behind it was disabled and
        nobody noticed). Filtering this list by privilege would make that invisible.
      - Entra-Admins.csv: only accounts holding at least one Entra directory role
        (active or PIM-eligible), with full role detail and its own review-tracking
        columns once pasted into the workbook.
      - Azure-RBAC-Admins.csv: the same, for Azure RBAC role assignments.

    An account holding privilege in both planes appears on both filtered exports;
    each carries an 'Also Holds ...' flag pointing at the other, so remediating one
    plane doesn't happen blind to exposure in the other.

    Also writes a fourth CSV - the "normal user accounts" comparison set. This is
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

.PARAMETER CloudAccountsOutputPath
    CSV path for the unfiltered cloud admin account inventory - every account
    matching the admin pattern, regardless of current privilege.

.PARAMETER EntraOutputPath
    CSV path for accounts holding at least one Entra directory role.

.PARAMETER AzureRbacOutputPath
    CSV path for accounts holding at least one Azure RBAC role assignment.

.PARAMETER NormalUsersOutputPath
    CSV path for the normal (non-admin) user account export - the comparison
    baseline used to determine orphaned admin accounts.

.PARAMETER SkipAzureRbac
    Skip Azure RBAC collection. Use if you only want the Entra directory role picture,
    or have no Azure access. Azure-RBAC-Admins.csv is still written, with headers only.

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
    [string]$CloudAccountsOutputPath = ".\Cloud-Admin-Accounts.csv",
    [string]$EntraOutputPath = ".\Entra-Admins.csv",
    [string]$AzureRbacOutputPath = ".\Azure-RBAC-Admins.csv",
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
           'SignInActivity','AssignedLicenses','Department','JobTitle','OnPremisesSyncEnabled',
           'OnPremisesSamAccountName')
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

# Index standard accounts BOTH by UPN prefix and by on-prem SamAccountName, so an
# admin account can be linked to a person either way.
#
# This matters because an org can name cloud ADMIN accounts after the on-prem
# SamAccountName (e.g. 'wredmo.azr@corp.onmicrosoft.com' for on-prem account
# 'wredmo') while the same person's real cloud UPN follows Entra's own convention
# instead (e.g. 'wesley.redmond@corp.com.au') - matching by UPN prefix alone then
# fails for every single admin, 100% of the time, because 'wredmo' never appears
# as a UPN prefix anywhere in the tenant; it only shows up in
# onPremisesSamAccountName, synced from AD by Entra Connect. SamAccountName is
# tried first below - once an org has any admin accounts named this way at all,
# it's the deliberate, authoritative join key - falling back to UPN-prefix
# matching for tenants (or individual accounts) where OnPremisesSamAccountName
# isn't populated (pure-cloud accounts never have it).
#
# Without -StandardAccountDomain, UPN-prefix matching crosses every domain in the
# tenant - UPNs are unique tenant-wide as full strings, but not per prefix, so the
# same prefix can legitimately belong to two different people on two different
# domains. Silently keeping whichever one enumerates first would feed a coin-flip
# 'Standard Acct Enabled' into the orphan check with no sign anything was
# ambiguous - so a prefix (or SamAccountName) seen more than once is tracked and
# excluded from resolution instead, the same way Update-AdminPeopleEntra.ps1
# already treats a same-prefix match with no domain given as 'Ambiguous' rather
# than guessing.
$standardCandidatesByPrefix = @{}
$standardCandidatesBySam    = @{}
foreach ($u in $allUsers) {
    if ($u.UserPrincipalName -match $AdminPattern) { continue }
    if ($StandardAccountDomain -and $u.UserPrincipalName -notlike "*@$StandardAccountDomain") { continue }

    $prefix = ($u.UserPrincipalName -split '@')[0].ToLower()
    if (-not $standardCandidatesByPrefix.ContainsKey($prefix)) { $standardCandidatesByPrefix[$prefix] = [System.Collections.Generic.List[object]]::new() }
    $standardCandidatesByPrefix[$prefix].Add($u)

    if ($u.OnPremisesSamAccountName) {
        $sam = $u.OnPremisesSamAccountName.ToLower()
        if (-not $standardCandidatesBySam.ContainsKey($sam)) { $standardCandidatesBySam[$sam] = [System.Collections.Generic.List[object]]::new() }
        $standardCandidatesBySam[$sam].Add($u)
    }
}

# Resolves one candidate map (prefix or SAM) down to a single match per key,
# tracking keys that resolved to more than one account as ambiguous rather than
# picking one. Same logic, run twice - once per key type - so both matching
# paths get the same "don't guess on ambiguity" treatment.
function Resolve-CandidateMap {
    param([hashtable]$Candidates, [string]$Label)
    $resolved = @{}
    $ambiguous = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $Candidates.Keys) {
        $c = $Candidates[$key]
        if ($c.Count -eq 1) {
            $resolved[$key] = $c[0]
        } else {
            $ambiguous.Add($key)
            Write-Warning "Ambiguous standard account for '$key' ($Label) - $($c.Count) accounts share this value ($(($c.UserPrincipalName) -join ', ')). Recorded as Ambiguous, not guessed."
        }
    }
    [PSCustomObject]@{
        Resolved  = $resolved
        Ambiguous = [System.Collections.Generic.HashSet[string]]::new([string[]]$ambiguous)
    }
}

$bySamResolution    = Resolve-CandidateMap -Candidates $standardCandidatesBySam    -Label 'on-prem SAM'
$byPrefixResolution = Resolve-CandidateMap -Candidates $standardCandidatesByPrefix -Label 'UPN prefix'
$standardBySam    = $bySamResolution.Resolved
$standardByPrefix = $byPrefixResolution.Resolved

# Looks up a base username against SAM first, then UPN prefix. Returns which path
# (if either) produced the match or the ambiguity, so the caller can report a
# meaningful 'Standard Account UPN' value and know which candidate list to show
# for an ambiguous case.
function Resolve-StandardAccount {
    param([string]$Base)
    if ($standardBySam.ContainsKey($Base))                    { return [PSCustomObject]@{ User = $standardBySam[$Base];    Ambiguous = $false; MatchedVia = 'SAM' } }
    if ($bySamResolution.Ambiguous.Contains($Base))            { return [PSCustomObject]@{ User = $null;                    Ambiguous = $true;  MatchedVia = 'SAM' } }
    if ($standardByPrefix.ContainsKey($Base))                 { return [PSCustomObject]@{ User = $standardByPrefix[$Base]; Ambiguous = $false; MatchedVia = 'UPN prefix' } }
    if ($byPrefixResolution.Ambiguous.Contains($Base))         { return [PSCustomObject]@{ User = $null;                    Ambiguous = $true;  MatchedVia = 'UPN prefix' } }
    return [PSCustomObject]@{ User = $null; Ambiguous = $false; MatchedVia = $null }
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
#
# Three parallel row-sets from one pass over $admins: the unfiltered account
# inventory (every admin account, so a zero-privilege one is never invisible),
# and the two plane-specific worklists (only accounts actually holding a role
# in that plane). No extra Graph/ARG calls - same data collected above, just
# projected three ways.
# --------------------------------------------------------------------------
function Get-TierString($role) {
    $t = Get-Tier $role
    # Cast to string: mixes int (a tiered role held) with '' (no tiered role) - Sort-Object
    # on a column mixing types throws under $ErrorActionPreference = 'Stop'.
    if ($null -eq $t) { '' } else { "$t" }
}

$now = Get-Date
$accountRows = [System.Collections.Generic.List[object]]::new()
$entraRows   = [System.Collections.Generic.List[object]]::new()
$rbacRows    = [System.Collections.Generic.List[object]]::new()

foreach ($a in $admins) {

    $base = if ($a.UserPrincipalName -match $BaseUsernameCapture) { $Matches[1].ToLower() }
            else { ($a.UserPrincipalName -split '@')[0].ToLower() }
    $stdResolution = Resolve-StandardAccount -Base $base
    $std = $stdResolution.User
    $stdAmbiguous = $stdResolution.Ambiguous

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
    $entraTier = Get-TierString $highestEntra

    $entraGroupGrants = @($actGrants + $eligGrants | Where-Object { $_.ViaGroupId })
    $entraGroupNames  = @($entraGroupGrants | ForEach-Object { $_.ViaGroup } | Sort-Object -Unique)
    $entraGroupIds    = @($entraGroupGrants | ForEach-Object { $_.ViaGroupId } | Sort-Object -Unique)
    $entraDirectCount = @($actGrants + $eligGrants | Where-Object { -not $_.ViaGroupId }).Count
    $entraGroupCount  = $entraGroupGrants.Count
    $entraRoute = if ($entraGroupCount -gt 0 -and $entraDirectCount -gt 0) { 'Direct + Group' }
                  elseif ($entraGroupCount -gt 0) { 'Group only' }
                  elseif ($entraDirectCount -gt 0) { 'Direct only' } else { '' }

    # Non-tenant-wide directory scopes, e.g. a role limited to one Administrative Unit
    $scopes = @($actGrants + $eligGrants | Where-Object { $_.Scope -and $_.Scope -ne 'Tenant-wide' } |
                ForEach-Object { $_.Scope } | Sort-Object -Unique)

    $az = @(if ($azByPrincipal.ContainsKey($a.Id)) { $azByPrincipal[$a.Id] })
    $azStrings = @($az | ForEach-Object {
        $t = "$($_.roleName) @ $(Get-ShortScope $_.scope)"
        if ($_.ViaGroup) { $t += " (via $($_.ViaGroup))" }
        $t
    } | Sort-Object -Unique)
    $highestAz = Get-HighestRole @($az.roleName)
    $azTier = Get-TierString $highestAz
    $broad = if ($az | Where-Object { (Get-ScopeKind $_.scope) -in @('Subscription','ManagementGroup') }) { 'Yes' } else { 'No' }

    $azGroupGrants = @($az | Where-Object { $_.ViaGroupId })
    $azGroupNames  = @($azGroupGrants | ForEach-Object { $_.ViaGroup } | Sort-Object -Unique)
    $azGroupIds    = @($azGroupGrants | ForEach-Object { $_.ViaGroupId } | Sort-Object -Unique)
    $azDirectCount = @($az | Where-Object { -not $_.ViaGroupId }).Count
    $azGroupCount  = $azGroupGrants.Count
    $azRoute = if ($azGroupCount -gt 0 -and $azDirectCount -gt 0) { 'Direct + Group' }
               elseif ($azGroupCount -gt 0) { 'Group only' }
               elseif ($azDirectCount -gt 0) { 'Direct only' } else { '' }

    $tiers = @(Get-Tier $highestEntra; Get-Tier $highestAz) | Where-Object { $null -ne $_ }
    $overallTier = if ($tiers) { "$(($tiers | Measure-Object -Minimum).Minimum)" } else { '' }

    $hasEntra = ($act.Count -gt 0 -or $elig.Count -gt 0)
    $hasRbac  = ($azStrings.Count -gt 0)

    $m  = $mfa[$a.Id]
    $sa = $a.SignInActivity
    $li = if ($sa -and $sa.LastSignInDateTime) { [datetime]$sa.LastSignInDateTime } else { $null }

    # Identity/credential columns are common to all three rows, built once
    $identity = [ordered]@{
        'Admin UPN'           = $a.UserPrincipalName
        'Display Name'        = $a.DisplayName
        'Object ID'           = $a.Id
        'Base Username'       = $base
        'Enabled'             = if ($a.AccountEnabled) { 'Yes' } else { 'No' }
        'Created'             = if ($a.CreatedDateTime) { ([datetime]$a.CreatedDateTime).ToString('dd/MM/yyyy') } else { '' }
        'Last Sign-In'        = if ($li) { $li.ToString('dd/MM/yyyy') } else { '' }
        'MFA Registered'      = if ($m) { if ($m.Registered) { 'Yes' } else { 'No' } } else { 'Unknown' }
        'Phishing Resistant'  = if ($m) { if ($m.PhishResistant) { 'Yes' } else { 'No' } } else { 'Unknown' }
        'Auth Methods'        = if ($m) { $m.Methods } else { '' }
    }
    # 'Ambiguous' takes priority over both 'Yes'/'No' and 'NOT FOUND': $std is $null
    # for an ambiguous key (it was deliberately excluded from resolution above), so
    # without this check it would read as a plain NOT FOUND - indistinguishable from
    # a genuine orphan, when what actually happened is "found more than one, didn't
    # guess." The candidate list shown depends on which path was ambiguous - SAM or
    # UPN prefix - so the reviewer sees the actual accounts that collided.
    $ambiguousCandidates = if ($stdAmbiguous -and $stdResolution.MatchedVia -eq 'SAM') { $standardCandidatesBySam[$base] }
                           elseif ($stdAmbiguous) { $standardCandidatesByPrefix[$base] }
                           else { $null }
    $standard = [ordered]@{
        'Standard Account UPN'  = if ($stdAmbiguous) { ($ambiguousCandidates.UserPrincipalName -join '; ') } elseif ($std) { $std.UserPrincipalName } else { '' }
        'Standard Acct Enabled' = if ($stdAmbiguous) { 'Ambiguous' } elseif ($std) { if ($std.AccountEnabled) { 'Yes' } else { 'No' } } else { 'NOT FOUND' }
        'Person Display Name'   = if ($std) { $std.DisplayName } else { '' }
        'Department'            = if ($std) { $std.Department } else { $a.Department }
        'Job Title'             = if ($std) { $std.JobTitle } else { $a.JobTitle }
    }

    $accountRows.Add([PSCustomObject]([ordered]@{} + $identity + [ordered]@{
        'Highest Entra Role' = $highestEntra
        'Highest Azure Role' = $highestAz
        'Overall Tier'       = $overallTier
    } + $standard))

    if ($hasEntra) {
        $entraRows.Add([PSCustomObject]([ordered]@{} + $identity + [ordered]@{
            'Entra Roles (Active)'   = if ($act.Count)  { $act -join '; ' }  else { 'None' }
            'Entra Roles (Eligible)' = if ($elig.Count) { $elig -join '; ' } else { 'None' }
            'Active Role Count'      = $act.Count
            'Eligible Role Count'    = $elig.Count
            'Highest Entra Role'     = $highestEntra
            'Entra Tier'             = $entraTier
            'Assignment Route'       = $entraRoute
            'Granting Groups'        = if ($entraGroupNames.Count) { $entraGroupNames -join '; ' } else { '' }
            'Granting Group IDs'     = if ($entraGroupIds.Count)   { $entraGroupIds   -join '; ' } else { '' }
            'Direct Assignments'     = $entraDirectCount
            'Group Assignments'      = $entraGroupCount
            'Directory Scopes'       = if ($scopes.Count) { $scopes -join '; ' } else { 'Tenant-wide' }
            'Also Holds Azure RBAC'  = if ($hasRbac) { 'Yes' } else { 'No' }
        } + $standard))
    }

    if ($hasRbac) {
        $rbacRows.Add([PSCustomObject]([ordered]@{} + $identity + [ordered]@{
            'Azure RBAC Roles'     = $azStrings -join '; '
            'Highest Azure Role'   = $highestAz
            'Azure Tier'           = $azTier
            'Sub or MG Scoped'     = $broad
            'Assignment Route'     = $azRoute
            'Granting Groups'      = if ($azGroupNames.Count) { $azGroupNames -join '; ' } else { '' }
            'Granting Group IDs'   = if ($azGroupIds.Count)   { $azGroupIds   -join '; ' } else { '' }
            'Direct Assignments'   = $azDirectCount
            'Group Assignments'    = $azGroupCount
            'Also Holds Entra Role'= if ($hasEntra) { 'Yes' } else { 'No' }
        } + $standard))
    }
}

$accountRows | Sort-Object @{E={if ($_.'Overall Tier' -eq '') { [int]::MaxValue } else { [int]$_.'Overall Tier' }}}, 'Admin UPN' |
    Export-Csv -Path $CloudAccountsOutputPath -NoTypeInformation -Encoding UTF8

$entraRows | Sort-Object @{E={if ($_.'Entra Tier' -eq '') { [int]::MaxValue } else { [int]$_.'Entra Tier' }}}, @{E={$_.'Active Role Count'};Descending=$true}, 'Admin UPN' |
    Export-Csv -Path $EntraOutputPath -NoTypeInformation -Encoding UTF8

$rbacRows | Sort-Object @{E={if ($_.'Azure Tier' -eq '') { [int]::MaxValue } else { [int]$_.'Azure Tier' }}}, @{E={$_.'Direct Assignments'+$_.'Group Assignments'};Descending=$true}, 'Admin UPN' |
    Export-Csv -Path $AzureRbacOutputPath -NoTypeInformation -Encoding UTF8

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
    # $adminByPrefix is keyed by whatever BaseUsernameCapture extracted from each
    # admin's own UPN - which, in an org that names cloud admins after the on-prem
    # SamAccountName (see the standard-account matching above), is a SAM-shaped
    # value like 'wredmo', not this user's UPN prefix ('wesley.redmond'). So a
    # normal user has to be checked against that map under BOTH of their own
    # possible identifiers - UPN prefix and OnPremisesSamAccountName - or an admin
    # account named the SAM way would never show as linked to its person here.
    $prefix = ($u.UserPrincipalName -split '@')[0].ToLower()
    $linkedAdmins = @(if ($adminByPrefix.ContainsKey($prefix)) { $adminByPrefix[$prefix] })
    if ($u.OnPremisesSamAccountName) {
        $sam = $u.OnPremisesSamAccountName.ToLower()
        if ($sam -ne $prefix -and $adminByPrefix.ContainsKey($sam)) {
            $linkedAdmins = @($linkedAdmins + $adminByPrefix[$sam] | Group-Object Id | ForEach-Object { $_.Group[0] })
        }
    }
    $sa = $u.SignInActivity
    $li = if ($sa -and $sa.LastSignInDateTime) { [datetime]$sa.LastSignInDateTime } else { $null }

    [PSCustomObject][ordered]@{
        'UPN'                       = $u.UserPrincipalName
        'Display Name'              = $u.DisplayName
        'Object ID'                 = $u.Id
        'Enabled'                   = if ($u.AccountEnabled) { 'Yes' } else { 'No' }
        'User Type'                 = $u.UserType
        'On-Prem Synced'            = if ($u.OnPremisesSyncEnabled) { 'Yes' } else { 'No' }
        'OnPrem SAM'                = $u.OnPremisesSamAccountName
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
$noPrivEither = @($accountRows | Where-Object { $_.'Highest Entra Role' -eq 'None' -and $_.'Highest Azure Role' -eq 'None' })
$orphaned     = @($accountRows | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })
$ambiguous    = @($accountRows | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -eq 'Ambiguous' })
$dormant      = @($accountRows | Where-Object { -not $_.'Last Sign-In' -and $_.Enabled -eq 'Yes' })
$noMfa        = @($accountRows | Where-Object { $_.'MFA Registered' -eq 'No' -and $_.Enabled -eq 'Yes' })

Write-Host "`nWritten to $CloudAccountsOutputPath" -ForegroundColor Green
Write-Host "  Cloud admin accounts                 : $($accountRows.Count)"
if ($orphaned.Count) {
    Write-Host "  ORPHANED - admin enabled, standard account disabled or missing : $($orphaned.Count)" -ForegroundColor Red
    Write-Host "    Likely leavers. Admin accounts are separate objects and are routinely missed at offboarding."
}
if ($ambiguous.Count) {
    Write-Host "  AMBIGUOUS standard account (same prefix, multiple domains) : $($ambiguous.Count)" -ForegroundColor Yellow
    Write-Host "    Not counted as orphaned or clean either way - see 'Standard Account UPN' on these rows for"
    Write-Host "    the candidates found, and pass -StandardAccountDomain if these are genuinely different people."
}
if ($noPrivEither.Count) {
    Write-Host "  Holding NO privilege in either plane  : $($noPrivEither.Count)" -ForegroundColor Yellow
    Write-Host "    Privilege was removed and the account wasn't, or it never held any. Not on the Entra or"
    Write-Host "    Azure RBAC worklists below - this account inventory is the only place it's visible."
}
if ($noMfa.Count)   { Write-Host "  Enabled with NO MFA registered        : $($noMfa.Count)" -ForegroundColor Red }
if ($dormant.Count) { Write-Host "  Enabled but never signed in            : $($dormant.Count)" }

$entraT0       = @($entraRows | Where-Object { $_.'Entra Tier' -eq 0 })
$entraStanding = @($entraRows | Where-Object { [int]$_.'Active Role Count' -gt 0 })
$entraNoPhish  = @($entraRows | Where-Object { $_.'Phishing Resistant' -ne 'Yes' -and $_.Enabled -eq 'Yes' })
$entraViaGroupOnly = @($entraRows | Where-Object { $_.'Assignment Route' -eq 'Group only' })
$entraAnyGroup     = @($entraRows | Where-Object { [int]$_.'Group Assignments' -gt 0 })
$entraScoped       = @($entraRows | Where-Object { $_.'Directory Scopes' -ne 'Tenant-wide' })
$entraAlsoRbac     = @($entraRows | Where-Object { $_.'Also Holds Azure RBAC' -eq 'Yes' })

Write-Host "`nWritten to $EntraOutputPath" -ForegroundColor Green
Write-Host "  Accounts holding an Entra role        : $($entraRows.Count)"
Write-Host "  Tier 0 (control plane)                : $($entraT0.Count)" -ForegroundColor Yellow
Write-Host "  Holding STANDING (permanent) roles    : $($entraStanding.Count)" -ForegroundColor Yellow
Write-Host "  Enabled without phishing-resistant MFA : $($entraNoPhish.Count)" -ForegroundColor Yellow
if ($entraAnyGroup.Count) {
    Write-Host "  Holding roles via group membership     : $($entraAnyGroup.Count)" -ForegroundColor Yellow
    Write-Host "    $($entraViaGroupOnly.Count) of these hold NO direct assignment at all - they would have been"
    Write-Host "    invisible to a report that matched only on the user's own object ID."
}
if ($entraScoped.Count) {
    Write-Host "  Roles scoped to an Administrative Unit : $($entraScoped.Count)"
    Write-Host "    Narrower than tenant-wide. Do not read these as full-tenant privilege."
}
if ($entraAlsoRbac.Count) {
    Write-Host "  Also holds an Azure RBAC role          : $($entraAlsoRbac.Count)"
    Write-Host "    Coordinate with whoever owns Azure-RBAC-Admins.csv before closing out remediation here."
}

$rbacT0           = @($rbacRows | Where-Object { $_.'Azure Tier' -eq 0 })
$rbacNoPhish      = @($rbacRows | Where-Object { $_.'Phishing Resistant' -ne 'Yes' -and $_.Enabled -eq 'Yes' })
$rbacViaGroupOnly = @($rbacRows | Where-Object { $_.'Assignment Route' -eq 'Group only' })
$rbacAnyGroup     = @($rbacRows | Where-Object { [int]$_.'Group Assignments' -gt 0 })
$rbacBroad        = @($rbacRows | Where-Object { $_.'Sub or MG Scoped' -eq 'Yes' })
$rbacAlsoEntra    = @($rbacRows | Where-Object { $_.'Also Holds Entra Role' -eq 'Yes' })

Write-Host "`nWritten to $AzureRbacOutputPath" -ForegroundColor Green
Write-Host "  Accounts holding an Azure RBAC role   : $($rbacRows.Count)"
Write-Host "  Tier 0 (control plane)                : $($rbacT0.Count)" -ForegroundColor Yellow
Write-Host "  Enabled without phishing-resistant MFA : $($rbacNoPhish.Count)" -ForegroundColor Yellow
if ($rbacAnyGroup.Count) {
    Write-Host "  Holding roles via group membership     : $($rbacAnyGroup.Count)" -ForegroundColor Yellow
    Write-Host "    $($rbacViaGroupOnly.Count) of these hold NO direct assignment at all."
}
if ($rbacBroad.Count) {
    Write-Host "  Sub or MG scoped                       : $($rbacBroad.Count)"
    Write-Host "    Covers every resource in the scope, including ones created next year."
}
if ($rbacAlsoEntra.Count) {
    Write-Host "  Also holds an Entra role                : $($rbacAlsoEntra.Count)"
    Write-Host "    Coordinate with whoever owns Entra-Admins.csv before closing out remediation here."
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

Write-Host "`nNext: paste Cloud Admin Accounts into the 'Cloud Admin Accounts' tab at cell A2 (columns A-R)." -ForegroundColor Cyan
Write-Host "      paste Entra Admins into the 'Entra Admins' tab at cell A2 (columns A-AB)." -ForegroundColor Cyan
Write-Host "      paste Azure RBAC Admins into the 'Azure RBAC Admins' tab at cell A2 (columns A-Y)." -ForegroundColor Cyan
Write-Host "      paste Normal Users into a 'Normal Users' tab at cell A2 (columns A-M), if you want it in the workbook." -ForegroundColor Cyan

<#
.SYNOPSIS
    Builds a flat Object ID -> Conditional Access exclusion map for the Entra ID
    Service Identity Inventory workbook.

.DESCRIPTION
    Reads every Conditional Access policy in the tenant and extracts:
      - excludeGroups           (expanded transitively, so nested groups are caught)
      - excludeUsers            (direct user / special-token exclusions)
      - excludeRoles            (optional; directory role members)
      - excludeServicePrincipals (workload identity exclusions)

    Output is one row per Object ID, with every excluding group and every excluded
    policy concatenated, ready to paste into the "CA Exclusion Map" tab at cell A2.

    READ-ONLY. This script makes no changes to your tenant.

.PARAMETER OutputPath
    Where to write the CSV. Defaults to .\CA-Exclusion-Map.csv

.PARAMETER IncludeReportOnly
    Include policies in enabledForReportingButNotEnforced state. Off by default,
    because a report-only exclusion is not yet a live control gap - but it is worth
    running with this switch before you promote a policy to enforced.

.PARAMETER IncludeRoleExclusions
    Expand excludeRoles into their current member Object IDs. Off by default because
    role membership is dynamic (especially with PIM) and the snapshot ages quickly.

.PARAMETER TenantId
    Optional tenant to connect to.

.EXAMPLE
    .\Build-CAExclusionMap.ps1 -OutputPath .\CA-Exclusion-Map.csv

.EXAMPLE
    .\Build-CAExclusionMap.ps1 -IncludeReportOnly -IncludeRoleExclusions -Verbose

.NOTES
    Requires the Microsoft.Graph PowerShell SDK:
        Install-Module Microsoft.Graph -Scope CurrentUser

    Required delegated scopes (all read-only):
        Policy.Read.All, Group.Read.All, Directory.Read.All,
        Application.Read.All, RoleManagement.Read.Directory

    Test against a non-production tenant first. Graph SDK cmdlet surface changes
    between major versions - verify property names if you are on an older release.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\CA-Exclusion-Map.csv",
    [switch]$IncludeReportOnly,
    [switch]$IncludeRoleExclusions,
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

$RequiredScopes = @(
    'Policy.Read.All'
    'Group.Read.All'
    'Directory.Read.All'
    'Application.Read.All'
    'RoleManagement.Read.Directory'
)

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
$context = Get-MgContext
if (-not $context) {
    Write-Verbose "Connecting to Microsoft Graph..."
    if ($TenantId) { Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantId | Out-Null }
    else           { Connect-MgGraph -Scopes $RequiredScopes | Out-Null }
    $context = Get-MgContext
}

$missingScopes = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }
if ($missingScopes) {
    Write-Warning "Session is missing scopes: $($missingScopes -join ', '). Some exclusions may not resolve. Reconnect with: Connect-MgGraph -Scopes $($RequiredScopes -join ',')"
}

Write-Host "Connected to tenant $($context.TenantId) as $($context.Account)" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Caches - a single excluding group is usually referenced by many policies
# ---------------------------------------------------------------------------
$groupMemberCache = @{}
$groupNameCache   = @{}
$objectCache      = @{}
$unresolved       = [System.Collections.Generic.List[object]]::new()

$GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

function Get-GroupDisplayName {
    param([string]$GroupId)
    if ($groupNameCache.ContainsKey($GroupId)) { return $groupNameCache[$GroupId] }
    try   { $name = (Get-MgGroup -GroupId $GroupId -Property Id,DisplayName).DisplayName }
    catch { $name = "UNRESOLVED GROUP ($GroupId)"; $unresolved.Add([PSCustomObject]@{ Type='Group'; Id=$GroupId; Reason=$_.Exception.Message }) }
    $groupNameCache[$GroupId] = $name
    return $name
}

function Get-GroupMembersTransitive {
    param([string]$GroupId)
    if ($groupMemberCache.ContainsKey($GroupId)) { return $groupMemberCache[$GroupId] }
    $members = @()
    try {
        # Transitive expansion resolves nested groups, which is where the
        # surprise exclusions almost always live.
        $members = Get-MgGroupTransitiveMember -GroupId $GroupId -All
    }
    catch {
        Write-Warning "Could not expand group $GroupId : $($_.Exception.Message)"
        $unresolved.Add([PSCustomObject]@{ Type='GroupExpansion'; Id=$GroupId; Reason=$_.Exception.Message })
    }
    $groupMemberCache[$GroupId] = $members
    return $members
}

function Resolve-DirectoryObject {
    param([string]$ObjectId)
    if ($objectCache.ContainsKey($ObjectId)) { return $objectCache[$ObjectId] }
    $result = [PSCustomObject]@{ DisplayName = "UNRESOLVED ($ObjectId)"; IdentityType = 'Unknown' }
    try {
        $obj  = Get-MgDirectoryObject -DirectoryObjectId $ObjectId
        $ap   = $obj.AdditionalProperties
        $type = ($ap['@odata.type'] -replace '#microsoft\.graph\.', '')
        $name = $ap['displayName']
        if ($type -eq 'servicePrincipal') {
            $spType = $ap['servicePrincipalType']
            if (-not $spType) {
                try { $spType = (Get-MgServicePrincipal -ServicePrincipalId $ObjectId -Property Id,ServicePrincipalType).ServicePrincipalType } catch { }
            }
            $type = if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
        }
        elseif ($type) {
            # user -> User, group -> Group
            $type = $type.Substring(0,1).ToUpper() + $type.Substring(1)
        }
        $result = [PSCustomObject]@{
            DisplayName  = if ($name) { $name } else { "(no display name)" }
            IdentityType = if ($type) { $type } else { 'Unknown' }
        }
    }
    catch {
        $unresolved.Add([PSCustomObject]@{ Type='DirectoryObject'; Id=$ObjectId; Reason=$_.Exception.Message })
    }
    $objectCache[$ObjectId] = $result
    return $result
}

# ---------------------------------------------------------------------------
# Walk the policies
# ---------------------------------------------------------------------------
Write-Verbose "Retrieving Conditional Access policies..."
$policies = Get-MgIdentityConditionalAccessPolicy -All

$records = [System.Collections.Generic.List[object]]::new()

function Add-Record {
    param($ObjectId, $DisplayName, $IdentityType, $Mechanism, $GroupName, $PolicyName, $PolicyState)
    $records.Add([PSCustomObject]@{
        ObjectId     = $ObjectId
        DisplayName  = $DisplayName
        IdentityType = $IdentityType
        Mechanism    = $Mechanism
        GroupName    = $GroupName
        PolicyName   = $PolicyName
        PolicyState  = $PolicyState
    })
}

$considered = 0
foreach ($policy in $policies) {

    if ($policy.State -eq 'disabled') {
        Write-Verbose "Skipping disabled policy: $($policy.DisplayName)"
        continue
    }
    if ($policy.State -eq 'enabledForReportingButNotEnforced' -and -not $IncludeReportOnly) {
        Write-Verbose "Skipping report-only policy: $($policy.DisplayName)"
        continue
    }
    $considered++
    Write-Verbose "Processing: $($policy.DisplayName) [$($policy.State)]"

    $users = $policy.Conditions.Users

    # --- Excluded groups, expanded transitively ---------------------------
    foreach ($groupId in @($users.ExcludeGroups)) {
        if (-not $groupId) { continue }
        $groupName = Get-GroupDisplayName -GroupId $groupId
        $members   = Get-GroupMembersTransitive -GroupId $groupId

        if (-not $members -or $members.Count -eq 0) {
            Write-Verbose "  Group '$groupName' has no members (or could not be expanded)."
            continue
        }

        foreach ($m in $members) {
            $ap       = $m.AdditionalProperties
            $odata    = ($ap['@odata.type'] -replace '#microsoft\.graph\.', '')
            if ($odata -eq 'group') { continue }   # the nested group object itself; its members are already flattened

            $type = switch ($odata) {
                'user'             { 'User' }
                'servicePrincipal' {
                    $spType = $ap['servicePrincipalType']
                    if (-not $spType) {
                        try { $spType = (Get-MgServicePrincipal -ServicePrincipalId $m.Id -Property Id,ServicePrincipalType).ServicePrincipalType } catch { }
                    }
                    if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
                }
                'device'           { 'Device' }
                default            { if ($odata) { $odata } else { 'Unknown' } }
            }

            Add-Record -ObjectId $m.Id `
                       -DisplayName $ap['displayName'] `
                       -IdentityType $type `
                       -Mechanism 'Group membership' `
                       -GroupName $groupName `
                       -PolicyName $policy.DisplayName `
                       -PolicyState $policy.State
        }
    }

    # --- Directly excluded users -----------------------------------------
    foreach ($userId in @($users.ExcludeUsers)) {
        if (-not $userId) { continue }
        if ($userId -notmatch $GuidPattern) {
            # Special tokens such as GuestsOrExternalUsers or All
            Add-Record -ObjectId $userId -DisplayName $userId -IdentityType 'SpecialToken' `
                       -Mechanism 'Direct exclusion' -GroupName $null `
                       -PolicyName $policy.DisplayName -PolicyState $policy.State
            continue
        }
        $o = Resolve-DirectoryObject -ObjectId $userId
        Add-Record -ObjectId $userId -DisplayName $o.DisplayName -IdentityType $o.IdentityType `
                   -Mechanism 'Direct exclusion' -GroupName $null `
                   -PolicyName $policy.DisplayName -PolicyState $policy.State
    }

    # --- Excluded workload identities (service principals) ----------------
    $clientApps = $policy.Conditions.ClientApplications
    if ($clientApps) {
        foreach ($spId in @($clientApps.ExcludeServicePrincipals)) {
            if (-not $spId) { continue }
            if ($spId -notmatch $GuidPattern) {
                Add-Record -ObjectId $spId -DisplayName $spId -IdentityType 'SpecialToken' `
                           -Mechanism 'Direct exclusion' -GroupName $null `
                           -PolicyName $policy.DisplayName -PolicyState $policy.State
                continue
            }
            $o = Resolve-DirectoryObject -ObjectId $spId
            Add-Record -ObjectId $spId -DisplayName $o.DisplayName -IdentityType $o.IdentityType `
                       -Mechanism 'Direct exclusion' -GroupName $null `
                       -PolicyName $policy.DisplayName -PolicyState $policy.State
        }
    }

    # --- Excluded directory roles (optional) ------------------------------
    if ($IncludeRoleExclusions) {
        foreach ($roleTemplateId in @($users.ExcludeRoles)) {
            if (-not $roleTemplateId) { continue }
            try {
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleTemplateId'" -ErrorAction Stop | Select-Object -First 1
                if (-not $role) { continue }   # role not activated in this tenant, so it has no members
                $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                foreach ($rm in $roleMembers) {
                    $ap    = $rm.AdditionalProperties
                    $odata = ($ap['@odata.type'] -replace '#microsoft\.graph\.', '')
                    $type  = if ($odata -eq 'user') { 'User' } elseif ($odata -eq 'servicePrincipal') { 'ServicePrincipal' } else { $odata }
                    Add-Record -ObjectId $rm.Id -DisplayName $ap['displayName'] -IdentityType $type `
                               -Mechanism 'Role membership' -GroupName "ROLE: $($role.DisplayName)" `
                               -PolicyName $policy.DisplayName -PolicyState $policy.State
                }
            }
            catch {
                Write-Warning "Could not expand role template $roleTemplateId : $($_.Exception.Message)"
                $unresolved.Add([PSCustomObject]@{ Type='Role'; Id=$roleTemplateId; Reason=$_.Exception.Message })
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Flatten to one row per Object ID
# ---------------------------------------------------------------------------
$snapshot = Get-Date -Format 'dd/MM/yyyy'

$rows = $records | Group-Object ObjectId | ForEach-Object {
    $g          = $_.Group
    $policyList = @($g | Select-Object -ExpandProperty PolicyName -Unique | Sort-Object)
    $groupList  = @($g | Where-Object { $_.GroupName } | Select-Object -ExpandProperty GroupName -Unique | Sort-Object)
    $mechanisms = @($g | Select-Object -ExpandProperty Mechanism -Unique | Sort-Object)
    $states     = @($g | Select-Object -ExpandProperty PolicyState -Unique | Sort-Object)

    [PSCustomObject]@{
        ObjectId           = $_.Name
        DisplayName        = ($g | Select-Object -First 1 -ExpandProperty DisplayName)
        IdentityType       = ($g | Select-Object -First 1 -ExpandProperty IdentityType)
        ExclusionMechanism = ($mechanisms -join ' + ')
        ExclusionGroups    = ($groupList  -join '; ')
        ExcludedPolicies   = ($policyList -join '; ')
        PolicyCount        = $policyList.Count
        PolicyStates       = ($states -join '; ')
        SnapshotDate       = $snapshot
    }
} | Sort-Object IdentityType, DisplayName

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "CA exclusion map written to $OutputPath" -ForegroundColor Green
Write-Host "  Policies in tenant           : $($policies.Count)"
Write-Host "  Policies considered          : $considered  $(if(-not $IncludeReportOnly){'(report-only excluded - use -IncludeReportOnly to include)'})"
Write-Host "  Excluding groups expanded    : $($groupMemberCache.Keys.Count)"
Write-Host "  Unique excluded identities   : $($rows.Count)"
Write-Host ""
$rows | Group-Object IdentityType | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("    {0,-18} {1}" -f $_.Name, $_.Count) }

$direct = @($rows | Where-Object { $_.ExclusionMechanism -like '*Direct*' })
if ($direct.Count -gt 0) {
    Write-Host ""
    Write-Host "  $($direct.Count) identity/identities are excluded DIRECTLY rather than via a group." -ForegroundColor Yellow
    Write-Host "  These bypass group-based governance entirely and are worth converting to group membership." -ForegroundColor Yellow
}

if ($unresolved.Count -gt 0) {
    $unresolvedPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + "unresolved.csv"
    $unresolved | Export-Csv -Path $unresolvedPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "  $($unresolved.Count) object(s) could not be resolved. Details: $unresolvedPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next step: open the CSV, copy everything below the header row," -ForegroundColor Cyan
Write-Host "then paste into the 'CA Exclusion Map' tab at cell A2 (columns A-I only)." -ForegroundColor Cyan

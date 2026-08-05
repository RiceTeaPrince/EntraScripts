<#
.SYNOPSIS
    Builds the Azure Resource Map for the Entra ID Service Identity Inventory workbook:
    every Azure RBAC assignment plus the Azure resource behind each managed identity.

.DESCRIPTION
    Azure RBAC lives in Azure Resource Manager, not Microsoft Graph. This script uses
    Azure Resource Graph, which queries every subscription in a single call rather than
    looping Get-AzRoleAssignment per subscription - the difference between minutes and
    hours on a tenant of any size.

    Output: one row per principal, ready to paste into the "Azure Resource Map" tab
    at cell A2 (columns A-O only; column P is a formula).

    READ-ONLY.

.PARAMETER OutputPath
    CSV path. Defaults to .\Azure-Resource-Map.csv

.PARAMETER UseTenantScope
    Query across the whole tenant rather than only subscriptions in the current context.
    Requires tenant-level read access.

.PARAMETER ManagementGroup
    Restrict the query to a management group.

.EXAMPLE
    .\Build-AzureResourceMap.ps1 -UseTenantScope -Verbose

.NOTES
    Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser

    Needs Reader at the scopes you want covered. Role assignments you cannot read
    simply will not appear - if the numbers look low, check your scope coverage first.

    Resource Graph returns a point-in-time snapshot with a short indexing lag.
    Assignments made in the last few minutes may not appear.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\Azure-Resource-Map.csv",
    [switch]$UseTenantScope,
    [string]$ManagementGroup
)

$ErrorActionPreference = 'Stop'

foreach ($m in @('Az.Accounts','Az.ResourceGraph')) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Module $m is not installed. Run: Install-Module $m -Scope CurrentUser"
    }
    Import-Module $m -ErrorAction Stop
}

if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
$ctx = Get-AzContext
Write-Host "Azure context: $($ctx.Account.Id) / tenant $($ctx.Tenant.Id)" -ForegroundColor Cyan

# --------------------------------------------------------------------------
# Paged Resource Graph query - Search-AzGraph caps at 1000 rows per page
# --------------------------------------------------------------------------
function Invoke-Graph {
    param([string]$Query)
    $results = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    do {
        $splat = @{ Query = $Query; First = 1000 }
        if ($skipToken)       { $splat.SkipToken = $skipToken }
        if ($UseTenantScope)  { $splat.UseTenantScope = $true }
        if ($ManagementGroup) { $splat.ManagementGroup = $ManagementGroup }
        $page = Search-AzGraph @splat
        if ($page) { $results.AddRange(@($page)) }
        $skipToken = $page.SkipToken
    } while ($skipToken)
    return $results
}

# --------------------------------------------------------------------------
# 1. Role assignments, joined to role definitions for readable names
# --------------------------------------------------------------------------
Write-Host "Querying role assignments..." -ForegroundColor Cyan
$assignmentQuery = @'
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType),
         roleDefId = tolower(tostring(properties.roleDefinitionId)),
         scope = tostring(properties.scope)
| join kind=leftouter (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend roleDefId = tolower(id),
             roleName = tostring(properties.roleName),
             roleType = tostring(properties.type)
    | project roleDefId, roleName, roleType
) on roleDefId
| project principalId, principalType, roleName, roleType, scope, subscriptionId
'@
$assignments = Invoke-Graph -Query $assignmentQuery
Write-Host "  $($assignments.Count) role assignment(s)"

# --------------------------------------------------------------------------
# 2. Managed identity resources - user-assigned and system-assigned
# --------------------------------------------------------------------------
Write-Host "Querying managed identity resources..." -ForegroundColor Cyan
$uaQuery = @'
resources
| where type =~ 'microsoft.managedidentity/userassignedidentities'
| extend principalId = tostring(properties.principalId)
| where isnotempty(principalId)
| project principalId, resourceId = id, resourceType = type, resourceGroup,
          subscriptionId, location, tags
'@
$saQuery = @'
resources
| where isnotnull(identity) and isnotempty(tostring(identity.principalId))
| extend principalId = tostring(identity.principalId)
| project principalId, resourceId = id, resourceType = type, resourceGroup,
          subscriptionId, location, tags
'@
$miResources = @()
$miResources += Invoke-Graph -Query $uaQuery
$miResources += Invoke-Graph -Query $saQuery
Write-Host "  $($miResources.Count) identity-bearing resource(s)"

# --------------------------------------------------------------------------
# 3. Subscription names
# --------------------------------------------------------------------------
$subMap = @{}
try {
    Invoke-Graph -Query "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name" |
        ForEach-Object { $subMap[$_.subscriptionId] = $_.name }
} catch { Write-Warning "Could not resolve subscription names: $($_.Exception.Message)" }

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
$RoleRank = @{
    'Owner' = 100; 'User Access Administrator' = 95; 'Role Based Access Control Administrator' = 90
    'Contributor' = 80; 'Key Vault Administrator' = 78; 'Storage Blob Data Owner' = 75
    'Key Vault Secrets Officer' = 72; 'Storage Blob Data Contributor' = 60
    'Key Vault Secrets User' = 50; 'Storage Blob Data Reader' = 30; 'Reader' = 20
}
function Get-RoleRank([string]$name) {
    if ($RoleRank.ContainsKey($name)) { return $RoleRank[$name] }
    if ($name -match 'Owner|Administrator')       { return 85 }
    if ($name -match 'Contributor|Write|Operator'){ return 55 }
    if ($name -match 'Reader|Read')               { return 25 }
    return 40
}
function Get-ScopeKind([string]$scope) {
    if ($scope -match '^/providers/Microsoft\.Management/managementGroups/') { return 'ManagementGroup' }
    if ($scope -match '^/subscriptions/[^/]+$')                              { return 'Subscription' }
    if ($scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$')         { return 'ResourceGroup' }
    return 'Resource'
}
function Get-ShortScope([string]$scope) {
    $kind = Get-ScopeKind $scope
    switch ($kind) {
        'ManagementGroup' { "MG:$($scope -replace '.*/managementGroups/','')" }
        'Subscription'    { $sid = $scope -replace '^/subscriptions/',''
                            if ($subMap.ContainsKey($sid)) { "SUBSCRIPTION:$($subMap[$sid])" } else { "SUBSCRIPTION:$sid" } }
        'ResourceGroup'   { "rg:$($scope -replace '.*/resourceGroups/','')" }
        default           { ($scope -split '/')[-1] }
    }
}
function Get-Tag($tags, [string[]]$names) {
    if (-not $tags) { return '' }
    foreach ($n in $names) {
        foreach ($k in $tags.Keys) { if ($k -ieq $n) { return $tags[$k] } }
    }
    return ''
}

# --------------------------------------------------------------------------
# Flatten to one row per principal
# --------------------------------------------------------------------------
$resourceByPrincipal = @{}
foreach ($r in $miResources) { if (-not $resourceByPrincipal.ContainsKey($r.principalId)) { $resourceByPrincipal[$r.principalId] = $r } }

$principalIds = @($assignments.principalId) + @($miResources.principalId) | Where-Object { $_ } | Sort-Object -Unique
$snapshot = Get-Date -Format 'dd/MM/yyyy'

$rows = foreach ($pid in $principalIds) {
    $mine = @($assignments | Where-Object { $_.principalId -eq $pid })
    $res  = $resourceByPrincipal[$pid]

    $roleStrings = @($mine | ForEach-Object { "$($_.roleName) @ $(Get-ShortScope $_.scope)" } | Sort-Object -Unique)
    $highest = if ($mine.Count -gt 0) {
        ($mine | Sort-Object { Get-RoleRank $_.roleName } -Descending | Select-Object -First 1).roleName
    } else { '' }
    $broad = if ($mine | Where-Object { (Get-ScopeKind $_.scope) -in @('Subscription','ManagementGroup') }) { 'Yes' } else { 'No' }

    $ptype = if ($mine.Count -gt 0) { ($mine | Select-Object -First 1).principalType } else { 'ManagedIdentity' }
    if ($res -and $res.resourceType -match 'userassignedidentities') { $ptype = 'ManagedIdentity' }

    $subId = if ($res) { $res.subscriptionId } elseif ($mine.Count -gt 0) { ($mine | Select-Object -First 1).subscriptionId } else { '' }
    $subName = if ($subId -and $subMap.ContainsKey($subId)) { $subMap[$subId] } else { $subId }

    [PSCustomObject][ordered]@{
        PrincipalId          = $pid
        PrincipalType        = $ptype
        DisplayName          = if ($res) { ($res.resourceId -split '/')[-1] } else { '' }
        AzureRoleAssignments = ($roleStrings -join '; ')
        HighestAzureRole     = $highest
        SubOrMgScoped        = $broad
        AssignmentCount      = $mine.Count
        AzureResourceId      = if ($res) { $res.resourceId }   else { '' }
        ResourceType         = if ($res) { $res.resourceType } else { '' }
        ResourceGroup        = if ($res) { $res.resourceGroup } else { '' }
        Subscription         = $subName
        Location             = if ($res) { $res.location } else { '' }
        OwnerTag             = if ($res) { Get-Tag $res.tags @('Owner','owner','ApplicationOwner','TechnicalOwner','Contact') } else { '' }
        CostCentreTag        = if ($res) { Get-Tag $res.tags @('CostCentre','CostCenter','costcentre','BillingCode') } else { '' }
        SnapshotDate         = $snapshot
    }
}

$rows | Sort-Object { Get-RoleRank $_.HighestAzureRole } -Descending |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
Write-Host "`nAzure Resource Map written to $OutputPath" -ForegroundColor Green
Write-Host "  Unique principals            : $($rows.Count)"
Write-Host "  Identity-bearing resources   : $($miResources.Count)"
Write-Host ""
$rows | Group-Object PrincipalType | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("    {0,-20} {1}" -f $_.Name, $_.Count) }

$owners = @($rows | Where-Object { $_.HighestAzureRole -in @('Owner','User Access Administrator') })
$broadS = @($rows | Where-Object { $_.SubOrMgScoped -eq 'Yes' })
Write-Host ""
Write-Host "  $($owners.Count) principal(s) hold Owner or User Access Administrator." -ForegroundColor Yellow
Write-Host "  $($broadS.Count) principal(s) have at least one subscription or management group scoped assignment." -ForegroundColor Yellow
$noTag = @($rows | Where-Object { $_.AzureResourceId -and -not $_.OwnerTag })
if ($noTag.Count -gt 0) {
    Write-Host "  $($noTag.Count) identity-bearing resource(s) carry no Owner tag - tag them and this column fills itself next run." -ForegroundColor Yellow
}

Write-Host "`nNext step: copy everything below the header row and paste into the" -ForegroundColor Cyan
Write-Host "'Azure Resource Map' tab at cell A2 (columns A-O only)." -ForegroundColor Cyan

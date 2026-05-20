#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications
#Requires -Version 7.0

<#
.SYNOPSIS
    Creates a custom app consent policy scoped to Graph Command Line Tools.
.DESCRIPTION
    Creates a permission grant policy that allows user consent only for
    Graph Command Line Tools, limited to three specific delegated permissions.
    Idempotent: deletes and recreates the policy if it already exists.
.NOTES
    Required Graph permissions: Policy.ReadWrite.PermissionGrant, Application.Read.All
#>

$ErrorActionPreference = 'Stop'

# --- Connect ---
# Policy.ReadWrite.PermissionGrant  : create/update/delete consent policies
# Application.Read.All              : look up service principals
Connect-MgGraph -Scopes "Policy.ReadWrite.PermissionGrant", "Application.Read.All" -NoWelcome

# --- Resolve permission IDs ---
# The scope definitions (GUIDs) live on the Microsoft Graph SP, not the CLI SP
$graphSpAppId = "00000003-0000-0000-c000-000000000000"
$graphSp      = Get-MgServicePrincipal -Filter "appId eq '$graphSpAppId'"

$permissionNames = @("Group.ReadWrite.All", "User.Read.All", "Directory.Read.All")
$permissionIds   = $graphSp.Oauth2PermissionScopes |
                   Where-Object { $_.Value -in $permissionNames } |
                   Select-Object -ExpandProperty Id

Write-Host "Resolved $($permissionIds.Count) permission ID(s) for: $($permissionNames -join ', ')"

# --- Delete existing policy if it exists (makes script re-runnable) ---
$policyId = "custom-graphcli-consent-policy"

try {
    Invoke-MgGraphRequest -Method DELETE `
        -Uri "https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies/$policyId"
    Write-Host "Existing policy deleted."
} catch {
    Write-Host "No existing policy found, proceeding with creation."
}

# --- Step 1: Create the empty policy shell ---
# The API does not accept 'includes' on the initial POST — conditions must be added separately
Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies" `
    -Body (@{
        id          = $policyId
        displayName = "Graph CLI Limited Consent Policy"
        description = "Allows user consent only for Graph Command Line Tools with specific delegated permissions."
    } | ConvertTo-Json)

Write-Host "Policy shell '$policyId' created. Adding include conditions..."

# --- Step 2: Add the include condition set ---
# permissionType = "delegated" targets OAuth2 (user-facing) scopes
# clientApplicationIds restricts consent to Graph Command Line Tools only
# permissions lists only the specific scope GUIDs resolved above
$graphCliAppId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/policies/permissionGrantPolicies/$policyId/includes" `
    -Body (@{
        permissionType           = "delegated"
        clientApplicationIds     = @($graphCliAppId)
        resourceApplication      = "00000003-0000-0000-c000-000000000000"
        permissionClassification = "all"
        permissions              = @($permissionIds)
    } | ConvertTo-Json)

Write-Host "Consent policy '$policyId' fully configured."

# --- Cleanup ---
Disconnect-MgGraph

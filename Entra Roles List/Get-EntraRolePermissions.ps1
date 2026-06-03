<#
    Get-EntraRolePermissions.ps1
    ----------------------------
    Pulls every built-in Entra ID role definition straight from Microsoft Graph and
    flattens it into a three-column CSV: one row per (role, permission) pair.

        Column 1  RoleDisplayName   e.g. Global Administrator
        Column 2  Permission        e.g. microsoft.directory/applications/standard.read
        Column 3  RoleType          Built-in | Custom

    Duplicate permissions across different roles are expected and intended.

    REQUIRES: Microsoft.Graph.Authentication and Microsoft.Graph.Identity.Governance
              (the Microsoft.Graph meta-module covers both). Global Reader is enough
              to read role definitions.

    USAGE:
      .\Get-EntraRolePermissions.ps1
      .\Get-EntraRolePermissions.ps1 -IncludeCustom
#>

param(
    [string] $OutputCsv = ".\EntraRolePermissions.csv",
    [switch] $IncludeCustom   # default: built-in roles only
)

Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -NoWelcome

$roles = Get-MgRoleManagementDirectoryRoleDefinition -All

$rows = foreach ($role in $roles) {

    if (-not $IncludeCustom -and -not $role.IsBuiltIn) { continue }

    $roleType = if ($role.IsBuiltIn) { "Built-in" } else { "Custom" }

    foreach ($perm in $role.RolePermissions) {
        foreach ($action in $perm.AllowedResourceActions) {
            [pscustomobject]@{
                RoleDisplayName = $role.DisplayName
                Permission      = $action
                RoleType        = $roleType
            }
        }
    }
}

$rows |
    Sort-Object RoleDisplayName, Permission |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ("Wrote {0} role-to-permission rows to {1}" -f $rows.Count, $OutputCsv)
Disconnect-MgGraph | Out-Null

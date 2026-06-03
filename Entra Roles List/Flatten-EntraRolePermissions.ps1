<#
    Flatten-EntraRolePermissions.ps1
    --------------------------------
    Reads a Microsoft Graph 'roleDefinitions' JSON export and flattens it into a
    three-column CSV: one row per (role, permission) pair.

        Column 1  RoleDisplayName   e.g. Global Administrator
        Column 2  Permission        e.g. microsoft.directory/applications/standard.read
        Column 3  RoleType          Built-in | Custom

    Duplicate permissions across different roles are expected and intended.
    NO PowerShell modules required - works with what you pull from Graph Explorer
    using Global Reader access.

    HOW TO GET THE JSON (Graph Explorer - developer.microsoft.com/graph/graph-explorer):
      GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=displayName,templateId,isBuiltIn,rolePermissions&$top=999
      Save the response body to a file, e.g. roledefs.json
      (Follow any @odata.nextLink and combine the 'value' arrays if results are paged.)

    USAGE:
      .\Flatten-EntraRolePermissions.ps1 -InputJson .\roledefs.json
      .\Flatten-EntraRolePermissions.ps1 -InputJson .\roledefs.json -IncludeCustom
#>

param(
    [Parameter(Mandatory)] [string] $InputJson,
    [string] $OutputCsv = ".\EntraRolePermissions.csv",
    [switch] $IncludeCustom   # by default, built-in roles only
)

if (-not (Test-Path $InputJson)) { throw "Input file not found: $InputJson" }

$raw   = Get-Content -Path $InputJson -Raw | ConvertFrom-Json
$roles = if ($null -ne $raw.value) { $raw.value } else { $raw }

$rows = foreach ($role in $roles) {

    if (-not $IncludeCustom -and ($role.isBuiltIn -eq $false)) { continue }

    $roleType = if ($role.isBuiltIn) { "Built-in" } else { "Custom" }

    foreach ($perm in $role.rolePermissions) {
        foreach ($action in $perm.allowedResourceActions) {
            [pscustomobject]@{
                RoleDisplayName = $role.displayName
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

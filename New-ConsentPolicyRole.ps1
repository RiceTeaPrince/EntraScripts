#Requires -Modules Microsoft.Graph.Identity.Governance
#Requires -Version 7.0

<#
.SYNOPSIS
    Creates a minimal custom Entra administrator role for assigning consent permission policies.
.DESCRIPTION
    Creates a custom directory role with only the permission required to assign
    an app consent permission grant policy. No other administrative permissions are included.
.EXAMPLE
    .\New-ConsentPolicyRole.ps1
.NOTES
    Required Graph scope: RoleManagement.ReadWrite.Directory
    The calling account must be a Privileged Role Administrator or Global Administrator.
#>

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory" -NoWelcome

New-MgRoleManagementDirectoryRoleDefinition -BodyParameter @{
    displayName     = "M365 Consent Policy Assigner"
    description     = "Used to assign the Graph CLI Limited Consent Policy to M365 users. No other permissions."
    isEnabled       = $true
    rolePermissions = @(@{
        allowedResourceActions = @("microsoft.directory/servicePrincipals/managePermissionGrantsForAll.custom-graphcli-consent-policy")
    })
    templateId      = [guid]::NewGuid().ToString()
}

Disconnect-MgGraph

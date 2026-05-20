Connect-MgGraph -Scopes "Policy.ReadWrite.PermissionGrant", "Application.Read.All"

$policy = New-MgPolicyPermissionGrantPolicy `
    -DisplayName "Graph CLI - Limited Delegated Consent" `
    -Description "Allow limited delegated Graph permissions for Graph CLI"

$params = @{
    displayName = "Graph CLI Limited Consent"
    description = "Allow limited delegated Graph permissions for Graph CLI"
    includes = @(
        @{
            clientApplicationIds = @(
                "14d82eec-204b-4c2f-b7e8-296a70dab67e"
            )

            resourceApplication = "00000003-0000-0000-c000-000000000000"

            permissionType = "delegated"

            permissions = @(
                "62a82d76-70ea-41e2-9197-370581804d09", # Group.ReadWrite.All
                "a154be20-db9c-4678-8ab7-66f6cc099a59", # User.Read.All
                "06da0dbc-49e2-44d2-8312-53f166ab848a"  # Directory.Read.All
            )
        }
    )
}

New-MgPolicyPermissionGrantPolicyInclude `
    -PermissionGrantPolicyId $policy.Id `
    -BodyParameter $params
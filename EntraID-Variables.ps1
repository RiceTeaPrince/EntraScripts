#Requires -Version 5.1
<#
.SYNOPSIS
    Shared variables file for Entra ID / Microsoft Graph PowerShell scripts.

.DESCRIPTION
    Central configuration file defining reusable variables for Entra ID tenant
    settings, Graph API endpoints, authentication, licensing, and common object
    attributes. Dot-source this file at the top of any script:

        . "$PSScriptRoot\EntraID-Variables.ps1"

.NOTES
    Update Section 1 (Tenant & App Registration) before use.
    All other sections can be consumed as-is or extended as needed.
#>

# ==============================================================================
# SECTION 1 — TENANT & APP REGISTRATION
# ==============================================================================
# Core identity values for your Entra ID tenant and the app registration used
# by your scripts to authenticate against Microsoft Graph.

$TenantId            = "8e349918-0edd-445d-91a0-40745f2547e3"   # Entra ID Tenant ID (GUID)
$TenantDomain        = "certificationswredmond.onmicrosoft.com"                 # Primary *.onmicrosoft.com domain
$TenantCustomDomain  = "contoso.com"                             # Vanity / verified custom domain

# App Registration — used for app-only (client credentials) auth
$AppClientId         = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # Application (client) ID
$AppClientSecret     = $null   # Set at runtime: $AppClientSecret = Read-Host -AsSecureString
$AppCertThumbprint   = ""      # Certificate thumbprint (alternative to secret)
$AppObjectId         = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # App registration Object ID

# Service Principal
$SpObjectId          = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # Enterprise app / SP Object ID


# ==============================================================================
# SECTION 2 — MICROSOFT GRAPH API
# ==============================================================================

$GraphBaseUrl        = "https://graph.microsoft.com"
$GraphVersion        = "v1.0"           # Change to "beta" for beta endpoints
$GraphApiRoot        = "$GraphBaseUrl/$GraphVersion"

# Common Graph endpoint shortcuts
$GraphEndpoints = @{
    Users               = "$GraphApiRoot/users"
    Groups              = "$GraphApiRoot/groups"
    Devices             = "$GraphApiRoot/devices"
    ServicePrincipals   = "$GraphApiRoot/servicePrincipals"
    Applications        = "$GraphApiRoot/applications"
    DirectoryRoles      = "$GraphApiRoot/directoryRoles"
    RoleDefinitions     = "$GraphApiRoot/roleManagement/directory/roleDefinitions"
    RoleAssignments     = "$GraphApiRoot/roleManagement/directory/roleAssignments"
    AuditLogs           = "$GraphApiRoot/auditLogs"
    SignInLogs          = "$GraphApiRoot/auditLogs/signIns"
    ConditionalAccess   = "$GraphApiRoot/identity/conditionalAccess/policies"
    NamedLocations      = "$GraphApiRoot/identity/conditionalAccess/namedLocations"
    Domains             = "$GraphApiRoot/domains"
    Organization        = "$GraphApiRoot/organization"
    SubscribedSkus      = "$GraphApiRoot/subscribedSkus"
    DirectoryObjects    = "$GraphApiRoot/directoryObjects"
    AdministrativeUnits = "$GraphApiRoot/administrativeUnits"
    AuthMethods         = "$GraphApiRoot/users/{id}/authentication/methods"
}

# OAuth / token endpoints
$AuthorityUrl        = "https://login.microsoftonline.com/$TenantId"
$TokenEndpoint       = "$AuthorityUrl/oauth2/v2.0/token"
$GraphScope          = "https://graph.microsoft.com/.default"


# ==============================================================================
# SECTION 3 — AUTHENTICATION SETTINGS
# ==============================================================================

# Preferred auth method: "ClientSecret" | "Certificate" | "ManagedIdentity" | "Interactive"
$AuthMethod          = "Certificate"

# Microsoft Graph PowerShell SDK — scopes for delegated (interactive) auth
$DelegatedScopes = @(
    "User.Read.All"
    "Group.ReadWrite.All"
    "Directory.ReadWrite.All"
    "AuditLog.Read.All"
    "Policy.Read.All"
    "RoleManagement.Read.All"
)


# ==============================================================================
# SECTION 4 — COMMON ENTRA ID OBJECT ATTRIBUTES
# ==============================================================================

# Default properties to retrieve for User objects (use with -Property or $select)
$UserSelectProperties = @(
    "id"
    "displayName"
    "userPrincipalName"
    "mail"
    "mailNickname"
    "givenName"
    "surname"
    "jobTitle"
    "department"
    "companyName"
    "officeLocation"
    "city"
    "country"
    "usageLocation"
    "mobilePhone"
    "businessPhones"
    "accountEnabled"
    "userType"                  # Member | Guest
    "assignedLicenses"
    "assignedPlans"
    "onPremisesSyncEnabled"
    "onPremisesLastSyncDateTime"
    "onPremisesDistinguishedName"
    "onPremisesSamAccountName"
    "onPremisesUserPrincipalName"
    "onPremisesImmutableId"
    "createdDateTime"
    "lastPasswordChangeDateTime"
    "passwordPolicies"
    "signInActivity"            # Requires AuditLog.Read.All
    "proxyAddresses"
    "otherMails"
    "preferredLanguage"
    "employeeId"
    "employeeType"
    "externalUserState"         # Populated for Guest accounts
)

# Default properties for Group objects
$GroupSelectProperties = @(
    "id"
    "displayName"
    "description"
    "mail"
    "mailNickname"
    "mailEnabled"
    "securityEnabled"
    "groupTypes"                # Unified = M365 group; empty = Security
    "membershipRule"
    "membershipRuleProcessingState"
    "onPremisesSyncEnabled"
    "onPremisesLastSyncDateTime"
    "createdDateTime"
    "renewedDateTime"
    "visibility"                # Public | Private | HiddenMembership
    "assignedLicenses"
    "proxyAddresses"
)

# Default properties for Device objects
$DeviceSelectProperties = @(
    "id"
    "displayName"
    "deviceId"
    "operatingSystem"
    "operatingSystemVersion"
    "trustType"                 # AzureAD | ServerAD | Workplace
    "joinType"                  # Registered | Joined | HybridJoined (beta)
    "complianceState"           # Requires Intune
    "isManaged"
    "isCompliant"
    "managementType"
    "enrollmentType"
    "manufacturer"
    "model"
    "onPremisesLastSyncDateTime"
    "registrationDateTime"
    "approximateLastSignInDateTime"
    "accountEnabled"
    "physicalIds"
    "extensionAttributes"
)


# ==============================================================================
# SECTION 5 — USER ACCOUNT DEFAULTS
# ==============================================================================

$DefaultUsageLocation        = "US"     # ISO 3166-1 alpha-2; required before license assignment
$DefaultPasswordLength       = 16
$DefaultUserType             = "Member"
$ForcePasswordChangeOnSignIn = $true

# Password profile template (do NOT hard-code passwords — populate at runtime)
$PasswordProfileTemplate = @{
    forceChangePasswordNextSignIn        = $ForcePasswordChangeOnSignIn
    forceChangePasswordNextSignInWithMfa = $false
    # password = <set at runtime>
}

# Guest invite settings
$GuestInviteRedirectUrl      = "https://myapps.microsoft.com"
$GuestUserMessageInfo        = "You have been invited to access our organisation's resources."


# ==============================================================================
# SECTION 6 — LICENSING (SKU IDs)
# ==============================================================================
# Well-known SKU Part Numbers → GUIDs. Verify against your tenant's subscribedSkus.
# Reference: https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference

$LicenseSkuIds = @{
    "AAD_PREMIUM"           = "078d2b04-f1bd-4111-bbd4-b4b1b354cef4"   # Entra ID P1
    "AAD_PREMIUM_P2"        = "84a661c4-e949-4bd2-a560-ed7766fcaf2b"   # Entra ID P2
    "ENTERPRISEPREMIUM"     = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"   # Microsoft 365 E5
    "ENTERPRISEPACK"        = "18181a46-0d4e-45cd-891e-60aabd171b4e"   # Office 365 E3
    "SPE_E3"                = "05e9a617-0261-4cee-bb44-138d3ef5d965"   # Microsoft 365 E3
    "SPE_E5"                = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"   # Microsoft 365 E5
    "FLOW_FREE"             = "f30db892-07e9-47e9-837c-80727f46fd3d"   # Power Automate Free
    "POWER_BI_PRO"          = "f8a1db68-be16-40ed-86d5-cb42ce701560"   # Power BI Pro
    "INTUNE_A"              = "061f9ace-7d42-4136-88ac-31dc755f143f"   # Intune Plan 1
    "EMS"                   = "efccb6f7-5641-4e0e-bd10-b4976e1bf68e"   # EMS E3
    "EMSPREMIUM"            = "b05e124f-c7cc-45a0-a6aa-8cf78c946968"   # EMS E5
    "DEFENDER_ENDPOINT_P1"  = "4ef96642-f096-40de-a3e9-d83fb2f90dea"   # Defender for Endpoint P1
    "DEFENDER_ENDPOINT_P2"  = "e20642f8-6e7e-4b6b-8b6c-2c2e3e9d52a1"   # Defender for Endpoint P2
}

# Disabled service plan GUIDs to suppress when assigning a SKU (example: disable Yammer in E3)
$DisabledServicePlans = @{
    "YAMMER_ENTERPRISE"     = "7547a3fe-08ee-4ccb-b430-5077c5041653"
    "TEAMS1"                = "57ff2da0-773e-42df-b2af-ffb7a2317929"
    "EXCHANGE_S_ENTERPRISE" = "efb87545-963c-4e0d-99df-69c6916d9eb0"
}


# ==============================================================================
# SECTION 7 — ROLE & PRIVILEGE CONSTANTS
# ==============================================================================
# Built-in Entra ID role template IDs (permanent — do not change between tenants)

$EntraRoles = @{
    "GlobalAdministrator"            = "62e90394-69f5-4237-9190-012177145e10"
    "GlobalReader"                   = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
    "UserAdministrator"              = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "GroupsAdministrator"            = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
    "HelpdeskAdministrator"          = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "SecurityAdministrator"          = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "SecurityReader"                 = "5d6b6bb7-de71-4623-b4af-96380a352509"
    "ConditionalAccessAdministrator" = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    "ApplicationAdministrator"       = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    "CloudApplicationAdministrator"  = "158c047a-c907-4556-b7ef-446551a6b5f7"
    "IntuneAdministrator"            = "3a2c62db-5318-420d-8d74-23affee5d9d5"
    "ExchangeAdministrator"          = "29232cdf-9323-42fd-ade2-1d097af3e4de"
    "SharePointAdministrator"        = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
    "TeamsAdministrator"             = "69091246-20e8-4a56-aa4d-066075b2a7a8"
    "PrivilegedRoleAdministrator"    = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "AuthenticationAdministrator"    = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    "LicenseAdministrator"           = "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
    "ReportsReader"                  = "4a5d8f65-41da-4de4-8968-e035b65339cf"
    "DirectoryReaders"               = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
    "DirectoryWriters"               = "9360feb5-f418-4baa-8175-720f6570544e"
}


# ==============================================================================
# SECTION 8 — CONDITIONAL ACCESS & NAMED LOCATIONS
# ==============================================================================

# Named location GUIDs (populate after creating them in your tenant)
$NamedLocations = @{
    "CorporateOffice"    = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    "TrustedVPN"         = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    "AllowedCountries"   = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}

# Conditional Access policy states
$CAPolicyStates = @{
    Enabled      = "enabled"
    Disabled     = "disabled"
    ReportOnly   = "enabledForReportingButNotEnforced"
}

# Grant controls
$CAGrantControls = @{
    MFA                      = "mfa"
    CompliantDevice          = "compliantDevice"
    DomainJoinedDevice       = "domainJoinedDevice"
    ApprovedApp              = "approvedApplication"
    AuthenticationStrength   = "authenticationStrength"
}


# ==============================================================================
# SECTION 9 — ADMINISTRATIVE UNITS
# ==============================================================================

$AdminUnits = @{
    # "UnitFriendlyName" = "GUID"
    # "HQ_Users"         = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    # "IT_Devices"       = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}


# ==============================================================================
# SECTION 10 — OPERATIONAL SETTINGS
# ==============================================================================

# Logging
$LogDirectory        = "C:\Logs\EntraID"
$LogFilePrefix       = "EntraID_Script"
$LogTimestampFormat  = "yyyy-MM-dd_HH-mm-ss"
$EnableVerboseLog    = $false

# Output / export paths
$ExportDirectory     = "C:\Reports\EntraID"
$ExportTimestamp     = (Get-Date -Format "yyyyMMdd_HHmmss")

# Paging — max results per Graph API page
$GraphPageSize       = 999    # Maximum allowed by Graph for most resources

# Retry / throttle handling
$MaxRetryAttempts    = 5
$RetryDelaySeconds   = 10

# Stale account threshold (days since last sign-in)
$StaleUserDays       = 90
$StaleDeviceDays     = 180

# Guest expiry review threshold (days)
$GuestReviewDays     = 365


# ==============================================================================
# SECTION 11 — ENVIRONMENT TAG
# ==============================================================================
# Useful when the same scripts run against dev / test / prod tenants.

$Environment         = "Production"    # Development | UAT | Production
$RunbookOwner        = "IT Operations"
$ScriptVersion       = "1.0.0"


# ==============================================================================
# HELPER: Confirm the file was dot-sourced successfully
# ==============================================================================
Write-Verbose "[$($MyInvocation.MyCommand.Name)] EntraID-Variables.ps1 loaded — Tenant: $TenantDomain | Environment: $Environment"

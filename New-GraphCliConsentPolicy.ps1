#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns
#Requires -Version 7.0

<#
.SYNOPSIS
    Creates a custom app consent policy scoped to the Graph Command Line Tools enterprise app
    with specific delegated permissions.
.DESCRIPTION
    Creates a permission grant policy in Entra ID that permits user consent only for the
    Microsoft Graph Command Line Tools service principal, restricted to the delegated scopes:
        - Group.ReadWrite.All
        - User.Read.All
        - Directory.Read.All

    The policy is built in two steps:
        1. Create the PermissionGrantPolicy object (the named policy).
        2. Add an "includes" condition set that locks the policy to the specified resource app
           and permission scopes.

    Once created, the policy ID can be referenced in Entra ID's user consent settings or
    assigned to an app consent framework (e.g. admin consent workflow).

.PARAMETER TenantId
    The Entra ID tenant ID or primary domain (e.g. contoso.onmicrosoft.com).

.PARAMETER PolicyId
    The identifier for the new permission grant policy. Must be lowercase, no spaces.
    Prefix 'microsoft-' is reserved — do not use it.
    Example: "custom-graphcli-consent-policy"

.PARAMETER PolicyDisplayName
    Human-readable display name for the policy shown in the Entra portal.

.PARAMETER PolicyDescription
    Optional description explaining the policy's purpose.

.EXAMPLE
    .\New-GraphCliConsentPolicy.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -PolicyId "custom-graphcli-consent-policy" `
        -PolicyDisplayName "Graph CLI Consent Policy" `
        -PolicyDescription "Permits user consent for Graph CLI with limited scopes"

.NOTES
    Required Graph delegated permissions (for the account running this script):
        - Policy.ReadWrite.PermissionGrant
        - Application.Read.All

    The operator account must hold at least the Privileged Role Administrator or
    Global Administrator role to manage permission grant policies.

    Graph Command Line Tools AppId: 14d82eec-204b-4c2f-b7e8-296a70dab67e
    This is a delegated-only policy — no app-only (application) permissions are granted.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^(?!microsoft-)[\w-]+$')]
    [string]$PolicyId,

    [Parameter(Mandatory)]
    [string]$PolicyDisplayName,

    [string]$PolicyDescription = "Custom consent policy for Graph Command Line Tools enterprise app."
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Constants ---
# Well-known AppId for "Microsoft Graph Command Line Tools" (stable across all tenants)
$GraphCliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

# The permission scopes to allow under this policy (delegated / Scope type)
$AllowedScopes = @(
    'Group.ReadWrite.All',
    'User.Read.All',
    'Directory.Read.All'
)
#endregion

#region --- Functions ---
function Invoke-MgWithRetry {
    <#
    .SYNOPSIS
        Wraps a Graph SDK call with exponential backoff on HTTP 429 / 503 / 504.
    #>
    param (
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 5,
        [int]$BaseDelaySeconds = 2
    )
    $attempt = 0
    while ($true) {
        try {
            return & $ScriptBlock
        }
        catch {
            $statusCode = $_.Exception.Response?.StatusCode.value__
            $retryAfter = $_.Exception.Response?.Headers?['Retry-After']
            $isThrottled = $statusCode -in @(429, 503, 504)
            $attempt++

            if (-not $isThrottled -or $attempt -gt $MaxRetries) {
                Write-Error "Graph call failed after $attempt attempt(s): $_"
                throw
            }

            $delay = if ($retryAfter) { [int]$retryAfter } else { [math]::Pow($BaseDelaySeconds, $attempt) }
            Write-Warning "Throttled (HTTP $statusCode). Retrying in $delay s... (attempt $attempt/$MaxRetries)"
            Start-Sleep -Seconds $delay
        }
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp][$Level] $Message"
    Write-Verbose $entry
    if ($Level -eq 'ERROR') { Write-Error $Message }
    elseif ($Level -eq 'WARN') { Write-Warning $Message }
    else { Write-Host $entry -ForegroundColor Cyan }
}
#endregion

#region --- Authentication ---
Write-Log "Connecting to Microsoft Graph (tenant: $TenantId)..."
Connect-MgGraph -TenantId $TenantId `
    -Scopes "Policy.ReadWrite.PermissionGrant", "Application.Read.All" `
    -NoWelcome
Write-Log "Connected successfully."
#endregion

#region --- Main Logic ---

# ── Step 1: Resolve the Graph CLI service principal ──────────────────────────
Write-Log "Resolving Graph Command Line Tools service principal (AppId: $GraphCliAppId)..."

$graphCliSp = Invoke-MgWithRetry {
    Get-MgServicePrincipal -Filter "appId eq '$GraphCliAppId'" -Property Id, AppId, DisplayName
}

if (-not $graphCliSp) {
    throw "Graph Command Line Tools service principal (AppId: $GraphCliAppId) was not found " +
          "in tenant '$TenantId'. Ensure the enterprise app exists before running this script."
}

Write-Log "Found SP: '$($graphCliSp.DisplayName)' (Object ID: $($graphCliSp.Id))"

# ── Step 2: Resolve delegated permission IDs from the Graph CLI SP ────────────
# Delegated permissions (OAuth2PermissionScopes) live on the SP object.
Write-Log "Resolving delegated permission IDs for: $($AllowedScopes -join ', ')..."

$resolvedScopeIds = foreach ($scopeName in $AllowedScopes) {
    $scope = $graphCliSp.Oauth2PermissionScopes | Where-Object Value -eq $scopeName
    if (-not $scope) {
        throw "Scope '$scopeName' was not found on the Graph CLI service principal. " +
              "Verify the scope name is correct and the SP exposes it as a delegated permission."
    }
    Write-Log "  Resolved '$scopeName' → $($scope.Id)"
    $scope.Id
}

# Build the space-separated scope value string required by the condition set
$permissionClassificationScopeIds = $resolvedScopeIds -join ' '

# ── Step 3: Check for existing policy with the same ID ───────────────────────
Write-Log "Checking whether policy '$PolicyId' already exists..."
$existingPolicy = $null
try {
    $existingPolicy = Invoke-MgWithRetry {
        Get-MgPolicyPermissionGrantPolicy -PermissionGrantPolicyId $PolicyId -ErrorAction Stop
    }
}
catch {
    if ($_.Exception.Message -notmatch '404|NotFound|does not exist') { throw }
}

if ($existingPolicy) {
    Write-Log "Policy '$PolicyId' already exists. Skipping creation." -Level WARN
}
else {
    # ── Step 4: Create the permission grant policy ────────────────────────────
    if ($PSCmdlet.ShouldProcess("PermissionGrantPolicy '$PolicyId'", "Create")) {
        Write-Log "Creating permission grant policy '$PolicyId'..."

        $policyBody = @{
            id          = $PolicyId
            displayName = $PolicyDisplayName
            description = $PolicyDescription
        }

        $newPolicy = Invoke-MgWithRetry {
            New-MgPolicyPermissionGrantPolicy -BodyParameter $policyBody
        }

        Write-Log "Policy created: '$($newPolicy.Id)'"
    }
}

# ── Step 5: Add an "includes" condition set to the policy ─────────────────────
# This locks the policy to: delegated permissions only, from the Graph CLI SP,
# for the specific scopes requested.
if ($PSCmdlet.ShouldProcess("PolicyId '$PolicyId'", "Add includes condition set")) {
    Write-Log "Adding includes condition set to policy '$PolicyId'..."

    $conditionSetBody = @{
        # 'delegated' = user-delegated (Scope). Use 'application' for app-only roles.
        permissionType         = "delegated"

        # Restrict to the Graph CLI resource SP only
        resourceApplication    = $graphCliSp.AppId

        # Comma-separated GUIDs of the specific scopes to allow
        permissions            = $resolvedScopeIds

        # 'low' classification; 'medium'/'high' require explicit classification in tenant
        permissionClassification = "all"

        # Only applies to apps from any verified publisher; remove to allow all publishers
        # clientApplicationsFromVerifiedPublisherOnly = $true

        # Scope to all client apps (restrict further by setting clientApplicationIds)
        clientApplicationIds   = @("all")
    }

    $conditionSet = Invoke-MgWithRetry {
        New-MgPolicyPermissionGrantPolicyInclude `
            -PermissionGrantPolicyId $PolicyId `
            -BodyParameter $conditionSetBody
    }

    Write-Log "Condition set added (Id: $($conditionSet.Id))."
}

# ── Step 6: Verify and summarise ─────────────────────────────────────────────
Write-Log "Verifying final policy state..."

$finalPolicy = Invoke-MgWithRetry {
    Get-MgPolicyPermissionGrantPolicy -PermissionGrantPolicyId $PolicyId
}
$includes = Invoke-MgWithRetry {
    Get-MgPolicyPermissionGrantPolicyInclude -PermissionGrantPolicyId $PolicyId -All
}

Write-Host "`n── Policy Summary ───────────────────────────────────────────" -ForegroundColor Green
Write-Host "  Policy ID      : $($finalPolicy.Id)"
Write-Host "  Display Name   : $($finalPolicy.DisplayName)"
Write-Host "  Description    : $($finalPolicy.Description)"
Write-Host "  Condition Sets : $($includes.Count) include(s)"
foreach ($cs in $includes) {
    Write-Host "    ┌ ConditionSet Id      : $($cs.Id)"
    Write-Host "    │ Permission Type      : $($cs.PermissionType)"
    Write-Host "    │ Resource App (AppId) : $($cs.ResourceApplication)"
    Write-Host "    │ Allowed Scope IDs    : $($cs.Permissions -join ', ')"
    Write-Host "    └ Client Apps          : $($cs.ClientApplicationIds -join ', ')"
}
Write-Host "─────────────────────────────────────────────────────────────`n" -ForegroundColor Green

Write-Log "Done. Policy '$PolicyId' is ready. Assign it to your tenant's user consent settings in the Entra portal under:"
Write-Log "  Enterprise apps → Consent and permissions → User consent settings → 'Use a custom app consent policy'"

#endregion

#region --- Cleanup ---
Disconnect-MgGraph -ErrorAction SilentlyContinue
Write-Log "Disconnected from Microsoft Graph."
#endregion

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Retrieves all app consent (permission grant) policies from an Entra ID tenant
    and lets the user interactively filter them by a search string.

.DESCRIPTION
    Dot-sources EntraID-Variables.ps1 for shared configuration, then calls the
    Microsoft Graph v1.0 endpoint for permissionGrantPolicies.  Authenticates
    via an interactive browser sign-in (delegated flow).  The user is prompted
    for a search string; the script filters across id, displayName, and
    description, then outputs matching policies to the console.  An optional CSV
    export is offered after each search.

    Graph API used:
        GET /v1.0/policies/permissionGrantPolicies

    Required permission (delegated): Policy.Read.All  (already in $DelegatedScopes)

.PARAMETER SearchQuery
    Optional.  Supply the search string directly to skip the interactive prompt.
    Useful when calling the script non-interactively.

.PARAMETER ExportCsv
    Optional switch.  When present, always exports to CSV without prompting.

.PARAMETER NoExport
    Optional switch.  When present, suppresses the CSV export prompt entirely.

.EXAMPLE
    # Interactive — prompts for search string and export choice
    .\Get-AppConsentPolicies.ps1

.EXAMPLE
    # Non-interactive — search for "microsoft" and skip export
    .\Get-AppConsentPolicies.ps1 -SearchQuery "microsoft" -NoExport

.EXAMPLE
    # Search and always export to CSV
    .\Get-AppConsentPolicies.ps1 -SearchQuery "low-risk" -ExportCsv

.NOTES
    - Uses the stable v1.0 Graph endpoint; condition set detail (includes/excludes)
      is not expanded at this tier — only id, displayName, and description are
      returned and searched.
    - Built-in Microsoft policies (ids starting with "microsoft-") are included
      in results for reference but cannot be modified.
    - $GraphVersion in EntraID-Variables.ps1 is respected; no override is needed
      as v1.0 is the default configured there.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SearchQuery,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$NoExport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ==============================================================================
# 0 — DOT-SOURCE SHARED VARIABLES
# ==============================================================================
$variablesFile = Join-Path $PSScriptRoot "EntraID-Variables.ps1"
if (-not (Test-Path $variablesFile)) {
    throw "Cannot find EntraID-Variables.ps1 at '$variablesFile'. " +
          "Ensure this script is in the same directory."
}
. $variablesFile

$ConsentPoliciesEndpoint = "$GraphApiRoot/policies/permissionGrantPolicies"

# ==============================================================================
# 1 — HELPER FUNCTIONS
# ==============================================================================

function Write-Header {
    param([string]$Text)
    $line = "=" * 72
    Write-Host ""
    Write-Host $line              -ForegroundColor Cyan
    Write-Host "  $Text"         -ForegroundColor Cyan
    Write-Host $line              -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step    { param([string]$Text) Write-Host "[*] $Text" -ForegroundColor Yellow  }
function Write-Success { param([string]$Text) Write-Host "[+] $Text" -ForegroundColor Green   }
function Write-Warn    { param([string]$Text) Write-Host "[!] $Text" -ForegroundColor Magenta }
function Write-Info    { param([string]$Text) Write-Host "    $Text" -ForegroundColor Gray    }

# Invoke-GraphRequest — wraps Invoke-MgGraphRequest with retry / throttle
# handling using $MaxRetryAttempts and $RetryDelaySeconds from variables file.
function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = "GET"
    )

    $attempt = 0
    do {
        $attempt++
        try {
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ($statusCode -eq 429 -and $attempt -lt $MaxRetryAttempts) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                $waitSecs   = if ($retryAfter) { [int]$retryAfter } else { $RetryDelaySeconds }
                Write-Warn "Graph throttled (429). Waiting ${waitSecs}s before retry $attempt/$MaxRetryAttempts..."
                Start-Sleep -Seconds $waitSecs
            }
            elseif ($attempt -lt $MaxRetryAttempts) {
                Write-Warn "Graph request failed (attempt $attempt/$MaxRetryAttempts): $($_.Exception.Message)"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
            else { throw }
        }
    } while ($attempt -lt $MaxRetryAttempts)
}

# Get-AllPages — follows @odata.nextLink to page through all results.
function Get-AllPages {
    param([Parameter(Mandatory)][string]$Uri)

    $allItems = [System.Collections.Generic.List[object]]::new()
    $nextUri  = $Uri

    do {
        $page = Invoke-GraphRequest -Uri $nextUri
        if ($page.value) { $allItems.AddRange($page.value) }
        $nextUri = $page.'@odata.nextLink'
    } while ($nextUri)

    return $allItems
}

# Test-PolicyMatchesQuery — case-insensitive substring match across
# id, displayName, and description.
function Test-PolicyMatchesQuery {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][string]$Query
    )

    $needle = $Query.ToLower()
    $fields = @($Policy.id, $Policy.displayName, $Policy.description) |
              Where-Object { $_ } |
              ForEach-Object { $_.ToLower() }

    return ($fields | Where-Object { $_ -like "*$needle*" }).Count -gt 0
}

# Show-PolicyDetail — pretty-prints one policy to the console.
function Show-PolicyDetail {
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][int]$Total
    )

    $isBuiltIn  = $Policy.id -like "microsoft-*"
    $typeLabel  = if ($isBuiltIn) { "[Built-in]" } else { "[Custom]  " }
    $typeColor  = if ($isBuiltIn) { "DarkCyan"  } else { "White"    }

    Write-Host ""
    Write-Host "  [$Index/$Total] $typeLabel" -ForegroundColor $typeColor -NoNewline
    Write-Host " $($Policy.displayName)"      -ForegroundColor White

    Write-Host "        ID          : " -NoNewline -ForegroundColor DarkGray
    Write-Host $Policy.id               -ForegroundColor Gray

    if ($Policy.description) {
        Write-Host "        Description : " -NoNewline -ForegroundColor DarkGray
        Write-Host $Policy.description   -ForegroundColor Gray
    }
    else {
        Write-Host "        Description : (none)" -ForegroundColor DarkGray
    }
}

# ==============================================================================
# 2 — AUTHENTICATE
# ==============================================================================
Write-Header "Entra ID — App Consent Policy Search"
Write-Info "Tenant : $TenantDomain"
Write-Info "Env    : $Environment"
Write-Host ""

Write-Step "Connecting to Microsoft Graph (browser sign-in)..."

try {
    Connect-MgGraph -TenantId $TenantId `
                    -Scopes   $DelegatedScopes `
                    -NoWelcome
    Write-Success "Connected to Microsoft Graph."
}
catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    exit 1
}

# ==============================================================================
# 3 — RETRIEVE ALL PERMISSION GRANT POLICIES
# ==============================================================================
Write-Step "Fetching permissionGrantPolicies from Graph $GraphVersion..."

try {
    $allPolicies = Get-AllPages -Uri $ConsentPoliciesEndpoint
}
catch {
    Write-Error "Failed to retrieve policies: $($_.Exception.Message)"
    Disconnect-MgGraph | Out-Null
    exit 1
}

if (-not $allPolicies -or $allPolicies.Count -eq 0) {
    Write-Warn "No permissionGrantPolicies found in tenant '$TenantDomain'."
    Disconnect-MgGraph | Out-Null
    exit 0
}

Write-Success "Retrieved $($allPolicies.Count) policy/policies total."

# ==============================================================================
# 4 — INTERACTIVE SEARCH LOOP
# ==============================================================================
Write-Header "Policy Search"

do {
    # Prompt for search string if not supplied as a parameter
    if (-not $SearchQuery) {
        Write-Host "  Enter a search string to filter policies (or press Enter to list all):" -ForegroundColor Cyan
        Write-Host "  Searches across: id, displayName, description." -ForegroundColor DarkGray
        Write-Host ""
        $inputQuery = Read-Host "  Search"
    }
    else {
        $inputQuery = $SearchQuery
        Write-Info "Using supplied search query: '$inputQuery'"
    }

    # Filter
    if ([string]::IsNullOrWhiteSpace($inputQuery)) {
        $matched = $allPolicies
        Write-Info "No filter applied — showing all $($allPolicies.Count) policies."
    }
    else {
        $matched = $allPolicies | Where-Object {
            Test-PolicyMatchesQuery -Policy $_ -Query $inputQuery
        }
    }

    # Display results
    Write-Host ""
    if ($matched.Count -eq 0) {
        Write-Warn "No policies matched '$inputQuery'."
    }
    else {
        $displayQuery = if ([string]::IsNullOrWhiteSpace($inputQuery)) { "(all)" } else { "'$inputQuery'" }
        Write-Success "$($matched.Count) policy/policies matched $displayQuery :"

        $i = 0
        foreach ($policy in $matched) {
            $i++
            Show-PolicyDetail -Policy $policy -Index $i -Total $matched.Count
        }
        Write-Host ""
    }

    # ==============================================================================
    # 5 — OPTIONAL CSV EXPORT
    # ==============================================================================
    if ($matched.Count -gt 0 -and -not $NoExport) {

        $doExport = if ($ExportCsv) {
            $true
        } else {
            (Read-Host "  Export these results to CSV? (Y/N)") -match '^[Yy]'
        }

        if ($doExport) {
            if (-not (Test-Path $ExportDirectory)) {
                New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
            }

            $safeQuery   = ($inputQuery -replace '[^\w\-]', '_').Trim('_')
            $safeQuery   = if ([string]::IsNullOrWhiteSpace($safeQuery)) { "All" } else { $safeQuery }
            $csvFileName = "${LogFilePrefix}_ConsentPolicies_${safeQuery}_${ExportTimestamp}.csv"
            $csvPath     = Join-Path $ExportDirectory $csvFileName

            $matched | ForEach-Object {
                [PSCustomObject]@{
                    PolicyId    = $_.id
                    DisplayName = $_.displayName
                    Description = $_.description
                    IsBuiltIn   = ($_.id -like "microsoft-*")
                }
            } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

            Write-Success "Exported $($matched.Count) row(s) to: $csvPath"
        }
    }

    # Loop — only repeat when running interactively
    if ($SearchQuery) {
        $again = $false
    }
    else {
        Write-Host ""
        $again       = (Read-Host "  Search again? (Y/N)") -match '^[Yy]'
        $SearchQuery = $null   # Clear so the prompt re-appears next iteration
    }

} while ($again)

# ==============================================================================
# 6 — DISCONNECT
# ==============================================================================
Write-Step "Disconnecting from Microsoft Graph..."
Disconnect-MgGraph | Out-Null
Write-Success "Done."
Write-Host ""

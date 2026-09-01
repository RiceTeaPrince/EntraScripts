<#
.SYNOPSIS
    Looks up each person in Admin-People.csv against Active Directory and records
    their manager and whether their AD account is active.

.DESCRIPTION
    Merge-AdminReview.ps1 produces one row per person, joined on base username, but
    carries no manager information and no live account-status check - its
    'On-Prem Identity Enabled' column (when present) reflects whichever AD sweep
    Build-OnPremAdminReview.ps1 last ran, not necessarily the state right now. This
    script does a targeted, per-person Get-ADUser lookup instead of a full domain
    sweep, so it's cheap to re-run close to review time regardless of when the bulk
    export was last built.

    AD is the authority here: this workbook treats Entra account status as
    downstream of AD via Entra Connect sync, so this script - not the Entra one -
    is the one that determines whether a person's identity is considered active.
    Update-AdminPeopleEntra.ps1 reads this script's 'AD Account Active' column to
    decide which accounts are even worth checking in Entra.

    For each base username: resolves the AD user by SamAccountName, records
    whether it's enabled, and resolves the Manager attribute (a distinguished
    name) to that manager's UserPrincipalName - not display name, so the value is
    directly usable to cross-reference the manager as their own row in this same
    CSV or look them up in Entra. Manager DN->UPN resolutions are cached, since
    many people share a manager.

    A base username with no matching AD account records 'Not Found' on 'AD Account
    Active', not 'No' - those are different findings. 'No' means a real,
    resolvable AD account that is disabled. 'Not Found' means no account matched
    the lookup at all (genuinely absent, or a naming/domain mismatch this script's
    single -Filter lookup didn't account for).

    Rewrites Admin-People.csv in place, adding (or overwriting, on a re-run) the
    'AD Manager' and 'AD Account Active' columns. Every other column is passed
    through unchanged.

    READ-ONLY.

.PARAMETER AdminPeoplePath
    Admin-People.csv from Merge-AdminReview.ps1. Read and rewritten in place.

.PARAMETER Server
    Domain controller (or domain) to query. Passed straight to Get-ADUser. Omit to
    let the ActiveDirectory module auto-discover one, same default as
    Build-OnPremAdminReview.ps1.

.EXAMPLE
    .\Update-AdminPeopleAD.ps1

.EXAMPLE
    .\Update-AdminPeopleAD.ps1 -Server dc01.corp.com.au

.NOTES
    Requires the ActiveDirectory module (RSAT) and a domain-joined machine, same as
    Build-OnPremAdminReview.ps1. Run Update-AdminPeopleEntra.ps1 after this one -
    it depends on the 'AD Account Active' column this script writes.
#>

[CmdletBinding()]
param(
    [string]$AdminPeoplePath = ".\Admin-People.csv",
    [string]$Server
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $AdminPeoplePath)) { throw "Not found: $AdminPeoplePath" }
$people = @(Import-Csv $AdminPeoplePath)
if ($people.Count -eq 0) { throw "$AdminPeoplePath has no rows." }

$common = @{}
if ($Server) { $common['Server'] = $Server }

Write-Host "Looking up $($people.Count) person(s) in AD..." -ForegroundColor Cyan

# Manager DN -> UPN cache. A DN can also fail to resolve (moved/deleted object,
# manager attribute pointing somewhere stale) - cache that outcome too so a bad
# DN shared by several people only costs one failed lookup, not one per person.
$managerUpnByDn = @{}
function Resolve-ManagerUpn([string]$Dn) {
    if (-not $Dn) { return '' }
    if ($managerUpnByDn.ContainsKey($Dn)) { return $managerUpnByDn[$Dn] }
    $upn = ''
    try {
        $mgr = Get-ADUser -Identity $Dn -Properties UserPrincipalName @common -ErrorAction Stop
        $upn = $mgr.UserPrincipalName
    } catch {
        Write-Verbose "Could not resolve manager '$Dn': $($_.Exception.Message)"
    }
    $managerUpnByDn[$Dn] = $upn
    return $upn
}

$found = 0
$notFound = 0
$disabled = 0
$outRows = [System.Collections.Generic.List[object]]::new()

foreach ($p in $people) {
    $username = $p.'Base Username'
    $adUser = $null
    if ($username) {
        # Escape embedded single quotes defensively before splicing into the
        # -Filter string - unlikely in a username, cheap to guard anyway.
        $safeUsername = $username.Replace("'", "''")
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$safeUsername'" -Properties Enabled, Manager @common -ErrorAction SilentlyContinue |
                  Select-Object -First 1
    }

    if ($adUser) {
        $found++
        $active = if ($adUser.Enabled) { 'Yes' } else { $disabled++; 'No' }
        $managerUpn = Resolve-ManagerUpn $adUser.Manager
    } else {
        $notFound++
        $active = 'Not Found'
        $managerUpn = ''
    }

    # Rebuild the row as an ordered hashtable rather than Add-Member -Force:
    # Add-Member on a property that already exists (a re-run) moves it to the
    # end instead of updating in place, which would reshuffle column order
    # every re-run - and, worse, push these columns after Entra's on a second
    # AD pass. This keeps a first run's column position stable forever after.
    $propNames = @($p.PSObject.Properties.Name)
    $hasCols = $propNames -contains 'AD Manager'
    $row = [ordered]@{}
    foreach ($name in $propNames) {
        if ($name -eq 'AD Manager') { $row[$name] = $managerUpn }
        elseif ($name -eq 'AD Account Active') { $row[$name] = $active }
        else { $row[$name] = $p.$name }
    }
    if (-not $hasCols) {
        $row['AD Manager'] = $managerUpn
        $row['AD Account Active'] = $active
    }
    $outRows.Add([PSCustomObject]$row)
}

$outRows | Export-Csv -Path $AdminPeoplePath -NoTypeInformation -Encoding UTF8

Write-Host "`nWritten to $AdminPeoplePath" -ForegroundColor Green
Write-Host "  AD account found          : $found"
Write-Host "  ...and disabled           : $disabled" -ForegroundColor Yellow
Write-Host "  No matching AD account    : $notFound"
Write-Host "`nNext: Update-AdminPeopleEntra.ps1 (checks Entra only for the '$disabled' disabled here)." -ForegroundColor Cyan

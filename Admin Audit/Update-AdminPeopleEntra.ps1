<#
.SYNOPSIS
    Checks Entra for exactly one thing: whether a person's account is still
    active there despite Update-AdminPeopleAD.ps1 finding their AD account
    disabled. Only runs against that subset.

.DESCRIPTION
    This is deliberately narrow. Entra Connect sync means AD is the source of
    truth for account status in this workbook - once Update-AdminPeopleAD.ps1 has
    run, Entra has no unique manager or status data worth collecting for anyone
    it already resolved. The only thing worth checking Entra for is the case sync
    is supposed to prevent: a person whose AD account is disabled but who can
    still sign in to Entra, because the disable hasn't (or won't) propagate. So
    this script reads the 'AD Account Active' column Update-AdminPeopleAD.ps1
    wrote and queries Entra ONLY for rows marked 'No' there. It throws if that
    column isn't present - it means Update-AdminPeopleAD.ps1 hasn't been run yet,
    and running this first would either check everyone (expensive and mostly
    pointless) or no-one.

    Rows it doesn't check get 'Entra Account Active' set to a reason, not left
    blank: 'Not Checked (AD Active)' or 'Not Checked (No AD Account)', so a blank
    cell is never confused with "checked, nothing found."

    For the rows it does check, the base username is resolved to a UPN the same
    way Build-CloudAdminReview.ps1 resolves a standard account: exact match against
    "<username>@<StandardAccountDomain>" if given, otherwise a UPN-prefix match
    across all domains in the tenant. If more than one Entra user matches the
    prefix (only possible without -StandardAccountDomain), that's flagged with a
    warning and recorded as 'Ambiguous' rather than silently picking one - this
    column feeds a security-relevant flag, so a wrong guess is worse than a gap.

    Writes 'Entra Account Active' and, only for the rows actually checked,
    'AD/Entra Active Mismatch' = YES when AD is disabled but Entra is still
    enabled - the specific finding this script exists to surface. Rows not
    checked get '' (not applicable) on the mismatch column, not 'No' - 'No' is
    reserved for "checked, and they matched."

    Rewrites Admin-People.csv in place. Every other column, including the ones
    Update-AdminPeopleAD.ps1 wrote, is passed through unchanged.

    READ-ONLY.

.PARAMETER AdminPeoplePath
    Admin-People.csv, already processed by Update-AdminPeopleAD.ps1. Read and
    rewritten in place.

.PARAMETER StandardAccountDomain
    UPN suffix of everyday accounts, e.g. 'corp.com.au'. Same parameter, same
    behaviour, as Build-CloudAdminReview.ps1's own -StandardAccountDomain: omit it
    to match on UPN prefix across every domain in the tenant instead.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All'
    .\Update-AdminPeopleEntra.ps1 -StandardAccountDomain 'corp.com.au'

.NOTES
    Module: Microsoft.Graph. Graph scope (read-only): User.Read.All.

    Must run after Update-AdminPeopleAD.ps1 - it depends on the 'AD Account
    Active' column that script writes and throws without it.
#>

[CmdletBinding()]
param(
    [string]$AdminPeoplePath = ".\Admin-People.csv",
    [string]$StandardAccountDomain
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $AdminPeoplePath)) { throw "Not found: $AdminPeoplePath" }
$people = @(Import-Csv $AdminPeoplePath)
if ($people.Count -eq 0) { throw "$AdminPeoplePath has no rows." }
if (-not ($people[0].PSObject.Properties.Name -contains 'AD Account Active')) {
    throw "'AD Account Active' column not found on $AdminPeoplePath. Run Update-AdminPeopleAD.ps1 first - this script only checks the accounts it found disabled."
}

$toCheck = @($people | Where-Object { $_.'AD Account Active' -eq 'No' })
Write-Host "$($people.Count) people total, $($toCheck.Count) with AD Account Active = No - checking Entra for those." -ForegroundColor Cyan

$checked = 0
$mismatches = 0
$ambiguous = 0
$outRows = [System.Collections.Generic.List[object]]::new()

# Rebuild each row as an ordered hashtable rather than Add-Member -Force - see
# Update-AdminPeopleAD.ps1 for why: -Force on an existing property relocates it
# to the end on a re-run instead of updating in place, which would reshuffle
# column order every time this script runs again.
function Set-Row($Person, [string]$EntraActive, [string]$Mismatch) {
    $propNames = @($Person.PSObject.Properties.Name)
    $hasCols = $propNames -contains 'Entra Account Active'
    $row = [ordered]@{}
    foreach ($name in $propNames) {
        if ($name -eq 'Entra Account Active') { $row[$name] = $EntraActive }
        elseif ($name -eq 'AD/Entra Active Mismatch') { $row[$name] = $Mismatch }
        else { $row[$name] = $Person.$name }
    }
    if (-not $hasCols) {
        $row['Entra Account Active'] = $EntraActive
        $row['AD/Entra Active Mismatch'] = $Mismatch
    }
    return [PSCustomObject]$row
}

foreach ($p in $people) {
    if ($p.'AD Account Active' -ne 'No') {
        $reason = if ($p.'AD Account Active' -eq 'Not Found') { 'Not Checked (No AD Account)' } else { 'Not Checked (AD Active)' }
        $outRows.Add((Set-Row $p $reason ''))
        continue
    }

    $checked++
    $username = $p.'Base Username'
    $matches = @()
    if ($username) {
        $safeUsername = $username.Replace("'", "''")
        if ($StandardAccountDomain) {
            $upn = "$safeUsername@$StandardAccountDomain"
            $matches = @(Get-MgUser -Filter "userPrincipalName eq '$upn'" -Property AccountEnabled, UserPrincipalName -ErrorAction Stop)
        } else {
            $matches = @(Get-MgUser -Filter "startsWith(userPrincipalName,'$safeUsername@')" -Property AccountEnabled, UserPrincipalName -All -ErrorAction Stop)
        }
    }

    if ($matches.Count -eq 1) {
        $entraActive = if ($matches[0].AccountEnabled) { 'Yes' } else { 'No' }
    } elseif ($matches.Count -eq 0) {
        $entraActive = 'Not Found'
    } else {
        $ambiguous++
        Write-Warning "Ambiguous Entra match for '$username' ($($matches.Count) accounts) - recorded as Ambiguous, not guessed."
        $entraActive = 'Ambiguous'
    }

    $mismatch = if ($entraActive -eq 'Yes') { $mismatches++; 'YES' } else { 'No' }

    $outRows.Add((Set-Row $p $entraActive $mismatch))
}

$outRows | Export-Csv -Path $AdminPeoplePath -NoTypeInformation -Encoding UTF8

Write-Host "`nWritten to $AdminPeoplePath" -ForegroundColor Green
Write-Host "  Checked in Entra (AD disabled)          : $checked"
if ($ambiguous) { Write-Host "  Ambiguous Entra match                    : $ambiguous" -ForegroundColor Yellow }
if ($mismatches) {
    Write-Host "  AD disabled but Entra still active       : $mismatches" -ForegroundColor Red
    Write-Host "    Entra Connect sync should have disabled these. Start here."
} else {
    Write-Host "  AD disabled but Entra still active       : 0" -ForegroundColor Green
}

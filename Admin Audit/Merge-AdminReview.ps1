<#
.SYNOPSIS
    Merges the cloud and on-premises admin exports into a per-person roll-up for the
    Privileged Access Review workbook.

.DESCRIPTION
    The other scripts produce one row per admin ACCOUNT. This one produces one row
    per PERSON, joined on the base username that both naming conventions encode.

    That shift matters. Cloud and on-prem admin accounts never mix, but the human
    behind them does: someone holding privilege in two or more planes is a single
    point of compromise reaching all of them, and no account-level view will show
    you that.

    Reads six inputs, not two - Build-CloudAdminReview.ps1 now splits its output
    across three files so Entra and Azure RBAC remediation can be worked as separate
    projects:

      - Cloud-Admin-Accounts.csv (unfiltered - every cloud admin account, so a
        zero-privilege one is never invisible here even though it's absent from
        the two files below). Drives 'Has Cloud Admin' and orphan detection.
      - Entra-Admins.csv and Azure-RBAC-Admins.csv (filtered to accounts actually
        holding a role in that plane). Drive the per-plane tier and highest-role
        columns.
      - OnPrem-Admins.csv, unchanged.
      - Normal-Users.csv and Normal-CloudUsers.csv (the "normal user accounts"
        exports each build script already writes) - see 'Cross-plane identity
        check' below.

    Runs offline. It only reads these CSVs and writes a seventh, so it can be run
    wherever you have the files, with no tenant or domain access needed. That
    matters here specifically: Build-OnPremAdminReview.ps1 (AD-only) and
    Build-CloudAdminReview.ps1 (Graph/Az-only) each intentionally have no access to
    the other plane, so neither can check a base username against the other
    directory itself. This script is the only place both CSVs are ever loaded at
    once, which makes it the only place that cross-check can happen.

    Cross-plane identity check: for every person, looks up their base username in
    the OTHER plane's normal-user export - an on-prem admin's username against
    Normal-CloudUsers.csv, a cloud admin's username against Normal-Users.csv - and
    records whether a standard (non-admin-pattern) account exists there and
    whether it's enabled. This is a different question from each build script's
    own same-plane 'Standard Acct Enabled' column: that one asks "does this
    admin's own plane still have their everyday account," this one asks "does the
    person also have an identity in the OTHER plane." It exists because a
    same-plane 'NOT FOUND' is ambiguous by itself - it can mean a genuine orphan,
    or it can mean the build script's OU/domain scope or naming-convention pattern
    just missed an account that's actually there (see each script's own
    NormalUsersOutputPath/NormalCloudUsersOutputPath notes). Finding an enabled
    identity on the other side doesn't resolve that ambiguity on its own, but it's
    a strong hint worth a manual look before treating a NOT FOUND as a real
    orphan. If a Normal-*.csv is missing, the corresponding '... Identity Exists'
    column reads 'Unknown' rather than 'No' - a missing input is not the same
    finding as a checked-and-absent account.

.PARAMETER CloudAccountsPath
    Cloud-Admin-Accounts.csv from Build-CloudAdminReview.ps1.

.PARAMETER EntraPath
    Entra-Admins.csv from Build-CloudAdminReview.ps1.

.PARAMETER AzureRbacPath
    Azure-RBAC-Admins.csv from Build-CloudAdminReview.ps1.

.PARAMETER OnPremPath
    OnPrem-Admins.csv from Build-OnPremAdminReview.ps1.

.PARAMETER NormalOnPremPath
    Normal-Users.csv from Build-OnPremAdminReview.ps1 - the on-prem standard-user
    baseline, used to check a CLOUD admin's base username for a matching AD identity.

.PARAMETER NormalCloudPath
    Normal-CloudUsers.csv from Build-CloudAdminReview.ps1 - the cloud standard-user
    baseline, used to check an ON-PREM admin's base username for a matching Entra
    identity.

.PARAMETER OutputPath
    CSV path. Defaults to .\Admin-People.csv

.EXAMPLE
    .\Merge-AdminReview.ps1

.NOTES
    Any input may be omitted or missing - the roll-up still builds from whichever
    are present, and a missing plane shows as 'No'. Exception: a missing
    Normal-Users.csv/Normal-CloudUsers.csv shows as 'Unknown' on the corresponding
    '... Identity Exists' column rather than 'No' - that column specifically means
    "checked and not there," and a missing input hasn't checked anything.
#>

[CmdletBinding()]
param(
    [string]$CloudAccountsPath = ".\Cloud-Admin-Accounts.csv",
    [string]$EntraPath         = ".\Entra-Admins.csv",
    [string]$AzureRbacPath     = ".\Azure-RBAC-Admins.csv",
    [string]$OnPremPath        = ".\OnPrem-Admins.csv",
    [string]$NormalOnPremPath  = ".\Normal-Users.csv",
    [string]$NormalCloudPath   = ".\Normal-CloudUsers.csv",
    [string]$OutputPath        = ".\Admin-People.csv"
)

$ErrorActionPreference = 'Stop'

function Import-IfPresent([string]$Path) {
    if (Test-Path $Path) { return @(Import-Csv $Path) }
    Write-Warning "Not found: $Path"
    return @()
}

$cloudAccounts = Import-IfPresent $CloudAccountsPath
$entra         = Import-IfPresent $EntraPath
$rbac          = Import-IfPresent $AzureRbacPath
$onprem        = Import-IfPresent $OnPremPath

# Cross-plane identity check inputs. Tracked separately from the imported rows
# (not just "$normalOnPrem.Count -eq 0") because an empty-but-present file and a
# missing file mean different things below: 'Unknown' vs a checked 'No'.
$normalOnPremFound = Test-Path $NormalOnPremPath
$normalCloudFound  = Test-Path $NormalCloudPath
$normalOnPrem      = Import-IfPresent $NormalOnPremPath
$normalCloud       = Import-IfPresent $NormalCloudPath

Write-Host "  $($cloudAccounts.Count) cloud admin account(s) ($($entra.Count) with an Entra role, $($rbac.Count) with an Azure RBAC role), $($onprem.Count) on-prem admin account(s)" -ForegroundColor Cyan
if ($cloudAccounts.Count -eq 0 -and $onprem.Count -eq 0) { throw "Neither Cloud-Admin-Accounts.csv nor OnPrem-Admins.csv has any rows. Nothing to merge." }

$cloudAccountsBy = $cloudAccounts | Group-Object 'Base Username' -AsHashTable -AsString
$entraBy         = $entra         | Group-Object 'Base Username' -AsHashTable -AsString
$rbacBy          = $rbac          | Group-Object 'Base Username' -AsHashTable -AsString
$onpremBy        = $onprem        | Group-Object 'Base Username' -AsHashTable -AsString

# Keyed the same way each build script keys its own standard-account lookup:
# SamAccountName for AD, UPN prefix for Entra - so a base username here (which
# comes from stripping '-a' or '.azr' the same way) lines up directly.
$normalOnPremBySam = @{}
foreach ($u in $normalOnPrem) { $normalOnPremBySam[$u.SamAccountName.ToLower()] = $u }

$normalCloudByPrefix = @{}
foreach ($u in $normalCloud) { $normalCloudByPrefix[(($u.UPN -split '@')[0]).ToLower()] = $u }

# Union across all four - not just the unfiltered lists - in case Entra/RBAC exports
# are from a newer run than Cloud-Admin-Accounts.csv and briefly disagree.
$people = @($cloudAccounts.'Base Username') + @($entra.'Base Username') + @($rbac.'Base Username') + @($onprem.'Base Username') |
          Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

function MinTier($values) {
    $nums = @($values | Where-Object { $_ -ne '' -and $null -ne $_ } | ForEach-Object { [int]$_ })
    # Cast to string: mixes int (a tier resolved) with '' (no tier in that plane) -
    # Sort-Object on a column mixing types throws under $ErrorActionPreference = 'Stop'.
    if ($nums.Count) { return "$(($nums | Measure-Object -Minimum).Minimum)" }
    return ''
}

$rows = foreach ($p in $people) {
    $ca = @(if ($cloudAccountsBy -and $cloudAccountsBy.ContainsKey($p)) { $cloudAccountsBy[$p] })
    $er = @(if ($entraBy         -and $entraBy.ContainsKey($p))         { $entraBy[$p] })
    $rb = @(if ($rbacBy          -and $rbacBy.ContainsKey($p))          { $rbacBy[$p] })
    $o  = @(if ($onpremBy        -and $onpremBy.ContainsKey($p))        { $onpremBy[$p] })

    $entraTier  = MinTier @($er.'Entra Tier')
    $azureTier  = MinTier @($rb.'Azure Tier')
    $onpremTier = MinTier @($o.'AD Tier')
    $overall    = MinTier @($entraTier, $azureTier, $onpremTier)

    # Person name: prefer whichever source resolved a standard account
    $name = @($ca.'Person Display Name') + @($o.'Person Display Name') | Where-Object { $_ } | Select-Object -First 1
    $dept = @($ca.Department) + @($o.Department) | Where-Object { $_ } | Select-Object -First 1
    $title= @($ca.'Job Title') + @($o.'Job Title') | Where-Object { $_ } | Select-Object -First 1

    $cloudEnabled  = @($ca | Where-Object { $_.Enabled -eq 'Yes' })
    $entraEnabled  = @($er | Where-Object { $_.Enabled -eq 'Yes' })
    $rbacEnabled   = @($rb | Where-Object { $_.Enabled -eq 'Yes' })
    $onpremEnabled = @($o  | Where-Object { $_.Enabled -eq 'Yes' })

    # Orphaned if any ENABLED admin account has a disabled or missing standard account.
    # Sourced from the unfiltered $ca (not $er/$rb), so a zero-privilege admin account
    # that's still enabled while its standard account is gone is not invisible here.
    $orphan = @($ca + $o | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })

    $planesHeld = @($entraEnabled.Count -gt 0; $rbacEnabled.Count -gt 0; $onpremEnabled.Count -gt 0) | Where-Object { $_ }
    $multiPlane = $planesHeld.Count -ge 2

    $onpremIdentity = if ($normalOnPremBySam.ContainsKey($p))   { $normalOnPremBySam[$p] }   else { $null }
    $cloudIdentity  = if ($normalCloudByPrefix.ContainsKey($p)) { $normalCloudByPrefix[$p] } else { $null }

    [PSCustomObject][ordered]@{
        'Base Username'                 = $p
        'Person Display Name'           = $name
        'Department'                    = $dept
        'Job Title'                     = $title
        'Has Cloud Admin'               = if ($cloudEnabled.Count) { 'Yes' } else { if ($ca.Count) { 'Disabled only' } else { 'No' } }
        'Cloud Admin Accounts'          = (@($ca.'Admin UPN') -join '; ')
        'Highest Entra Role'            = (@($er.'Highest Entra Role' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'Entra Tier'                    = $entraTier
        'Highest Azure Role'            = (@($rb.'Highest Azure Role' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'Azure Tier'                    = $azureTier
        'Has On-Prem Admin'             = if ($onpremEnabled.Count) { 'Yes' } else { if ($o.Count) { 'Disabled only' } else { 'No' } }
        'On-Prem Admin Accounts'        = (@($o.SamAccountName) -join '; ')
        'Highest AD Group'              = (@($o.'Highest AD Group' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'On-Prem Tier'                  = $onpremTier
        'Privileged In Multiple Planes' = if ($multiPlane) { 'YES' } else { 'No' }
        'Overall Tier'                  = $overall
        'Orphaned Admin Account'        = if ($orphan.Count) { 'YES' } else { 'No' }
        'Total Admin Accounts'          = $ca.Count + $o.Count
        'On-Prem Identity Exists'       = if (-not $normalOnPremFound) { 'Unknown' } elseif ($onpremIdentity) { 'Yes' } else { 'No' }
        'On-Prem Identity Enabled'      = if ($onpremIdentity) { $onpremIdentity.Enabled } else { '' }
        'Cloud Identity Exists'         = if (-not $normalCloudFound) { 'Unknown' } elseif ($cloudIdentity) { 'Yes' } else { 'No' }
        'Cloud Identity Enabled'        = if ($cloudIdentity) { $cloudIdentity.Enabled } else { '' }
    }
}

$rows | Sort-Object @{E={if ($_.'Overall Tier' -eq '') { [int]::MaxValue } else { [int]$_.'Overall Tier' }}}, @{E={$_.'Privileged In Multiple Planes'};Descending=$true}, 'Base Username' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
$t0    = @($rows | Where-Object { $_.'Overall Tier' -eq 0 })
$multi = @($rows | Where-Object { $_.'Privileged In Multiple Planes' -eq 'YES' })
$orph  = @($rows | Where-Object { $_.'Orphaned Admin Account' -eq 'YES' })
$sprawl = @($rows | Where-Object { [int]$_.'Total Admin Accounts' -gt 2 })
$orphanButAlive = @($rows | Where-Object {
    $_.'Orphaned Admin Account' -eq 'YES' -and
    ($_.'On-Prem Identity Enabled' -eq 'Yes' -or $_.'Cloud Identity Enabled' -eq 'Yes')
})

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  People holding privileged access       : $($rows.Count)"
Write-Host "  Tier 0 in at least one plane            : $($t0.Count)" -ForegroundColor Yellow
Write-Host "  Privileged in MULTIPLE planes           : $($multi.Count)" -ForegroundColor Yellow
Write-Host "    One person, two or more control planes. Compromising them once reaches all of them."
if ($orph.Count) {
    Write-Host "  ORPHANED admin accounts                 : $($orph.Count)" -ForegroundColor Red
    Write-Host "    Enabled admin account, standard account disabled or missing. Start here."
}
if ($sprawl.Count) { Write-Host "  Holding more than two admin accounts    : $($sprawl.Count)" }
if ($orphanButAlive.Count) {
    Write-Host "  ORPHANED but enabled on the other plane : $($orphanButAlive.Count)" -ForegroundColor Yellow
    Write-Host "    Standard account missing/disabled where the admin account lives, but an enabled"
    Write-Host "    identity exists on the other plane. Worth a manual check before calling these true"
    Write-Host "    orphans - see 'On-Prem Identity ...' / 'Cloud Identity ...' on the person's row."
}
Write-Host "`nNext: paste into the 'People' tab at cell A2 (columns A-V)." -ForegroundColor Cyan

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

    Reads four inputs, not two - Build-CloudAdminReview.ps1 now splits its output
    across three files so Entra and Azure RBAC remediation can be worked as separate
    projects:

      - Cloud-Admin-Accounts.csv (unfiltered - every cloud admin account, so a
        zero-privilege one is never invisible here even though it's absent from
        the two files below). Drives 'Has Cloud Admin' and orphan detection.
      - Entra-Admins.csv and Azure-RBAC-Admins.csv (filtered to accounts actually
        holding a role in that plane). Drive the per-plane tier and highest-role
        columns.
      - OnPrem-Admins.csv, unchanged.

    Runs offline. It only reads these CSVs and writes a fifth, so it can be run
    wherever you have all four files, with no tenant or domain access needed.

.PARAMETER CloudAccountsPath
    Cloud-Admin-Accounts.csv from Build-CloudAdminReview.ps1.

.PARAMETER EntraPath
    Entra-Admins.csv from Build-CloudAdminReview.ps1.

.PARAMETER AzureRbacPath
    Azure-RBAC-Admins.csv from Build-CloudAdminReview.ps1.

.PARAMETER OnPremPath
    OnPrem-Admins.csv from Build-OnPremAdminReview.ps1.

.PARAMETER OutputPath
    CSV path. Defaults to .\Admin-People.csv

.EXAMPLE
    .\Merge-AdminReview.ps1

.NOTES
    Any input may be omitted or missing - the roll-up still builds from whichever
    are present, and a missing plane shows as 'No'.
#>

[CmdletBinding()]
param(
    [string]$CloudAccountsPath = ".\Cloud-Admin-Accounts.csv",
    [string]$EntraPath         = ".\Entra-Admins.csv",
    [string]$AzureRbacPath     = ".\Azure-RBAC-Admins.csv",
    [string]$OnPremPath        = ".\OnPrem-Admins.csv",
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

Write-Host "  $($cloudAccounts.Count) cloud admin account(s) ($($entra.Count) with an Entra role, $($rbac.Count) with an Azure RBAC role), $($onprem.Count) on-prem admin account(s)" -ForegroundColor Cyan
if ($cloudAccounts.Count -eq 0 -and $onprem.Count -eq 0) { throw "Neither Cloud-Admin-Accounts.csv nor OnPrem-Admins.csv has any rows. Nothing to merge." }

$cloudAccountsBy = $cloudAccounts | Group-Object 'Base Username' -AsHashTable -AsString
$entraBy         = $entra         | Group-Object 'Base Username' -AsHashTable -AsString
$rbacBy          = $rbac          | Group-Object 'Base Username' -AsHashTable -AsString
$onpremBy        = $onprem        | Group-Object 'Base Username' -AsHashTable -AsString

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
    }
}

$rows | Sort-Object @{E={if ($_.'Overall Tier' -eq '') { [int]::MaxValue } else { [int]$_.'Overall Tier' }}}, @{E={$_.'Privileged In Multiple Planes'};Descending=$true}, 'Base Username' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
$t0    = @($rows | Where-Object { $_.'Overall Tier' -eq 0 })
$multi = @($rows | Where-Object { $_.'Privileged In Multiple Planes' -eq 'YES' })
$orph  = @($rows | Where-Object { $_.'Orphaned Admin Account' -eq 'YES' })
$sprawl = @($rows | Where-Object { [int]$_.'Total Admin Accounts' -gt 2 })

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
Write-Host "`nNext: paste into the 'People' tab at cell A2 (columns A-R)." -ForegroundColor Cyan

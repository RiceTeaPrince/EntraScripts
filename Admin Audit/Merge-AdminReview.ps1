<#
.SYNOPSIS
    Merges the cloud and on-premises admin exports into a per-person roll-up for the
    Privileged Access Review workbook.

.DESCRIPTION
    The other two scripts produce one row per admin ACCOUNT. This one produces one
    row per PERSON, joined on the base username that both naming conventions encode.

    That shift matters. Cloud and on-prem admin accounts never mix, but the human
    behind them does: someone holding both is a single point of compromise reaching
    both planes, and no account-level view will show you that.

    Runs offline. It reads the two CSVs and writes a third - no tenant or domain
    access needed, so it can run anywhere after the other two have been executed in
    their respective environments.

.PARAMETER CloudPath
    Cloud-Admins.csv from Build-CloudAdminReview.ps1.

.PARAMETER OnPremPath
    OnPrem-Admins.csv from Build-OnPremAdminReview.ps1.

.PARAMETER OutputPath
    CSV path. Defaults to .\Admin-People.csv

.EXAMPLE
    .\Merge-AdminReview.ps1 -CloudPath .\Cloud-Admins.csv -OnPremPath .\OnPrem-Admins.csv

.NOTES
    Either input may be omitted - the roll-up still builds from whichever is present,
    and the missing plane shows as 'No'.
#>

[CmdletBinding()]
param(
    [string]$CloudPath  = ".\Cloud-Admins.csv",
    [string]$OnPremPath = ".\OnPrem-Admins.csv",
    [string]$OutputPath = ".\Admin-People.csv"
)

$ErrorActionPreference = 'Stop'

$cloud  = if (Test-Path $CloudPath)  { @(Import-Csv $CloudPath) }  else { Write-Warning "Not found: $CloudPath";  @() }
$onprem = if (Test-Path $OnPremPath) { @(Import-Csv $OnPremPath) } else { Write-Warning "Not found: $OnPremPath"; @() }

Write-Host "  $($cloud.Count) cloud admin account(s), $($onprem.Count) on-prem admin account(s)" -ForegroundColor Cyan
if ($cloud.Count -eq 0 -and $onprem.Count -eq 0) { throw "Neither input file has any rows. Nothing to merge." }

$cloudBy  = $cloud  | Group-Object 'Base Username' -AsHashTable -AsString
$onpremBy = $onprem | Group-Object 'Base Username' -AsHashTable -AsString

$people = @($cloud.'Base Username') + @($onprem.'Base Username') |
          Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

function MinTier($values) {
    $nums = @($values | Where-Object { $_ -ne '' -and $null -ne $_ } | ForEach-Object { [int]$_ })
    if ($nums.Count) { return ($nums | Measure-Object -Minimum).Minimum }
    return ''
}

$rows = foreach ($p in $people) {
    $c = @(if ($cloudBy  -and $cloudBy.ContainsKey($p))  { $cloudBy[$p] })
    $o = @(if ($onpremBy -and $onpremBy.ContainsKey($p)) { $onpremBy[$p] })

    $cloudTier  = MinTier @($c.'Overall Tier')
    $onpremTier = MinTier @($o.'AD Tier')
    $overall    = MinTier @($cloudTier, $onpremTier)

    # Person name: prefer whichever source resolved a standard account
    $name = @($c.'Person Display Name') + @($o.'Person Display Name') | Where-Object { $_ } | Select-Object -First 1
    $dept = @($c.Department) + @($o.Department) | Where-Object { $_ } | Select-Object -First 1
    $title= @($c.'Job Title') + @($o.'Job Title') | Where-Object { $_ } | Select-Object -First 1

    $cloudEnabled  = @($c | Where-Object { $_.Enabled -eq 'Yes' })
    $onpremEnabled = @($o | Where-Object { $_.Enabled -eq 'Yes' })

    # Orphaned if any ENABLED admin account has a disabled or missing standard account
    $orphan = @($c + $o | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })

    $bothPlanes = ($cloudEnabled.Count -gt 0 -and $onpremEnabled.Count -gt 0)

    [PSCustomObject][ordered]@{
        'Base Username'          = $p
        'Person Display Name'    = $name
        'Department'             = $dept
        'Job Title'              = $title
        'Has Cloud Admin'        = if ($cloudEnabled.Count)  { 'Yes' } else { if ($c.Count) { 'Disabled only' } else { 'No' } }
        'Cloud Admin Accounts'   = (@($c.'Admin UPN') -join '; ')
        'Highest Entra Role'     = (@($c.'Highest Entra Role' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'Highest Azure Role'     = (@($c.'Highest Azure Role' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'Azure Sub/MG Scoped'    = if (@($c | Where-Object { $_.'Sub or MG Scoped' -eq 'Yes' }).Count) { 'Yes' } else { 'No' }
        'Granting Groups'        = (@($c.'Granting Groups' | Where-Object { $_ }) -join '; ')
        'Assignment Route'       = if (@($c | Where-Object { $_.'Assignment Route' -like '*Group*' }).Count) {
                                       if (@($c | Where-Object { $_.'Assignment Route' -eq 'Group only' }).Count -eq $c.Count) { 'Group only' } else { 'Direct + Group' }
                                   } elseif ($c.Count) { 'Direct only' } else { '' }
        'Cloud Tier'             = $cloudTier
        'Standing Cloud Roles'   = (@($c.'Active Role Count' | ForEach-Object { [int]$_ }) | Measure-Object -Sum).Sum
        'Has On-Prem Admin'      = if ($onpremEnabled.Count) { 'Yes' } else { if ($o.Count) { 'Disabled only' } else { 'No' } }
        'On-Prem Admin Accounts' = (@($o.SamAccountName) -join '; ')
        'Highest AD Group'       = (@($o.'Highest AD Group' | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -First 1) + 'None')[0]
        'On-Prem Tier'           = $onpremTier
        'Privileged In Both Planes' = if ($bothPlanes) { 'YES' } else { 'No' }
        'Overall Tier'           = $overall
        'Orphaned Admin Account' = if ($orphan.Count) { 'YES' } else { 'No' }
        'Total Admin Accounts'   = $c.Count + $o.Count
    }
}

$rows | Sort-Object 'Overall Tier', @{E={$_.'Privileged In Both Planes'};Descending=$true}, 'Base Username' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
$t0    = @($rows | Where-Object { $_.'Overall Tier' -eq 0 })
$both  = @($rows | Where-Object { $_.'Privileged In Both Planes' -eq 'YES' })
$orph  = @($rows | Where-Object { $_.'Orphaned Admin Account' -eq 'YES' })
$multi = @($rows | Where-Object { [int]$_.'Total Admin Accounts' -gt 2 })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  People holding privileged access     : $($rows.Count)"
Write-Host "  Tier 0 in at least one plane         : $($t0.Count)" -ForegroundColor Yellow
Write-Host "  Privileged in BOTH planes            : $($both.Count)" -ForegroundColor Yellow
Write-Host "    One person, both control planes. Compromising them once reaches both."
if ($orph.Count) {
    Write-Host "  ORPHANED admin accounts              : $($orph.Count)" -ForegroundColor Red
    Write-Host "    Enabled admin account, standard account disabled or missing. Start here."
}
if ($multi.Count) { Write-Host "  Holding more than two admin accounts : $($multi.Count)" }
Write-Host "`nNext: paste into the 'People' tab at cell A2 (columns A-U)." -ForegroundColor Cyan

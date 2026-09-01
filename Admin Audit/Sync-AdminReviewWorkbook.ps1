<#
.SYNOPSIS
    Writes the five pipeline CSVs into the matching tabs of the Privileged Access
    Review workbook, in place, without disturbing formulas, manual review columns,
    or header comments.

.DESCRIPTION
    Every Build/Merge/Update script in this pipeline ends with a "paste into the
    'X' tab" reminder because pasting has, until now, been a manual step. It looks
    like a simple copy-paste, but the workbook is not just five plain tables:

      - Each data tab (People, Cloud Admin Accounts, Entra Admins, Azure RBAC
        Admins, On-Prem Admins) has the CSV's own columns on the left, then a
        block of FORMULA columns (ORPHANED?, Risk Flags, Days Since Sign-In/
        Logon, Access Status, Review Status, Auto-Removal Risk) already filled
        down to row 1001, guarded with IF($A2="","",...) so they read blank
        until a row has data - and then a block of MANUAL columns a reviewer
        fills in by hand (Business Justification, Decided By, Review Decision,
        Notes, Last Reviewed, Next Review Due, Line Manager, ...).
      - Every Build/Merge script re-sorts its output on each run (by tier, then
        other keys), so row position is not a stable identity across runs. A
        plain "clear the tab and paste" would either wipe every reviewer's
        manual entries, or worse, silently misalign them - person A's review
        notes ending up next to person B because the sort order shifted.

    So this script does a key-based upsert instead of a paste:

      1. For each tab, match each CSV row to an existing sheet row by its
         natural key (Base Username for People, Admin UPN for the three cloud
         tabs, SamAccountName for On-Prem Admins - always column A).
      2. If found, overwrite ONLY the columns that come from the CSV, by
         matching column NAME (not position) against the sheet's own row-1
         headers. Formula columns and manual columns are never touched -
         they're simply not among the CSV's column names.
      3. If not found, insert the row into the first free pre-provisioned row
         (formula already present, data columns blank).
      4. Any existing row whose key was NOT seen in this run's CSV - someone
         who no longer appears in a fresh export at all - is left completely
         alone except for a 'Not In Latest Export' column, stamped with the
         date this was first noticed. It is never cleared, blanked, or
         deleted; if the person reappears in a later run, the stamp is
         cleared automatically. This is a deliberate choice, made with the
         user: audit history for a leaver is worth more than a tidy sheet.
      5. Column TYPE (text / number / date) for each column is read from
         whatever the sheet already has in that column - not guessed. Getting
         this wrong is the single easiest way to break a formula silently
         (TODAY()-$G2 on a column that ends up holding text, instead of an
         Excel date serial, does not error - it just always evaluates to the
         same wrong number). See the source for exactly how.

    Cell comments on these tabs (the header-row documentation - "0 = control
    plane. See the Role Tiers tab." and so on) are read but never written.
    Testing against a copy of this exact workbook found that EPPlus's comment
    APIs (both Set-CellComment and the raw .AddComment() method) corrupt the
    EXISTING comments on a sheet that already has any - which every data tab
    here does. Adding a comment to the new 'Not In Latest Export' header would
    have been a nice touch; it isn't worth the risk, so this script never
    calls either API.

    A dated backup copy of the workbook is made before anything is written
    (Privileged_Access_Review.pre-sync-<date>.xlsx alongside it, matching the
    pre-*.xlsx convention already used in this folder), unless -NoBackup is
    passed.

    Does NOT create new tabs, and does not touch Dashboard, How to Use,
    Role Tiers, or Reference - only the five tabs with a CSV to match. A tab
    named in this script's parameters that does not exist in the workbook is
    a hard error, not a skip - that almost always means -WorkbookPath is
    pointed at the wrong file.

.PARAMETER WorkbookPath
    The .xlsx to update in place. Must already contain the five named tabs.

.PARAMETER AdminPeoplePath
    Admin-People.csv from Merge-AdminReview.ps1 (ideally after
    Update-AdminPeopleAD.ps1 / Update-AdminPeopleEntra.ps1 too) -> 'People' tab.

.PARAMETER CloudAccountsPath
    Cloud-Admin-Accounts.csv from Build-CloudAdminReview.ps1 -> 'Cloud Admin
    Accounts' tab.

.PARAMETER EntraPath
    Entra-Admins.csv from Build-CloudAdminReview.ps1 -> 'Entra Admins' tab.

.PARAMETER AzureRbacPath
    Azure-RBAC-Admins.csv from Build-CloudAdminReview.ps1 -> 'Azure RBAC
    Admins' tab.

.PARAMETER OnPremPath
    OnPrem-Admins.csv from Build-OnPremAdminReview.ps1 -> 'On-Prem Admins' tab.

.PARAMETER NoBackup
    Skip the automatic pre-sync backup copy. Not recommended - this script
    writes into the workbook in place, and the backup is the only undo.

.PARAMETER SyncDate
    Date used for the 'Not In Latest Export' stamp. Defaults to today. Mainly
    useful for re-running this script against an older CSV set without the
    stamp reading today's date.

.EXAMPLE
    .\Sync-AdminReviewWorkbook.ps1

    Syncs all five CSVs (default paths, current directory) into
    .\Privileged_Access_Review.xlsx.

.EXAMPLE
    .\Sync-AdminReviewWorkbook.ps1 -WorkbookPath 'C:\Reviews\PAR.xlsx' -AdminPeoplePath '.\2026-09-01\Admin-People.csv' -CloudAccountsPath '.\2026-09-01\Cloud-Admin-Accounts.csv' -EntraPath '.\2026-09-01\Entra-Admins.csv' -AzureRbacPath '.\2026-09-01\Azure-RBAC-Admins.csv' -OnPremPath '.\2026-09-01\OnPrem-Admins.csv'

.NOTES
    Requires the ImportExcel module (Install-Module ImportExcel). Any single
    CSV may be missing - that tab is skipped with a warning, matching
    Merge-AdminReview.ps1's own "any input may be omitted" behaviour.

    Any input CSV column with no matching header in its target tab is reported
    as a warning and that column's data is not written anywhere - it is never
    silently dropped without being mentioned. This should only happen if a
    column was renamed in one of the Build/Merge/Update scripts without the
    workbook being updated to match.
#>

[CmdletBinding()]
param(
    [string]$WorkbookPath      = '.\Privileged_Access_Review.xlsx',
    [string]$AdminPeoplePath   = '.\Admin-People.csv',
    [string]$CloudAccountsPath = '.\Cloud-Admin-Accounts.csv',
    [string]$EntraPath         = '.\Entra-Admins.csv',
    [string]$AzureRbacPath     = '.\Azure-RBAC-Admins.csv',
    [string]$OnPremPath        = '.\OnPrem-Admins.csv',
    [switch]$NoBackup,
    [datetime]$SyncDate = (Get-Date).Date
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    throw "ImportExcel module not found. Install-Module ImportExcel -Scope CurrentUser"
}
Import-Module ImportExcel -WarningAction SilentlyContinue
if (-not (Test-Path $WorkbookPath)) { throw "Not found: $WorkbookPath" }

$MissingFlagHeader = 'Not In Latest Export'

# Tab definitions: SheetName, CSV path, key column name (always column A in
# this workbook, but matched by name here rather than assumed).
$tabs = @(
    [PSCustomObject]@{ Sheet = 'People';                CsvPath = $AdminPeoplePath;   KeyColumn = 'Base Username' }
    [PSCustomObject]@{ Sheet = 'Cloud Admin Accounts';   CsvPath = $CloudAccountsPath; KeyColumn = 'Admin UPN' }
    [PSCustomObject]@{ Sheet = 'Entra Admins';           CsvPath = $EntraPath;         KeyColumn = 'Admin UPN' }
    [PSCustomObject]@{ Sheet = 'Azure RBAC Admins';      CsvPath = $AzureRbacPath;     KeyColumn = 'Admin UPN' }
    [PSCustomObject]@{ Sheet = 'On-Prem Admins';         CsvPath = $OnPremPath;        KeyColumn = 'SamAccountName' }
)

# --------------------------------------------------------------------------
# Column type detection. EPPlus returns a plain System.Double for BOTH a date
# cell and a numeric cell when you read .Value - a date is just a number with
# a date NumberFormat applied. So a date is only distinguishable from a plain
# number by also checking the cell's NumberFormat string. Scans down from row
# 2 for the first non-blank cell in each column, rather than trusting row 2
# alone, in case a particular column happens to be blank on whichever row is
# used as the template.
# --------------------------------------------------------------------------
function Get-ColumnType {
    param($Worksheet, [int]$Col, [int]$FirstDataRow, [int]$LastRow)
    for ($r = $FirstDataRow; $r -le $LastRow; $r++) {
        $cell = $Worksheet.Cells[$r, $Col]
        # Deliberately not "-eq ''" here: PowerShell coerces the comparison to the
        # LEFT operand's type, so ($cellValue -eq '') on a numeric 0.0 evaluates
        # True - a legitimate Tier 0 would be treated as blank and skipped, and
        # once every row past it is genuinely blank, the scan falls through to
        # the String default for the whole column. Checking [string] first avoids
        # ever comparing a numeric value against a string this way.
        if ($null -eq $cell.Value) { continue }
        if ($cell.Value -is [string] -and $cell.Value -eq '') { continue }
        if ($cell.Value -is [double] -or $cell.Value -is [int]) {
            if ($cell.Style.Numberformat.Format -match 'y{2,4}') { return 'Date' }
            return 'Number'
        }
        return 'String'
    }
    return 'String'
}

function Convert-CsvValue {
    param([string]$Value, [string]$Type)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    switch ($Type) {
        'Date' {
            $dt = [datetime]::MinValue
            if ([datetime]::TryParseExact($Value, 'dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {
                return $dt
            }
            Write-Warning "Could not parse '$Value' as a date (expected dd/MM/yyyy) - writing as text instead."
            return $Value
        }
        'Number' {
            $n = 0.0
            if ([double]::TryParse($Value, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
                return $n
            }
            return $Value
        }
        default { return $Value }
    }
}

function Sync-Tab {
    param($Package, [string]$SheetName, [string]$CsvPath, [string]$KeyColumn, [datetime]$SyncDate)

    if (-not (Test-Path $CsvPath)) {
        Write-Warning "[$SheetName] CSV not found ($CsvPath) - skipping this tab."
        return
    }
    $csvRows = @(Import-Csv $CsvPath)
    if ($csvRows.Count -eq 0) {
        Write-Warning "[$SheetName] $CsvPath has no rows - skipping this tab."
        return
    }

    $ws = $Package.Workbook.Worksheets[$SheetName]
    if (-not $ws) { throw "Worksheet '$SheetName' not found in the workbook. Check -WorkbookPath points at the right file." }

    # ---- Header map: name -> column index, and vice versa -----------------
    $lastCol = $ws.Dimension.End.Column
    $lastRow = $ws.Dimension.End.Row
    $headerByName = @{}
    for ($c = 1; $c -le $lastCol; $c++) {
        $h = $ws.Cells[1, $c].Value
        if ($h) { $headerByName[[string]$h] = $c }
    }
    if (-not $headerByName.ContainsKey($KeyColumn)) {
        throw "[$SheetName] Key column '$KeyColumn' not found in row 1. Sheet headers may have changed."
    }
    $keyCol = $headerByName[$KeyColumn]

    # ---- CSV columns -> sheet columns, warn about anything unmapped -------
    $csvColumns = @($csvRows[0].PSObject.Properties.Name)
    $colMap = @{}   # csv column name -> sheet column index
    $unmapped = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $csvColumns) {
        if ($headerByName.ContainsKey($name)) { $colMap[$name] = $headerByName[$name] }
        else { $unmapped.Add($name) }
    }
    if ($unmapped.Count) {
        Write-Warning "[$SheetName] $($unmapped.Count) CSV column(s) have no matching header in this tab and will NOT be written anywhere: $($unmapped -join ', ')"
    }

    # ---- Ensure the 'Not In Latest Export' column exists -------------------
    if (-not $headerByName.ContainsKey($MissingFlagHeader)) {
        $newCol = $lastCol + 1
        $ws.Cells[1, $newCol].Value = $MissingFlagHeader
        $ws.Cells[1, $newCol].StyleID = $ws.Cells[1, $lastCol].StyleID
        $lastCol = $newCol
        $newRange = $ws.Cells[1, 1, $lastRow, $lastCol]
        $ws.Cells[$newRange.Address].AutoFilter = $true
        $headerByName[$MissingFlagHeader] = $newCol
        Write-Host "[$SheetName] Added '$MissingFlagHeader' column." -ForegroundColor Cyan
    }
    $missingCol = $headerByName[$MissingFlagHeader]

    # ---- Column type template, built once per column ----------------------
    $colType = @{}
    foreach ($sheetCol in ($colMap.Values | Sort-Object -Unique)) {
        $colType[$sheetCol] = Get-ColumnType -Worksheet $ws -Col $sheetCol -FirstDataRow 2 -LastRow $lastRow
    }

    # ---- Existing key -> row map -------------------------------------------
    $rowByKey = @{}
    $freeRows = [System.Collections.Generic.Queue[int]]::new()
    for ($r = 2; $r -le $lastRow; $r++) {
        $k = $ws.Cells[$r, $keyCol].Value
        if ($k) { $rowByKey[[string]$k] = $r }
        else { $freeRows.Enqueue($r) }
    }

    # ---- Upsert -------------------------------------------------------------
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new()
    $updated = 0; $inserted = 0; $unplaced = 0

    foreach ($csvRow in $csvRows) {
        $key = $csvRow.$KeyColumn
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $seenKeys.Add($key) | Out-Null

        if ($rowByKey.ContainsKey($key)) {
            $r = $rowByKey[$key]
            $updated++
        } elseif ($freeRows.Count -gt 0) {
            $r = $freeRows.Dequeue()
            $rowByKey[$key] = $r
            $inserted++
        } else {
            $unplaced++
            continue
        }

        foreach ($csvColName in $colMap.Keys) {
            $sheetCol = $colMap[$csvColName]
            $ws.Cells[$r, $sheetCol].Value = Convert-CsvValue -Value $csvRow.$csvColName -Type $colType[$sheetCol]
        }
        # Reappeared - clear any earlier missing-flag rather than leaving a stale stamp.
        if ($ws.Cells[$r, $missingCol].Value) { $ws.Cells[$r, $missingCol].Value = $null }
    }

    if ($unplaced -gt 0) {
        Write-Warning "[$SheetName] $unplaced row(s) had no free pre-provisioned row to go into (all rows up to $lastRow are in use). Select the last data row in Excel and fill formulas down further, then re-run."
    }

    # ---- Flag existing rows whose key wasn't in this run's CSV -------------
    $newlyFlagged = 0; $stillFlagged = 0
    foreach ($key in $rowByKey.Keys) {
        if ($seenKeys.Contains($key)) { continue }
        $r = $rowByKey[$key]
        $existing = $ws.Cells[$r, $missingCol].Value
        if (-not $existing) {
            $ws.Cells[$r, $missingCol].Value = "Yes ($($SyncDate.ToString('yyyy-MM-dd')))"
            $newlyFlagged++
        } else {
            $stillFlagged++
        }
    }

    Write-Host "[$SheetName] matched/updated: $updated, inserted: $inserted, newly flagged missing: $newlyFlagged, still flagged missing: $stillFlagged" -ForegroundColor Green
}

# --------------------------------------------------------------------------
# Backup, then sync each tab in one open/save.
# --------------------------------------------------------------------------
if (-not $NoBackup) {
    $dir  = Split-Path -Parent (Resolve-Path $WorkbookPath)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($WorkbookPath)
    $ext  = [System.IO.Path]::GetExtension($WorkbookPath)
    $backupPath = Join-Path $dir "$base.pre-sync-$($SyncDate.ToString('yyyy-MM-dd'))$ext"
    $suffix = 1
    while (Test-Path $backupPath) {
        $backupPath = Join-Path $dir "$base.pre-sync-$($SyncDate.ToString('yyyy-MM-dd'))-$suffix$ext"
        $suffix++
    }
    Copy-Item -Path $WorkbookPath -Destination $backupPath
    Write-Host "Backup: $backupPath" -ForegroundColor Cyan
}

$pkg = Open-ExcelPackage -Path $WorkbookPath
try {
    foreach ($t in $tabs) {
        Sync-Tab -Package $pkg -SheetName $t.Sheet -CsvPath $t.CsvPath -KeyColumn $t.KeyColumn -SyncDate $SyncDate
    }
    Close-ExcelPackage -ExcelPackage $pkg
    Write-Host "`nSaved: $WorkbookPath" -ForegroundColor Green
} catch {
    Close-ExcelPackage -ExcelPackage $pkg -NoSave
    Write-Host "Sync failed - workbook NOT saved. $(if (-not $NoBackup) { "Original untouched; backup at $backupPath is a no-op copy of what was already there." })" -ForegroundColor Red
    throw
}

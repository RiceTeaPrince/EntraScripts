<#
.SYNOPSIS
    Updates a SharePoint-hosted service account inventory workbook in place, using
    the Microsoft Graph Excel API.

.DESCRIPTION
    RECONCILES rather than replaces. For each tab:

      - Identities present in the tenant but not in the sheet  -> a row is ADDED
      - Rows in the sheet whose identity no longer exists       -> the row is REMOVED
      - Everything else                                          -> LEFT ALONE

    Existing rows are never rewritten, so categorisation and ownership entered by a
    human survive every subsequent run. That is the whole point: categorise once.

    Rows are keyed on Object ID, which survives a rename - so a renamed account keeps
    its row and its categorisation rather than being treated as a departure plus an
    arrival. Display Name and UPN are refreshed so the sheet stays searchable, the
    old values are recorded in Previous Identifier, and Row Status is set to RENAMED
    so a repurposed account does not inherit an old categorisation unnoticed.

    Each tab has two column zones. The script-managed zone (left) is written on the
    run that first adds a row. The human zone (right) is never written by this
    script under any circumstance.

    Removed rows are copied to the Archive tab before deletion, so the categorisation
    effort is not silently lost when an account is offboarded.

.PARAMETER SiteUrl
    SharePoint site containing the workbook, e.g.
    https://contoso.sharepoint.com/sites/IdentityGovernance

.PARAMETER FilePath
    Path within the site's document library, e.g.
    Shared Documents/Identity/Service_Account_Inventory.xlsx

.PARAMETER RefreshAttributes
    Also update the script-managed columns on EXISTING rows (enabled state, sign-in
    dates, MFA registration). Off by default, which matches "no changes to existing
    accounts" - but it does mean those columns show the values as at the day the row
    was added, and they age. The human zone is never touched either way.

.PARAMETER PreserveStaleNames
    Do NOT refresh Display Name and User Principal Name on existing rows.

    By default these two ARE refreshed every run, even without -RefreshAttributes,
    because a rename is a new label on the same object rather than new data - and a
    sheet showing an identifier nobody uses any more is unsearchable and quietly
    erodes trust in the whole exercise. The human zone is never touched either way.

    When a rename is detected the previous values are written to Previous Identifier
    and Row Status is set to RENAMED, so it is visible rather than silent.

.PARAMETER NoRestoreFromArchive
    Do not look in the Archive tab when adding a row. By default, if an Object ID
    being added is found in the Archive, its previous categorisation and owner are
    restored - which covers an account soft-deleted and then reinstated inside the
    30-day window, where a naive add would discard work already done.

.PARAMETER MaxDeletePercent
    Safety guard. If a run would delete more than this share of existing rows it
    aborts instead. A collection that fails partway looks exactly like a mass
    offboarding, and the difference matters when the operation is destructive.
    Default 20.

.PARAMETER Force
    Bypass the delete guard. Use only after confirming the collection was healthy.

.PARAMETER WhatIf
    Report what would change without writing anything.

.EXAMPLE
    .\Update-SharePointInventory.ps1 `
        -SiteUrl 'https://contoso.sharepoint.com/sites/IdentityGovernance' `
        -FilePath 'Shared Documents/Identity/Service_Account_Inventory.xlsx' -WhatIf

.NOTES
    Graph application permissions required:
        Sites.ReadWrite.All  (or Sites.Selected, granted on this one site - preferred)
        User.Read.All, Application.Read.All, Directory.Read.All,
        Group.Read.All, Policy.Read.All, AuditLog.Read.All

    Sites.Selected is materially better than Sites.ReadWrite.All: it grants write
    access to one named site instead of every site in the tenant. Set it up with
    Grant-SitePermission below.

    The Excel API operates on files under roughly 25 MB, and works through a
    workbook session. Verify current limits against Microsoft's documentation if
    the workbook grows large.

    Do not edit the workbook while this runs. Schedule it outside business hours.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SiteUrl,
    [Parameter(Mandatory)][string]$FilePath,
    [switch]$RefreshAttributes,
    [switch]$PreserveStaleNames,
    [switch]$NoRestoreFromArchive,
    [int]$MaxDeletePercent = 20,
    [switch]$Force,
    [switch]$UseManagedIdentity
)

$ErrorActionPreference = 'Stop'
$script:GraphBase = 'https://graph.microsoft.com/v1.0'

# ==========================================================================
# Connect
# ==========================================================================
if (-not (Get-MgContext)) {
    if ($UseManagedIdentity) {
        Connect-MgGraph -Identity -NoWelcome
    } else {
        Connect-MgGraph -NoWelcome -Scopes @(
            'Sites.ReadWrite.All','User.Read.All','Application.Read.All',
            'Directory.Read.All','Group.Read.All','Policy.Read.All','AuditLog.Read.All'
        )
    }
}
Write-Host "Connected to tenant $((Get-MgContext).TenantId)" -ForegroundColor Cyan

# ==========================================================================
# Resolve the workbook
# ==========================================================================
function Resolve-WorkbookItem {
    param([string]$SiteUrl, [string]$FilePath)

    if ($SiteUrl -notmatch '^https://([^/]+)/sites/(.+?)/?$') {
        throw "SiteUrl must look like https://tenant.sharepoint.com/sites/SiteName"
    }
    $hostName = $Matches[1]; $sitePath = $Matches[2]

    $site = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphBase/sites/${hostName}:/sites/$sitePath"
    Write-Verbose "Site: $($site.displayName) [$($site.id)]"

    # Strip the library name; Graph addresses paths relative to the default drive
    $rel = $FilePath -replace '^/', '' -replace '^Shared Documents/', '' -replace '^Documents/', ''
    $encoded = ($rel -split '/' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'

    $item = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphBase/sites/$($site.id)/drive/root:/${encoded}"
    Write-Host "Workbook: $($item.name)  ($([math]::Round($item.size/1MB,2)) MB, modified $($item.lastModifiedDateTime))"

    if ($item.size -gt 24MB) {
        Write-Warning "Workbook is close to the Excel API size limit. Consider archiving older rows."
    }
    return [PSCustomObject]@{ SiteId = $site.id; ItemId = $item.id; WebUrl = $item.webUrl }
}

$book = Resolve-WorkbookItem -SiteUrl $SiteUrl -FilePath $FilePath
$wbUri = "$script:GraphBase/sites/$($book.SiteId)/drive/items/$($book.ItemId)/workbook"

# ==========================================================================
# Workbook session. Batching every change into one persistent session is much
# faster than firing individual requests, and keeps the file consistent.
# ==========================================================================
$sessionId = $null
try {
    $s = Invoke-MgGraphRequest -Method POST -Uri "$wbUri/createSession" `
            -Body (@{ persistChanges = $true } | ConvertTo-Json)
    $sessionId = $s.id
    Write-Verbose "Workbook session opened."
} catch {
    Write-Warning "Could not open a workbook session; falling back to sessionless calls: $($_.Exception.Message)"
}

function Invoke-Excel {
    param([string]$Method, [string]$Path, $Body)
    $headers = @{}
    if ($sessionId) { $headers['workbook-session-id'] = $sessionId }
    $splat = @{ Method = $Method; Uri = "$wbUri$Path"; Headers = $headers }
    if ($Body) { $splat.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    return Invoke-MgGraphRequest @splat
}

function Close-WorkbookSession {
    if (-not $sessionId) { return }
    try { Invoke-Excel -Method POST -Path '/closeSession' | Out-Null } catch { }
    $sessionId = $null
}

# ==========================================================================
# Table helpers
# ==========================================================================
function Get-TableRows {
    param([string]$TableName)
    $rows = @()
    $uri = "/tables('$TableName')/rows"
    do {
        $resp = Invoke-Excel -Method GET -Path $uri
        $rows += @($resp.value)
        $next = $resp.'@odata.nextLink'
        if ($next) { $uri = $next -replace [regex]::Escape($wbUri), '' }
    } while ($next)
    return $rows
}

function Get-TableColumnNames {
    param([string]$TableName)
    $resp = Invoke-Excel -Method GET -Path "/tables('$TableName')/columns"
    return @($resp.value | Sort-Object index | ForEach-Object { $_.name })
}

function Add-TableRows {
    param([string]$TableName, [object[][]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return }
    # Chunked: a single enormous payload is rejected and is slower to retry
    $chunk = 100
    for ($i = 0; $i -lt $Values.Count; $i += $chunk) {
        $slice = $Values[$i..([Math]::Min($i + $chunk - 1, $Values.Count - 1))]
        Invoke-Excel -Method POST -Path "/tables('$TableName')/rows/add" `
            -Body @{ values = $slice } | Out-Null
        Write-Verbose "  added rows $($i+1)-$($i+$slice.Count)"
    }
}

function Remove-TableRows {
    param([string]$TableName, [int[]]$Indexes)
    if (-not $Indexes -or $Indexes.Count -eq 0) { return }
    # DESCENDING is mandatory. Deleting row 3 shifts every row after it up by one,
    # so ascending deletion removes the wrong rows from the second delete onward.
    foreach ($i in ($Indexes | Sort-Object -Descending)) {
        Invoke-Excel -Method POST -Path "/tables('$TableName')/rows/itemAt(index=$i)/delete" | Out-Null
    }
}

function Update-TableCell {
    param([string]$TableName, [int]$RowIndex, [int]$ColumnIndex, $Value)
    Invoke-Excel -Method PATCH -Path "/tables('$TableName')/rows/itemAt(index=$RowIndex)/range/cell(row=0,column=$ColumnIndex)" `
        -Body @{ values = @(, @($Value)) } | Out-Null
}

# ==========================================================================
# Reconcile
# ==========================================================================
function Sync-InventoryTable {
    <#
        Adds new identities, removes departed ones, leaves everything else alone.
        $Current must be an array of ordered hashtables whose keys match the
        script-managed column names exactly.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$TabLabel,
        [Parameter(Mandatory)][object[]]$Current,
        [string]$KeyColumn = 'Object ID',
        [int]$ArchiveKeyCount = 3
    )

    Write-Host "`n--- $TabLabel ---" -ForegroundColor Cyan
    $columns  = Get-TableColumnNames -TableName $TableName
    $keyIndex = [array]::IndexOf($columns, $KeyColumn)
    if ($keyIndex -lt 0) { throw "Column '$KeyColumn' not found in table $TableName." }

    $existingRows = Get-TableRows -TableName $TableName
    $existingKeys = @{}
    for ($i = 0; $i -lt $existingRows.Count; $i++) {
        $k = [string]$existingRows[$i].values[0][$keyIndex]
        if ($k) { $existingKeys[$k] = @{ Index = $i; Values = $existingRows[$i].values[0] } }
    }
    $currentKeys = @{}
    foreach ($c in $Current) { if ($c[$KeyColumn]) { $currentKeys[[string]$c[$KeyColumn]] = $c } }

    $toAdd    = @($Current | Where-Object { $_[$KeyColumn] -and -not $existingKeys.ContainsKey([string]$_[$KeyColumn]) })
    $toRemove = @($existingKeys.Keys | Where-Object { -not $currentKeys.ContainsKey($_) })

    $before = $existingRows.Count
    Write-Host "  in sheet: $before   in tenant: $($Current.Count)   to add: $($toAdd.Count)   to remove: $($toRemove.Count)"

    # ---- Safety guard --------------------------------------------------
    # A partial collection failure is indistinguishable from a mass offboarding
    # by row count alone, so refuse the destructive path rather than guess.
    if ($before -gt 0 -and $toRemove.Count -gt 0) {
        $pct = [math]::Round(($toRemove.Count / $before) * 100, 1)
        if ($pct -gt $MaxDeletePercent -and -not $Force) {
            $msg = "ABORTED: would remove $($toRemove.Count) of $before rows ($pct%), above the $MaxDeletePercent% guard. This usually means the collection failed rather than that the accounts are gone. Verify, then re-run with -Force."
            Write-Warning $msg
            Write-RunLog -Tab $TabLabel -Before $before -Added 0 -Removed 0 -After $before -Outcome 'ABORTED' -Detail $msg
            return
        }
    }

    if ($WhatIfPreference) {
        Write-Host "  [WhatIf] no changes written." -ForegroundColor Yellow
        if ($toAdd.Count)    { $toAdd    | Select-Object -First 5 | ForEach-Object { Write-Host "    + $($_[$KeyColumn]) $($_['Display Name'])" } }
        if ($toRemove.Count) { $toRemove | Select-Object -First 5 | ForEach-Object { Write-Host "    - $_" } }
        return
    }

    # ---- Archive then remove -------------------------------------------
    if ($toRemove.Count -gt 0) {
        $archiveRows = foreach ($k in $toRemove) {
            $v = $existingKeys[$k].Values
            $catIdx   = [array]::IndexOf($columns, 'Confirmed Category')
            $ownIdx   = [array]::IndexOf($columns, 'Owner Team')
            $nameIdx  = [array]::IndexOf($columns, 'Display Name')
            $upnIdx   = [array]::IndexOf($columns, 'User Principal Name')
            ,@(
                $k
                if ($nameIdx -ge 0) { [string]$v[$nameIdx] } else { '' }
                if ($upnIdx  -ge 0) { [string]$v[$upnIdx]  } else { '' }
                $TabLabel
                if ($catIdx -ge 0) { [string]$v[$catIdx] } else { '' }
                if ($ownIdx -ge 0) { [string]$v[$ownIdx] } else { '' }
                (Get-Date -Format 'dd/MM/yyyy')
                'No longer present in the tenant'
            )
        }
        Add-TableRows -TableName 'tblArchive' -Values $archiveRows
        Write-Host "  archived $($archiveRows.Count) row(s)"

        $indexes = @($toRemove | ForEach-Object { $existingKeys[$_].Index })
        Remove-TableRows -TableName $TableName -Indexes $indexes
        Write-Host "  removed $($indexes.Count) row(s)"
    }

    # ---- Add new --------------------------------------------------------
    if ($toAdd.Count -gt 0) {

        # An account soft-deleted and then reinstated inside the 30-day window
        # returns with the SAME Object ID. Without this it would be re-added blank
        # and the categorisation already done would be discarded.
        $archived = @{}
        if (-not $NoRestoreFromArchive) {
            try {
                $archCols = Get-TableColumnNames -TableName 'tblArchive'
                $aKey = [array]::IndexOf($archCols, 'Object ID')
                $aCat = [array]::IndexOf($archCols, 'Confirmed Category')
                $aOwn = [array]::IndexOf($archCols, 'Owner Team')
                foreach ($ar in (Get-TableRows -TableName 'tblArchive')) {
                    $ak = [string]$ar.values[0][$aKey]
                    if ($ak) {
                        $archived[$ak] = @{
                            Category = [string]$ar.values[0][$aCat]
                            OwnerTeam = [string]$ar.values[0][$aOwn]
                        }
                    }
                }
            } catch { Write-Verbose "Archive not readable, skipping restore: $($_.Exception.Message)" }
        }

        $restored = 0
        $newRows = foreach ($item in $toAdd) {
            $key = [string]$item[$KeyColumn]
            $prior = $archived[$key]
            if ($prior -and ($prior.Category -or $prior.OwnerTeam)) { $restored++ }
            ,@($columns | ForEach-Object {
                switch ($_) {
                    'Confirmed Category' { if ($prior) { $prior.Category }  else { '' } }
                    'Owner Team'         { if ($prior) { $prior.OwnerTeam } else { '' } }
                    'Row Status'         { if ($prior -and $prior.Category) { 'RESTORED' } else { 'NEW' } }
                    default              { if ($item.Contains($_)) { $item[$_] } else { '' } }
                }
            })
        }
        Add-TableRows -TableName $TableName -Values $newRows
        Write-Host "  added $($toAdd.Count) row(s)"
        if ($restored) {
            Write-Host "  restored prior categorisation for $restored row(s) from the Archive" -ForegroundColor Yellow
        }
    }

    # ---- Rename detection and name refresh ------------------------------
    #
    # Rows are keyed on Object ID, which survives a rename. So a renamed account
    # keeps its row and keeps its categorisation - correct, and the reason the key
    # is not the UPN. But the name columns would otherwise show a value nobody uses
    # any more, so they are refreshed by default and the change is recorded.
    $renamed = 0
    if (-not $PreserveStaleNames) {
        $nameCols = @('Display Name','User Principal Name') |
                    Where-Object { [array]::IndexOf($columns, $_) -ge 0 }
        $prevIdx  = [array]::IndexOf($columns, 'Previous Identifier')
        $statIdx  = [array]::IndexOf($columns, 'Row Status')

        $rowsNow = Get-TableRows -TableName $TableName
        for ($i = 0; $i -lt $rowsNow.Count; $i++) {
            $k = [string]$rowsNow[$i].values[0][$keyIndex]
            if (-not $currentKeys.ContainsKey($k)) { continue }
            $src = $currentKeys[$k]

            $changes = @()
            foreach ($colName in $nameCols) {
                $ci  = [array]::IndexOf($columns, $colName)
                $old = [string]$rowsNow[$i].values[0][$ci]
                $new = [string]$src[$colName]
                if ($old -and $new -and $old -ne $new) {
                    $changes += "$colName was '$old'"
                    Update-TableCell -TableName $TableName -RowIndex $i -ColumnIndex $ci -Value $new
                }
            }
            if ($changes.Count -eq 0) { continue }

            $renamed++
            $note = "$($changes -join '; ') (detected $(Get-Date -Format 'dd/MM/yyyy'))"
            if ($prevIdx -ge 0) { Update-TableCell -TableName $TableName -RowIndex $i -ColumnIndex $prevIdx -Value $note }
            if ($statIdx -ge 0) { Update-TableCell -TableName $TableName -RowIndex $i -ColumnIndex $statIdx -Value 'RENAMED' }
            Write-Verbose "  renamed: $k - $note"
        }
        if ($renamed) {
            Write-Host "  renamed $renamed row(s) - flagged RENAMED for review" -ForegroundColor Yellow
        }
    }

    # ---- Optionally refresh the script zone on existing rows ------------
    $refreshed = 0
    if ($RefreshAttributes) {
        # Only columns the script owns. Anything from 'Confirmed Category'
        # rightwards is off limits, always.
        $humanStart = [array]::IndexOf($columns, 'Confirmed Category')
        if ($humanStart -lt 0) { $humanStart = [array]::IndexOf($columns, 'Owner Team') }
        $volatile = @('Enabled','Last Interactive Sign-In','Last Non-Interactive Sign-In',
                      'MFA Registered','Licensed','Last Sign-In','Days to Expiry',
                      'Next Credential Expiry','CA Excluded','Permission Risk')

        # Re-read: indexes shifted during add and remove
        $rowsNow = Get-TableRows -TableName $TableName
        for ($i = 0; $i -lt $rowsNow.Count; $i++) {
            $k = [string]$rowsNow[$i].values[0][$keyIndex]
            if (-not $currentKeys.ContainsKey($k)) { continue }
            $src = $currentKeys[$k]
            foreach ($colName in $volatile) {
                $ci = [array]::IndexOf($columns, $colName)
                if ($ci -lt 0) { continue }
                if ($humanStart -ge 0 -and $ci -ge $humanStart) { continue }   # never cross the line
                if (-not $src.Contains($colName)) { continue }
                $new = [string]$src[$colName]
                if ([string]$rowsNow[$i].values[0][$ci] -ne $new) {
                    Update-TableCell -TableName $TableName -RowIndex $i -ColumnIndex $ci -Value $new
                    $refreshed++
                }
            }
        }
        Write-Host "  refreshed $refreshed cell(s) in the script-managed zone"
    }

    $after = $before - $toRemove.Count + $toAdd.Count
    $detail = "added $($toAdd.Count), removed $($toRemove.Count), renamed $renamed" +
              $(if ($RefreshAttributes) { ", refreshed $refreshed cell(s)" } else { '' })
    Write-RunLog -Tab $TabLabel -Before $before -Added $toAdd.Count -Removed $toRemove.Count -After $after -Outcome 'OK' -Detail $detail
}

function Write-RunLog {
    param([string]$Tab, [int]$Before, [int]$Added, [int]$Removed, [int]$After,
          [string]$Outcome, [string]$Detail)
    if ($WhatIfPreference) { return }
    try {
        Add-TableRows -TableName 'tblRunLog' -Values @(,@(
            (Get-Date -Format 'dd/MM/yyyy HH:mm'), $Tab, $Before, $Added, $Removed, $After, $Outcome, $Detail
        ))
    } catch { Write-Warning "Could not write to the Run Log: $($_.Exception.Message)" }
}

# ==========================================================================
# Collection
# ==========================================================================
function Get-CurrentUsers {
    Write-Host "`nCollecting user accounts..." -ForegroundColor Cyan
    $props = @('Id','DisplayName','UserPrincipalName','AccountEnabled','CreatedDateTime',
               'UserType','OnPremisesSyncEnabled','AssignedLicenses','SignInActivity','EmployeeId')
    $users = try { Get-MgUser -All -Property $props -PageSize 999 }
             catch {
                Write-Warning "Retrying without signInActivity (needs Entra ID P1)."
                Get-MgUser -All -Property ($props | Where-Object { $_ -ne 'SignInActivity' }) -PageSize 999
             }
    $users = @($users | Where-Object { $_.UserType -ne 'Guest' })

    $mfa = @{}
    try {
        Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
            ForEach-Object { $mfa[$_.Id] = [bool]$_.IsMfaRegistered }
    } catch { Write-Warning "MFA registration report unavailable: $($_.Exception.Message)" }

    $mgr = @{}
    foreach ($u in $users) {
        try { if (Get-MgUserManager -UserId $u.Id -ErrorAction Stop) { $mgr[$u.Id] = $true } } catch { }
    }

    $today = Get-Date -Format 'dd/MM/yyyy'
    foreach ($u in $users) {
        $sa  = $u.SignInActivity
        $li  = if ($sa -and $sa.LastSignInDateTime) { ([datetime]$sa.LastSignInDateTime).ToString('dd/MM/yyyy') } else { '' }
        $lni = if ($sa -and $sa.LastNonInteractiveSignInDateTime) { ([datetime]$sa.LastNonInteractiveSignInDateTime).ToString('dd/MM/yyyy') } else { '' }
        $hasEmp = [bool]$u.EmployeeId
        $hasMgr = [bool]$mgr[$u.Id]
        $mfaReg = if ($mfa.ContainsKey($u.Id)) { if ($mfa[$u.Id]) { 'Yes' } else { 'No' } } else { 'Unknown' }

        # Suggested category. Informational only - the human column is authoritative.
        $name = "$($u.DisplayName) $($u.UserPrincipalName)".ToLower()
        $suggestion = 'Standard User'; $confidence = 'Low'
        if ($name -match 'break[\s\-_]?glass|emergency|firecall') { $suggestion = 'Break-Glass (Emergency Access)'; $confidence = 'Medium' }
        elseif ($name -match '^(svc|sa|srv|app|int|auto)[-_. ]|service|automation|integration|daemon|batch') { $suggestion = 'Service Account'; $confidence = 'High' }
        elseif (-not $li -and $lni) { $suggestion = 'Service Account'; $confidence = 'High' }
        elseif ($name -match 'shared|mailbox|reception') { $suggestion = 'Shared / Departmental'; $confidence = 'Medium' }
        elseif ($name -match 'test|uat|dummy') { $suggestion = 'Test Account'; $confidence = 'Medium' }
        elseif ($hasEmp -and $hasMgr) { $suggestion = 'Standard User'; $confidence = 'High' }

        [ordered]@{
            'Object ID'                   = $u.Id
            'Display Name'                = $u.DisplayName
            'User Principal Name'         = $u.UserPrincipalName
            'Enabled'                     = if ($u.AccountEnabled) { 'Yes' } else { 'No' }
            'Created'                     = if ($u.CreatedDateTime) { ([datetime]$u.CreatedDateTime).ToString('dd/MM/yyyy') } else { '' }
            'Last Interactive Sign-In'    = $li
            'Last Non-Interactive Sign-In'= $lni
            'MFA Registered'              = $mfaReg
            'Licensed'                    = if (@($u.AssignedLicenses).Count -gt 0) { 'Yes' } else { 'No' }
            'Identity Source'             = if ($u.OnPremisesSyncEnabled) { 'Hybrid Synced' } else { 'Cloud-only' }
            'Has Manager'                 = if ($hasMgr) { 'Yes' } else { 'No' }
            'Has EmployeeId'              = if ($hasEmp) { 'Yes' } else { 'No' }
            'Suggested Category'          = $suggestion
            'Confidence'                  = $confidence
            'First Seen'                  = $today
            'Row Status'                  = 'NEW'
        }
    }
}

function Get-CurrentServicePrincipals {
    Write-Host "Collecting service principals..." -ForegroundColor Cyan
    # Adapt from Build-IdentityInventory.ps1. Keys must match the table columns.
    # Left as a stub so the two implementations are not duplicated here - move the
    # collection body into a shared module and call it from both.
    return @()
}

function Get-CurrentManagedIdentities {
    Write-Host "Collecting managed identities..." -ForegroundColor Cyan
    return @()
}

# ==========================================================================
# Run
# ==========================================================================
try {
    $users = @(Get-CurrentUsers)
    Sync-InventoryTable -TableName 'tblUserCategorisation' -TabLabel 'User Categorisation' -Current $users

    $sps = @(Get-CurrentServicePrincipals)
    if ($sps.Count) { Sync-InventoryTable -TableName 'tblServicePrincipals' -TabLabel 'Service Principals' -Current $sps }

    $mis = @(Get-CurrentManagedIdentities)
    if ($mis.Count) { Sync-InventoryTable -TableName 'tblManagedIdentities' -TabLabel 'Managed Identities' -Current $mis }

    Write-Host "`nDone. $($book.WebUrl)" -ForegroundColor Green
}
finally {
    Close-WorkbookSession
}

# ==========================================================================
# One-off: grant Sites.Selected write access to just this site
# ==========================================================================
<#
Sites.Selected is the least-privilege option: it grants nothing until you
explicitly permission the identity on a named site, unlike Sites.ReadWrite.All
which reaches every site in the tenant.

    Connect-MgGraph -Scopes 'Sites.FullControl.All'

    $siteId = (Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/IdentityGovernance').id

    $body = @{
        roles = @('write')
        grantedToIdentities = @(@{
            application = @{
                id          = '<managed identity APPLICATION id>'
                displayName = 'aa-identity-governance'
            }
        })
    }

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/permissions" `
        -Body ($body | ConvertTo-Json -Depth 5)
#>

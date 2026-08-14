# SharePoint Self-Updating Service Account Inventory

A workbook hosted in SharePoint that an Azure Automation runbook keeps current, while preserving categorisation work entered by hand.

**Core behaviour:** new identities are added, departed identities are removed, and everything else is left exactly as it was. You categorise each account once.

---

## Contents

1. [How persistence works](#1-how-persistence-works)
2. [Files](#2-files)
3. [Prerequisites](#3-prerequisites)
4. [Upload and configure the workbook](#4-upload-and-configure-the-workbook)
5. [Permissions](#5-permissions)
6. [Sites.Selected](#6-sitesselected)
7. [First run](#7-first-run)
8. [Scheduling](#8-scheduling)
9. [The categorisation workflow](#9-the-categorisation-workflow)
10. [Design decisions worth understanding](#10-design-decisions-worth-understanding)
11. [Troubleshooting](#11-troubleshooting)
12. [Extending it](#12-extending-it)

---

## 1. How persistence works

Each tab is a real **Excel Table**, addressed by name through the Graph Excel API. Every run reconciles three sets:

```
in tenant, not in sheet   ->  ADD a row (Row Status = NEW)
in sheet, not in tenant   ->  ARCHIVE the row, then REMOVE it
in both                   ->  LEAVE ALONE
```

Columns are zoned. On the User Categorisation tab:

| Columns | Zone | Written by |
|---|---|---|
| A–P | Script-managed | The runbook, on the run that first adds the row |
| Q–X | Human | You, only ever |

The runbook has no code path that writes into the human zone. Even `-RefreshAttributes` explicitly checks the column index against the zone boundary and skips anything at or beyond it.

**Why the Graph Excel API rather than download-modify-upload.** Downloading the file, rewriting it and uploading replaces the whole workbook — losing formatting, dropdowns, conditional formatting and any concurrent edit. The Excel API touches only the specific rows, in place.

---

## 2. Files

| File | Purpose |
|---|---|
| `Service_Account_Inventory_SharePoint.xlsx` | The workbook. Upload to SharePoint. |
| `Update-SharePointInventory.ps1` | The runbook. |

### Tabs

| Tab | Table name | Behaviour |
|---|---|---|
| Dashboard | — | Formulas over rows 2–5000 |
| How to Use | — | In-workbook summary |
| **User Categorisation** | `tblUserCategorisation` | Reconciled; human zone preserved |
| Service Principals | `tblServicePrincipals` | Reconciled; human zone preserved |
| Managed Identities | `tblManagedIdentities` | Reconciled; human zone preserved |
| Archive | `tblArchive` | Append-only record of removed rows |
| Run Log | `tblRunLog` | Append-only run history |
| Reference | — | Drop-down lists. Never touched. |

> **Do not rename tabs, tables or columns.** The runbook addresses all three by name and will fail rather than guess.

---

## 3. Prerequisites

- Azure Automation Account with a system-assigned managed identity — see the main Automation Guide, sections 3–4
- Graph PowerShell sub-modules imported: `Microsoft.Graph.Authentication`, `.Users`, `.Identity.DirectoryManagement`, `.Applications`, `.Reports`, `.Groups`
- A SharePoint site and document library for the workbook
- PowerShell 7.2 or later runtime

---

## 4. Upload and configure the workbook

Upload `Service_Account_Inventory_SharePoint.xlsx` to your document library, then note the two values the runbook needs:

```powershell
$siteUrl  = 'https://contoso.sharepoint.com/sites/IdentityGovernance'
$filePath = 'Shared Documents/Identity/Service_Account_Inventory.xlsx'
```

Verify Graph can resolve it before going further:

```powershell
Connect-MgGraph -Scopes 'Sites.Read.All'

$site = Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/IdentityGovernance'

$item = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drive/root:/Identity/Service_Account_Inventory.xlsx"

$item.name; $item.id

# Confirm the tables came through the upload intact
Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drive/items/$($item.id)/workbook/tables" |
    Select-Object -ExpandProperty value | Select-Object name
```

You should see all five table names. If you see none, the upload flattened the tables — re-upload without opening and re-saving in a converter.

**Turn off automatic checkout** on the library. A checked-out file cannot be written by the runbook.

---

## 5. Permissions

Graph **application** permissions on the managed identity:

| Permission | For |
|---|---|
| `Sites.Selected` *(preferred)* or `Sites.ReadWrite.All` | Writing the workbook |
| `User.Read.All` | User accounts |
| `Application.Read.All` | Service principals, managed identities |
| `Directory.Read.All` | Directory objects |
| `Group.Read.All` | Group expansion |
| `Policy.Read.All` | Conditional Access policies |
| `AuditLog.Read.All` | Sign-in activity, MFA registration |

Assign with the app-role-assignment pattern from the main Automation Guide, section 5.

---

## 6. Sites.Selected

`Sites.ReadWrite.All` grants write access to **every SharePoint site in the tenant**, which is far more than this needs. `Sites.Selected` grants nothing until you explicitly permission the identity on a named site.

Grant the app role, then permission the one site:

```powershell
Connect-MgGraph -Scopes 'Sites.FullControl.All','AppRoleAssignment.ReadWrite.All'

$siteId = (Invoke-MgGraphRequest -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/sites/contoso.sharepoint.com:/sites/IdentityGovernance').id

# The managed identity's APPLICATION id, not its object id
$miAppId = (Get-MgServicePrincipal -ServicePrincipalId $miObjectId).AppId

$body = @{
    roles = @('write')
    grantedToIdentities = @(@{
        application = @{ id = $miAppId; displayName = 'aa-identity-governance' }
    })
}

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/permissions" `
    -Body ($body | ConvertTo-Json -Depth 5)

# Verify
Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/sites/$siteId/permissions"
```

Worth the extra ten minutes. It's the difference between an automation account that can rewrite any document in the tenant and one that can write a single file.

---

## 7. First run

Always start with `-WhatIf`:

```powershell
Connect-MgGraph -Scopes 'Sites.ReadWrite.All','User.Read.All','Directory.Read.All','AuditLog.Read.All'

.\Update-SharePointInventory.ps1 `
    -SiteUrl  'https://contoso.sharepoint.com/sites/IdentityGovernance' `
    -FilePath 'Shared Documents/Identity/Service_Account_Inventory.xlsx' `
    -WhatIf -Verbose
```

Expected output on a clean workbook:

```
--- User Categorisation ---
  in sheet: 1   in tenant: 487   to add: 487   to remove: 1
  [WhatIf] no changes written.
```

The single removal is the pale-yellow example row — its Object ID doesn't exist in your tenant, so the reconcile cleans it up naturally. That is the design working.

Then run for real:

```powershell
.\Update-SharePointInventory.ps1 -SiteUrl $siteUrl -FilePath $filePath -Verbose
```

Open the workbook and check: the example row is gone, real accounts are present, Row Status reads NEW, and the human columns are empty.

### Publishing as a runbook

```powershell
Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa `
    -Path .\Update-SharePointInventory.ps1 -Name 'Update-SharePointInventory' `
    -Type PowerShell72 -Force -Published
```

In the runbook, pass `-UseManagedIdentity`.

---

## 8. Scheduling

```powershell
New-AzAutomationSchedule -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name 'SharePointInventory-Weekly' `
    -StartTime (Get-Date '05:00').AddDays(1) `
    -WeekInterval 1 -DaysOfWeek Monday -TimeZone 'Australia/Sydney'

Register-AzAutomationScheduledRunbook -ResourceGroupName $rg -AutomationAccountName $aa `
    -RunbookName 'Update-SharePointInventory' -ScheduleName 'SharePointInventory-Weekly' `
    -Parameters @{
        SiteUrl            = $siteUrl
        FilePath           = $filePath
        UseManagedIdentity = $true
    }
```

**Schedule outside business hours.** The Excel API and a person editing in Excel Online can conflict, and the loser is usually the person's unsaved work. 5am Monday means new accounts are waiting when the team starts, with no overlap.

**Weekly suits categorisation work.** Daily produces a trickle nobody batches; monthly produces a pile nobody starts.

---

## 9. The categorisation workflow

Each Monday:

1. Open the workbook. The Dashboard shows **New since last run**.
2. Go to User Categorisation, filter **Row Status = NEW**.
3. For each row, read **Suggested Category** and **Confidence**, then set **Confirmed Category**. The red highlight clears as you go.
4. For anything you mark as a service account, set **Owner Team** while you're there — it's much harder to establish later.

The runbook sets Row Status to `NEW` only when it adds the row, and never touches it again. If you'd like rows to drop off the NEW filter once handled, add a formula column outside the table, or overwrite Row Status yourself — the runbook won't mind.

**Suggested Category is a starting point, not an answer.** The strongest signal it uses is a blank interactive sign-in date with a populated non-interactive one — close to definitive for a service account. Break-glass detection relies entirely on naming convention, so verify those specifically.

---

## 10. Design decisions worth understanding

### The delete guard

A collection that fails partway looks identical to a mass offboarding if you only count rows. Since deletion is destructive and categorisation is expensive, the runbook refuses to remove more than **20%** of rows in one run:

```
ABORTED: would remove 312 of 487 rows (64.1%), above the 20% guard.
```

It logs to the Run Log and exits without touching anything. Verify the collection was healthy, then re-run with `-Force`. Tune with `-MaxDeletePercent`.

### Archive before delete

Every removed row is copied to the Archive tab with its category, owner and removal date first. When someone leaves and returns, or an account is deleted in error, the categorisation is recoverable.

### Descending delete order

Deleting a table row shifts every subsequent row up by one. Deleting ascending removes the wrong rows from the second delete onward — silently, with no error. The runbook sorts descending before deleting. Worth knowing if you modify that code.

### `-RefreshAttributes` is off by default

This matches "no changes to existing accounts", and keeps the tab stable. The trade-off: `Enabled`, sign-in dates and MFA status show values as at the day the row was added, so after a year they're stale.

Turn it on if currency matters more than stability. It still never writes into the human zone — the check is on column index against the zone boundary, not on a list of column names, so it holds even if you add columns.

### Row Status and First Seen

Without a way to find the 12 new rows among 487, nobody categorises anything. These two columns make the weekly workflow a filter rather than a search.

---

## 11. Troubleshooting

**`Item not found` resolving the file.**
Graph addresses paths relative to the drive root, so the library name is stripped. `Shared Documents/Identity/file.xlsx` becomes `/Identity/file.xlsx`. Confirm with the verification snippet in section 4.

**`Access denied` writing, but reads work.**
Using `Sites.Selected` without granting site permission. Reading may succeed via another permission while writing fails. Check `GET /sites/{id}/permissions`.

**`The workbook cannot be opened because it is locked.`**
Someone has it open in the desktop app, or automatic checkout is enabled on the library. Turn off automatic checkout and reschedule outside business hours.

**Tables missing after upload.**
Some conversion paths flatten Excel Tables to plain ranges. Re-upload the original file. Verify with `GET /workbook/tables`.

**Rows added at the bottom instead of inside the table.**
The table range no longer covers the data. Click inside the table in Excel, then **Table Design → Resize Table**, and save.

**Categorisation disappeared after a run.**
Should not happen — the runbook has no write path into the human zone. Check Run Log for a large `Removed` count, then Archive for the rows. Recover the file through **SharePoint version history** if needed.

**Run takes longer each week.**
Row-by-row cell updates from `-RefreshAttributes` are the usual cause. Consider running it monthly rather than weekly, or turning it off.

**`Request payload too large`.**
Reduce the chunk size in `Add-TableRows` from 100.

**Session errors mid-run.**
Workbook sessions expire after a period of inactivity. The script falls back to sessionless calls, which are slower but work. Persistent failures usually mean the file is locked.

---

## 12. Extending it

**Complete the collection stubs.** `Get-CurrentServicePrincipals` and `Get-CurrentManagedIdentities` are stubs. Lift the bodies from `Build-IdentityInventory.ps1` and `Build-AzureResourceMap.ps1` into a shared module so one implementation serves both the interactive and automated paths — and they can't drift apart.

**Email the newly added rows.** Pair with the reporting runbook from the Automation Guide: after each sync, mail the categorisation owners a short list of what's new, linked to the workbook. A weekly nudge sustains the habit far better than a workbook nobody remembers to open.

**Power Automate on categorisation.** Trigger a flow when Confirmed Category is set to notify the nominated Owner Team, turning categorisation into ownership assignment without a second pass.

**Sensitivity labels.** The workbook lists every account in your tenant with its classification. Label it and restrict library access accordingly.

**Consider a SharePoint List instead.** If the workbook grows past a few thousand rows or several people categorise simultaneously, a List handles concurrency and versioning better, offers per-item permissions, and drives Power Apps natively. Excel is the right answer while the audience is small and the formulas earn their place; a List is the right answer once this becomes a shared operational process.

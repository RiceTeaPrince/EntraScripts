# Service Identity Inventory — Delivery Runbook

**Scope:** Build a complete inventory of user accounts, service principals and managed identities in Microsoft Entra ID, flag which are excluded from Conditional Access policies, and triage the highest-risk subset.

**Out of scope (deliberately):** Full ownership assignment and exclusion governance backfill across all identities. Those are a separate multi-week piece of work.

**Estimated:** 2–3 days.

---

## Files you need

| File | Used in |
|---|---|
| `Build-CAExclusionMap.ps1` | Step 4 |
| `Build-AzureResourceMap.ps1` | Step 5 |
| `Build-IdentityInventory.ps1` | Step 6 |
| `Entra_Service_Identity_Inventory.xlsx` | Step 7 onward |
| `Get-ServiceAccountExclusions.ps1` | Step 3 (optional sizing run) |
| `Service-Identity-Inventory-Guide.md` | Reference throughout |

---

## Step 1 — Set up the environment

**~20 minutes**

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser
```

Create the working folder and place all four working files in it:

```powershell
mkdir C:\identity-inventory\output
cd C:\identity-inventory
```

```
C:\identity-inventory\
├── Build-CAExclusionMap.ps1
├── Build-AzureResourceMap.ps1
├── Build-IdentityInventory.ps1
├── Get-ServiceAccountExclusions.ps1
├── Entra_Service_Identity_Inventory.xlsx
└── output\
```

---

## Step 2 — Connect and verify scopes

**~10 minutes**

```powershell
Connect-MgGraph -Scopes 'Policy.Read.All','Group.Read.All','Directory.Read.All',
  'User.Read.All','Application.Read.All','AuditLog.Read.All',
  'RoleManagement.Read.Directory','Organization.Read.All'

Connect-AzAccount
```

**Checkpoint — do not skip.** A missing scope surfaces as blank columns three steps later, with no error:

```powershell
(Get-MgContext).Scopes | Sort-Object
(Get-AzContext).Account.Id
```

Confirm all eight Graph scopes are listed.

---

## Step 3 — Sizing run (optional but recommended)

**~15 minutes**

```powershell
.\Get-ServiceAccountExclusions.ps1 -IncludeWorkloadIdentities -Identification Naming
```

Record two numbers from the console summary:

- **Total identities** — if any single type exceeds 200, you'll extend the workbook in Step 7a
- **Excluded count** — if it exceeds 2,000, extend the map tabs too

This run is throwaway. Its only purpose is sizing.

---

## Step 4 — Build the CA exclusion map

**~5–15 minutes**

```powershell
.\Build-CAExclusionMap.ps1 -OutputPath .\output\CA-Exclusion-Map.csv -Verbose
```

**Watch for:** unresolved group warnings. Each one is an exclusion group the script couldn't expand, meaning members are missing from the map. If any appear, check the generated `CA-Exclusion-Mapunresolved.csv` and resolve the permission issue before continuing.

**Checkpoint:** console reports policies considered and unique excluded identities. Zero excluded identities on a tenant with CA policies means something is wrong.

---

## Step 5 — Build the Azure resource map

**~5–20 minutes**

```powershell
.\Build-AzureResourceMap.ps1 -OutputPath .\output\Azure-Resource-Map.csv -UseTenantScope -Verbose
```

**Watch for:** a low principal count. Role assignments you lack Reader on simply don't appear — silently, with no error. If the number looks implausibly small for your estimate, fix scope coverage before continuing rather than concluding the tenant is clean.

---

## Step 6 — Build the identity inventory

**~20–60 minutes, unattended**

```powershell
.\Build-IdentityInventory.ps1 -OutputFolder .\output -Verbose
```

This is the slow script — it makes per-object calls for managers, owners and permission grants.

Produces three files in `output\`:

- `Inventory-Accounts.csv`
- `Inventory-ServicePrincipals.csv`
- `Inventory-ManagedIdentities.csv`

**Watch for:** the inferred-category count in the summary. You'll verify those in Step 9.

---

## Step 7 — Prepare the workbook

**~15 minutes**

Open `Entra_Service_Identity_Inventory.xlsx`.

### 7a. Extend rows, if Step 3 said you need to

Do this **before** pasting anything.

- **Identity tabs:** select all of row 201, copy, paste into rows 202 onward to the count you need
- **Map tabs:** select all of row 2001, copy, paste down as needed

Formulas are relative and will follow.

### 7b. Delete the example rows

Delete the contents of **row 2** on all five data tabs:

- Accounts
- Service Principals
- Managed Identities
- CA Exclusion Map
- Azure Resource Map

They're pale yellow and are counted in every Dashboard figure until removed.

---

## Step 8 — Load the data

**~20 minutes**

For each file below: open the CSV, select everything **below the header row**, copy, then paste at cell **A2** of the matching tab.

| Source file | Destination tab | Columns |
|---|---|---|
| `output\CA-Exclusion-Map.csv` | CA Exclusion Map | A–I |
| `output\Azure-Resource-Map.csv` | Azure Resource Map | A–O |
| `output\Inventory-Accounts.csv` | Accounts | A–P |
| `output\Inventory-ServicePrincipals.csv` | Service Principals | A–Q |
| `output\Inventory-ManagedIdentities.csv` | Managed Identities | A–H |

**Never paste into the last column of either map tab.** That column is a formula flagging entries missing from your inventory.

### 8a. Check the date locale

Find any date after the 12th of a month — for example `13/08/2026`. If it renders left-aligned as text, or has flipped to a US reading, fix it now:

> Select the affected date columns → **Data → Text to Columns → Next → Next → Date: DMY → Finish**

Every expiry and review calculation depends on this.

### 8b. Recalculate

Press **F9**.

**Checkpoint:** Dashboard → **Import Coverage** section at the bottom. Both map row counts should be non-zero and both snapshot dates should show today. If either reads zero, that paste didn't land.

---

## Step 9 — Validate

**~2–3 hours. Do not skip this — it is what makes the output defensible.**

### 9a. Spot-check the exclusion join

Pick three identities the workbook shows as `CA Excluded? = Yes`. For each, open the named policy in the Entra portal and confirm both the exclusion and the group membership.

You are proving the lookup works before anyone else relies on it.

### 9b. Verify inferred account categories

On the **Accounts** tab, filter column D for `(inferred)`.

Break-glass detection depends entirely on your naming convention. Check those specifically. If the pattern is wrong, edit the regex in the `Get-AccountCategory` function inside `Build-IdentityInventory.ps1`, then re-run Step 6 and re-paste the Accounts tab.

### 9c. Work the two coverage gaps

Filter the final column of each map tab for `NOT IN INVENTORY`:

- **CA Exclusion Map** — identities excluded from CA that aren't in your inventory
- **Azure Resource Map** — principals holding Azure roles that appear in none of your three tabs

Both are usually revealing on a first run. Investigate anything unexpected; these often surface forgotten deployment service principals.

### 9d. Reconcile totals

Dashboard **Population** figures should roughly match your tenant. A large shortfall usually means the `-MaxObjects` cap (default 5000) truncated a collection — re-run Step 6 with a higher value.

---

## Step 10 — Triage

**~1–2 hours. This is the deliverable.**

On each of the three identity tabs, filter for:

- `CA Excluded? = Yes` **and** `Sub / MG Scoped? = Yes`

Then separately:

- `Highest Azure Role` = `Owner` or `User Access Administrator`

Combine into a single list — typically 10–25 rows. These are identities with no Conditional Access enforcement and broad Azure control-plane rights.

Copy them into a new sheet in the same workbook named **Triage**.

---

## Step 11 — Backfill the triage list only

**~10–15 hours. Strongly recommended.**

For each row on the Triage list, fill the governance columns on its home tab:

- Exclusion Justification
- Exclusion Approved By
- Exclusion Approved Date
- **Exclusion Expiry Date**
- Compensating Controls
- Owner Team, Owner Name, Owner Email

**Shortcuts for the ownership fields:**

| Tab | Column | Contains |
|---|---|---|
| Service Principals | P | Registered owner from Graph |
| Accounts | O | Manager |
| Managed Identities | O | Azure resource `Owner` tag |

Confirm before recording — these are starting points, not answers. But confirming a name is far faster than finding one.

**Why this matters:** without it you're reporting *"we have 47 exclusions and don't know why any exist."* With it: *"we have 47 exclusions; the 15 carrying real risk are documented, approved and time-bound; the remaining 32 are scheduled."* The second is a position. The first is a problem statement.

It also stress-tests the process cheaply — if fifteen rows takes far longer than expected, you've learned something useful about full-scale effort before committing to it.

---

## Step 12 — Prepare for presentation

**~1 hour**

### 12a. Hide the empty columns

Hide the manual columns you didn't backfill. On the **Accounts** tab that's roughly Y–AB and AE–AQ; equivalent ranges on the other two tabs.

A workbook that looks 30% complete invites questions about the missing 70%. One showing only populated columns reads as finished. Unhide when the work resumes.

### 12b. Add a scope note

On the **Dashboard**, in a blank cell below the last section, record:

> Snapshot: [date]. Scope: inventory and triage. Ownership assignment and full exclusion governance backfill are deliberately deferred — see [reference]. Red status indicates undocumented, not unapproved.

In six months nobody will remember that was a decision rather than an oversight.

### 12c. Save the baseline

```
Entra_Service_Identity_Inventory_YYYY-MM-DD_baseline.xlsx
```

Mark it read-only. This is your evidence artefact.

---

## Step 13 — Frame the handover

**~30 minutes**

The Dashboard will look alarming — nearly every exclusion showing `NO EXPIRY SET` in red, ownership columns largely empty. **State the framing before anyone sees it**, or the conversation becomes about the colour rather than the content.

Suggested framing:

> This is a coverage baseline, not a compliance assessment. Red indicates undocumented, not unapproved. Most of these exclusions are probably legitimate, but none currently carries a recorded justification or end date. Establishing that is a separate piece of work.

**Lead with the numbers that are complete and need no caveats:**

- Total identities by type
- How many are excluded from one or more CA policies
- How many are excluded **directly** rather than via a group *(these bypass any group-membership review)*
- The two `NOT IN INVENTORY` counts
- The triage list size, with those rows documented

Close with a proposal rather than a finding. *"Here is our exposure, here is what we propose next"* tends to get resourced. *"Here is our exposure"* tends to get filed.

---

## Step 14 — Establish the monthly refresh

**~30 minutes per month**

Highest-value habit available from here. Re-run Steps 4–6 monthly and diff the new `CA-Exclusion-Map.csv` against the previous month's.

```powershell
Compare-Object `
  (Import-Csv .\output\CA-Exclusion-Map-previous.csv) `
  (Import-Csv .\output\CA-Exclusion-Map.csv) `
  -Property ObjectId, ExclusionGroups -PassThru |
  Where-Object SideIndicator -eq '=>'
```

New exclusions documented at creation cost minutes. The same exclusion investigated two years later costs hours.

**When re-pasting into the workbook:** clear the existing map data first — select A2 through the last populated row in columns A–I (CA map) or A–O (Azure map) and press Delete. Do **not** delete entire rows; that shifts the formula column. Then paste the new snapshot at A2.

Since you're carrying little manual data at this scope, row-realignment is a minor concern. If you completed Step 11, keep those Object IDs noted separately so you can re-locate the backfilled rows after a refresh.

---

## Quick reference

| Step | Action | Time |
|---|---|---|
| 1–2 | Setup and connect | 30 min |
| 3 | Sizing run | 15 min |
| 4–6 | Run the three scripts | 30–90 min |
| 7–8 | Load the workbook | 35 min |
| 9 | Validate | 2–3 h |
| 10 | Triage | 1–2 h |
| 11 | Backfill triage list | 10–15 h |
| 12–13 | Prepare and present | 1.5 h |
| 14 | Monthly refresh | 30 min/month |

Full column references, troubleshooting and regulatory mapping are in `Service-Identity-Inventory-Guide.md`.

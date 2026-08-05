# Entra ID Service Identity Inventory — Operator Guide

A unified inventory of user accounts, service principals and managed identities in Microsoft Entra ID, tracking Conditional Access exclusions and accountable ownership across all three.

**Version:** 2 · **Last updated:** 5 August 2026

---

## Contents

1. [What this is](#1-what-this-is)
2. [Files](#2-files)
3. [Prerequisites](#3-prerequisites)
4. [First run](#4-first-run)
5. [The refresh cycle](#5-the-refresh-cycle)
6. [Paste zones](#6-paste-zones)
7. [Column reference](#7-column-reference)
8. [What you fill in by hand, and why](#8-what-you-fill-in-by-hand-and-why)
9. [Reading the Dashboard](#9-reading-the-dashboard)
10. [Troubleshooting](#10-troubleshooting)
11. [Known limits and things to verify](#11-known-limits-and-things-to-verify)
12. [Extending it](#12-extending-it)
13. [Australian regulatory context](#13-australian-regulatory-context)

---

## 1. What this is

Three tabs, one per identity type, sharing an identical Conditional Access exclusion block and ownership block so they can be stacked into a single view.

The design principle throughout: **anything the directory can tell you is imported; anything requiring judgement is entered by a human.** The imported columns are grey or teal and formula-driven. The manual columns are the audit trail — why an exclusion exists, who approved it, when it lapses, what mitigates it. If a script could write those fields they would mean nothing.

Three read-only PowerShell scripts feed the workbook. None of them writes to your tenant.

### The core mechanic

Conditional Access exclusions are group-based, and groups nest. Manually recording "is this account excluded?" goes stale the moment someone adds a nested group to an existing exclusion group.

Instead, `Build-CAExclusionMap.ps1` reads every CA policy, expands every excluding group transitively, and produces a flat Object ID → exclusion mapping. The workbook looks up against it. Four columns on every identity tab fill themselves, and the flag is only ever as stale as your last script run.

---

## 2. Files

| File | Purpose |
|---|---|
| `Entra_Service_Identity_Inventory.xlsx` | The workbook. 8 tabs. |
| `Build-CAExclusionMap.ps1` | Every CA exclusion, expanded transitively. |
| `Build-AzureResourceMap.ps1` | Every Azure RBAC assignment + managed identity resource metadata. |
| `Build-IdentityInventory.ps1` | The three identity tabs. |

### Workbook tabs

| Tab | What it is |
|---|---|
| **Dashboard** | Roll-up across all three identity tabs. Read-only, all formulas. |
| **How to Use** | Condensed version of this guide, in the workbook. |
| **Accounts** | Users, including user-based service accounts. |
| **Service Principals** | Enterprise applications and app registrations. |
| **Managed Identities** | System-assigned and user-assigned. |
| **CA Exclusion Map** | Paste target. Object ID → exclusion groups and policies. |
| **Azure Resource Map** | Paste target. Principal ID → Azure RBAC and resource metadata. |
| **Reference** | Drop-down lists. Edit to match your naming standards. |

### Colour code

| Header colour | Meaning |
|---|---|
| Dark blue | Graph import zone — paste here, no formulas |
| Teal | Lookup from Azure Resource Map — never type |
| Grey | Calculated — never type |
| Brown | CA exclusion governance — you enter |
| Green | Ownership — you enter |
| Mid blue | Other manual fields |

Pale yellow row 2 on every tab is a worked example. **Delete it before loading real data** — it is counted in every Dashboard figure until you do.

Headers with a red corner marker carry a comment. Hover for guidance on what belongs in the column.

---

## 3. Prerequisites

### Modules

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser
```

### Graph permissions (delegated, all read-only)

| Scope | Needed for |
|---|---|
| `Policy.Read.All` | Conditional Access policies |
| `Group.Read.All` | Transitive expansion of exclusion groups |
| `Directory.Read.All` | Directory objects generally |
| `Application.Read.All` | Service principals, applications, owners |
| `User.Read.All` | User accounts and managers |
| `AuditLog.Read.All` | Sign-in activity, MFA registration report |
| `RoleManagement.Read.Directory` | Active and PIM-eligible role assignments |
| `Organization.Read.All` | Licence SKU catalogue |

### Azure permissions

Reader at the scopes you want covered — management group root if you want tenant-wide coverage.

### Licensing dependencies

| Feature | Requires |
|---|---|
| User `signInActivity` | Entra ID P1 |
| Authentication methods registration report | Entra ID P1 |
| PIM eligibility data | Entra ID P2 |
| Targeting service principals with CA | Workload ID Premium, per identity |

Without P1 the sign-in and MFA columns come back blank and the scripts continue. Use `-SkipSignInActivity` to skip the attempt entirely.

---

## 4. First run

Test against a non-production tenant first.

```powershell
# 1 — CA exclusions
.\Build-CAExclusionMap.ps1 -OutputPath .\CA-Exclusion-Map.csv -Verbose

# 2 — Azure RBAC and managed identity resources
.\Build-AzureResourceMap.ps1 -OutputPath .\Azure-Resource-Map.csv -UseTenantScope -Verbose

# 3 — the three identity tabs
.\Build-IdentityInventory.ps1 -OutputFolder .\inventory -Verbose
```

Then, in the workbook:

1. Delete the pale yellow example row on each of the five data tabs.
2. Paste each CSV into its tab at **cell A2** (see [paste zones](#6-paste-zones)).
3. Press **F9** if calculation is set to manual.
4. Go to the Dashboard. Start with the **Import Coverage** section at the bottom — if the row counts are zero, nothing pasted correctly.

Expect the first run to produce an uncomfortable number of orphaned identities. That is the point of the exercise.

---

## 5. The refresh cycle

Fortnightly is a reasonable cadence; weekly if your tenant changes quickly. Always re-run before an attestation or audit submission.

**Order doesn't matter** — the lookups resolve on Object ID whenever both sides are present. What matters is that you **clear existing rows before pasting a fresh snapshot** rather than pasting over the top. Paste-on-top leaves stale rows below the new data, and those keep flagging identities as excluded long after the exclusion was removed.

To clear a map tab safely:

1. Select `A2` through the last populated row, in **columns A to I** (CA map) or **A to O** (Azure map).
2. Press Delete. Do not delete entire rows — that shifts the formula column up.
3. Paste the new snapshot at A2.

The final column on each map tab (`In Inventory?`) is a formula. Never paste over it.

The manual governance columns on the identity tabs are keyed to rows, not Object IDs, so if the identity list changes order between runs your justifications will end up against the wrong rows. Two ways to handle this:

- **Small tenants:** sort the CSV consistently before pasting. The scripts already sort predictably.
- **Larger tenants:** keep a separate governance sheet keyed on Object ID and pull the manual columns in with `INDEX`/`MATCH`, the same pattern the exclusion map uses.

---

## 6. Paste zones

| CSV | Tab | Paste at | Columns | Count |
|---|---|---|---|---|
| `Inventory-Accounts.csv` | Accounts | A2 | A–P | 16 |
| `Inventory-ServicePrincipals.csv` | Service Principals | A2 | A–Q | 17 |
| `Inventory-ManagedIdentities.csv` | Managed Identities | A2 | A–H | 8 |
| `CA-Exclusion-Map.csv` | CA Exclusion Map | A2 | A–I | 9 |
| `Azure-Resource-Map.csv` | Azure Resource Map | A2 | A–O | 15 |

The scripts emit exactly these columns in exactly this order, so a straight paste lands correctly.

**If you add columns, add them to the right of the import zone, never inside it.** A column inserted at position 5 of the Accounts tab silently shifts every subsequent paste by one, and the errors it produces look like data problems rather than layout problems.

The workbook is built for 200 identity rows and 2,000 map rows. To extend, copy the last formula row down — the formulas are relative and will follow.

---

## 7. Column reference

### Accounts (43 columns)

| Range | Source | Contents |
|---|---|---|
| A–P | **Graph import** | Display name, UPN, Object ID, account category, user type, identity source, enabled, created, last interactive sign-in, last non-interactive sign-in, MFA status, active roles, PIM-eligible roles, licence, manager, manager email |
| Q | Calculated | Days since sign-in (based on **non-interactive**) |
| R–T | Azure lookup | RBAC roles, highest Azure role, sub/MG scoped |
| U–X | CA lookup | Excluded, mechanism, group, policies |
| Y–AD | **Manual** | Justification, approver, approved date, expiry date, status *(calc)*, compensating controls |
| AE–AK | **Manual** | Owner team, owner name, email, backup owner, cost centre, environment, criticality |
| AL–AQ | **Manual** | Last reviewed, reviewed by, disposition, next review *(calc)*, review status *(calc)*, notes |

> **Column J matters more than column I.** Service accounts often show no interactive sign-in for years while running daily. Judge dormancy on last *non-interactive* sign-in, which is why the Days Since Sign-In calculation uses it.

### Service Principals (47 columns)

| Range | Source | Contents |
|---|---|---|
| A–Q | **Graph import** | Display name, app ID, object ID, origin, sign-in audience, enabled, created, last sign-in, credential type, next expiry, credential count, highest permission, permission risk, delegated count, admin consent, registered owner, owner email |
| R–S | Calculated | Days since sign-in, days to credential expiry |
| T–U | **Manual** | Credential stored in, Workload ID Premium licensed |
| V–X | Azure lookup | RBAC roles, highest role, sub/MG scoped |
| Y–AB | CA lookup | Excluded, mechanism, group, policies |
| AC–AU | **Manual** | Exclusion governance, ownership, review — as Accounts |

> **Column C is the join key, not column B.** The exclusion map and Azure map both key on the service principal Object ID. Pasting Application (Client) IDs into column C breaks every lookup on the tab.

### Managed Identities (42 columns)

| Range | Source | Contents |
|---|---|---|
| A–H | **Graph import** | Display name, client ID, principal ID, MI type, created, last sign-in, Graph role assignments, permission risk |
| I | Calculated | Days since sign-in |
| J–R | Azure lookup | Associated resource, resource type, resource group, subscription, region, owner tag, RBAC roles, highest role, sub/MG scoped |
| S | **Manual** | Federated credential alternative |
| T–AP | Mixed | CA lookups, exclusion governance, ownership, review |

> Nine columns here come from the Azure Resource Map. If you skip `Build-AzureResourceMap.ps1`, half this tab stays blank.

### Map tabs

**CA Exclusion Map** — A `ObjectId` · B `DisplayName` · C `IdentityType` · D `ExclusionMechanism` · E `ExclusionGroups` · F `ExcludedPolicies` · G `PolicyCount` · H `PolicyStates` · I `SnapshotDate` · **J `In Inventory?` (formula)**

**Azure Resource Map** — A `PrincipalId` · B `PrincipalType` · C `DisplayName` · D `AzureRoleAssignments` · E `HighestAzureRole` · F `SubOrMgScoped` · G `AssignmentCount` · H `AzureResourceId` · I `ResourceType` · J `ResourceGroup` · K `Subscription` · L `Location` · M `OwnerTag` · N `CostCentreTag` · O `SnapshotDate` · **P `In Inventory?` (formula)**

---

## 8. What you fill in by hand, and why

Seven fields per identity. They exist because Graph has no opinion on them:

| Field | Why a human |
|---|---|
| Exclusion justification | Graph knows *that* an exclusion exists, never *why* |
| Exclusion approved by | Accountability requires a name |
| Exclusion approved date | Establishes when the clock started |
| Exclusion expiry date | Drives the whole traffic-light calculation |
| Compensating controls | Only you know what mitigates the gap |
| Business criticality | A business judgement, not a technical attribute |
| Owner (confirmed) | The registered owner is a starting point, not an answer |

### The expiry date is the load-bearing field

Leave it blank and the status calculates as **NO EXPIRY SET**, in red, counted on the Dashboard. That is deliberate. Treat no-expiry as a finding rather than a state — the only exclusions that reasonably run indefinitely are break-glass accounts, and even those need a documented quarterly test.

The status logic:

| Condition | Status | Colour |
|---|---|---|
| Not excluded | `N/A` | — |
| Excluded, no expiry recorded | `NO EXPIRY SET` | Red |
| Expiry in the past | `EXPIRED` | Red |
| Expiry within 30 days | `Expiring Soon` | Amber |
| Otherwise | `Active` | Green |

### Review cadence

Enter **Last Reviewed** and the workbook sets **Next Review Due** 90 days later, flagging `Due Soon` at 14 days and `OVERDUE` past the date. To change the cadence, edit the `+90` in the Next Review Due formula and the `14` in Review Status, then fill down.

---

## 9. Reading the Dashboard

### Start here

**Import Coverage** (bottom section). If the map row counts are zero, every CA and Azure column on every tab is blank and the rest of the Dashboard is meaningless. Check the snapshot dates too — anything over a fortnight old should be re-run before you act on it.

### The two numbers that matter most

**CA-excluded AND Azure privileged** — identities with no conditional access enforcement *and* subscription or management-group scoped Azure rights. Work this list before anything else on the page.

**Azure-privileged principals NOT in inventory** — principals holding Azure roles that appear in none of your three tabs. On a first run this is usually the most revealing figure in the workbook: identities with real control-plane rights that nobody has inventoried, owned or reviewed. Frequently includes long-forgotten deployment service principals.

### Section by section

| Section | Watch for |
|---|---|
| **Population** | Sanity check. Totals should roughly match your tenant. |
| **CA Exclusions** | `NO EXPIRY SET` is the usual audit finding. `Direct exclusion` bypasses group governance entirely. |
| **Azure Privilege** | Owner and User Access Administrator can grant themselves anything — this should be the shortest list on the page. |
| **Ownership** | Blank owner team is the cleanup backlog. |
| **Hygiene** | 90+ days dormant, and overdue reviews. |
| **SP Credentials** | Expiring credentials are outage risk; `>2 credentials` is usually an orphaned secret nobody dared delete. |

---

## 10. Troubleshooting

**Every "CA Excluded?" cell reads No.**
The CA Exclusion Map tab is empty, or Object IDs didn't land in column A. Check Dashboard → Import Coverage → rows loaded.

**Lookups return blank for identities you know are excluded.**
Object ID mismatch. On the Service Principals tab the join key is column C (SP Object ID), not column B (Application ID). Confirm with a spot check: `=MATCH(C2,'CA Exclusion Map'!A:A,0)`.

**Azure columns blank across all three tabs.**
Either `Build-AzureResourceMap.ps1` hasn't been run, or it ran without sufficient scope. Role assignments you lack Reader on simply don't appear — with no error. If the principal count looks low, check scope coverage before concluding the tenant is clean.

**Script reports far fewer role assignments than expected.**
Add `-UseTenantScope`, or run against a management group with `-ManagementGroup`. Resource Graph defaults to subscriptions in the current Az context only.

**Sign-in and MFA columns are empty.**
Requires Entra ID P1 plus `AuditLog.Read.All`. Reconnect with the full scope list; if you don't hold P1, run with `-SkipSignInActivity` to skip the attempt cleanly.

**Service principal Last Sign-In is blank for everything.**
The beta endpoint may be unavailable in your tenant or region. Blank means no recorded sign-in, which is *not* the same as never used — fall back to sign-in logs exported to Log Analytics.

**Break-glass accounts categorised as "Standard User".**
Category detection relies on your naming convention. Edit the regex in `Get-AccountCategory` in `Build-IdentityInventory.ps1` to match your standard, or key it off membership of a designated group.

**Formulas show as text, or the Dashboard shows stale numbers.**
Calculation is set to manual. Press F9, or Formulas → Calculation Options → Automatic.

**Everything below your pasted data still shows old values.**
You pasted on top of a longer previous snapshot. Clear the range first, per [section 5](#5-the-refresh-cycle).

---

## 11. Known limits and things to verify

**Service principal sign-in activity is a beta Graph endpoint.** Microsoft does not support beta APIs for production use and they change without notice. Treat that column as indicative and verify the endpoint still behaves as expected on each major SDK upgrade.

**Conditional Access for workload identities has real constraints.** It targets single-tenant service principals and requires a Workload ID Premium licence per identity. Multi-tenant and third-party SaaS service principals generally cannot be targeted at all — which is exactly why Compensating Controls matters most on those rows. Managed identity support and licensing have both shifted over time; confirm current behaviour against Microsoft's documentation before designing controls around it.

**Account Category is a heuristic, not a fact.** Inferred values are suffixed `(inferred)` and counted in the run summary. Verify them, particularly break-glass.

**Resource Graph has an indexing lag.** Assignments made in the last few minutes may not appear.

**Nested group membership is a point-in-time snapshot.** Someone can add a group to an exclusion group thirty seconds after your run.

**Sign-in logs retain 30 days by default.** You need longer history to defend a "this is dormant, decommission it" decision — export to Log Analytics.

**PIM-eligible is not the same as PIM-active.** The Accounts tab records both separately. An account eligible for Global Administrator is a different risk from one holding it permanently, and both are different from one that activated it last Tuesday.

---

## 12. Extending it

Ordered roughly by value:

**Exclusion drift detection.** Diff each `CA-Exclusion-Map.csv` against the previous run and alert on new entries. Pair with `Get-MgAuditLogDirectoryAudit` filtered on the *Update conditional access policy* activity to catch who changed what. This catches the exclusion added quietly on a Friday afternoon, which is the actual risk the inventory exists to manage.

**Scheduled refresh.** Azure Automation or a Function App running app-only with the read scopes above — ideally using a managed identity, which then appears in its own inventory.

**Access reviews.** With Entra ID Governance licensing, `/identityGovernance/accessReviews/definitions` can automate recurring attestation of the exclusion groups themselves, retiring the manual review columns for group-based exclusions. This is the single biggest reduction in ongoing effort available.

**Log Analytics for sign-in history.** Export to a workspace in Australia East and query `AADServicePrincipalSignInLogs`. Doubles as ISM event-logging evidence.

**Automated expiry remediation.** Removing an identity from an exclusion group when its recorded expiry passes is a Graph write (`Remove-MgGroupMemberByRef`). Put an approval gate in front of it — an automated removal that breaks a payroll run at 2am is a worse outcome than a stale exclusion.

**Tag hygiene in Azure.** Every identity-bearing resource carrying an `Owner` tag means the Managed Identities ownership column fills itself. The script reports how many are missing.

---

## 13. Australian regulatory context

**ACSC Essential Eight** — *Restrict administrative privileges* expects privileged access to be validated on first request, revalidated annually or more often, and disabled after 12 months of inactivity. The Privileged Roles, Review Status and Days Since Sign-In columns give you evidence for all three. *Regular logging and monitoring of privileged access* is supported by the sign-in columns, provided you retain logs beyond the default 30 days.

**APRA CPS 234** — requires information assets to be identified and classified by criticality and sensitivity, with clearly defined information security roles and responsibilities. The Owner Team, Owner Name and Business Criticality columns map onto this directly. The 90-day review cycle provides the periodic testing evidence.

**ACSC ISM** — event log retention expectations exceed Entra's 30-day default. Export to Log Analytics with an appropriate retention period.

**Data residency** — the Region column on the Managed Identities tab shows where each workload runs. `australiaeast` and `australiasoutheast` keep processing onshore, which matters where the identity touches personal information.

**Privacy Act 1988 / Australian Privacy Principles** — APP 11 requires reasonable steps to secure personal information. An inventory with accountable owners and reviewed access is part of that, but obligations depend on your circumstances. Take advice from your own privacy and legal advisers rather than treating this workbook as compliance in itself.

---

*Nothing here constitutes legal or compliance advice. Verify all Microsoft API behaviour and licensing against current documentation before relying on it.*

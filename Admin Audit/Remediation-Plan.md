# Privileged Access Remediation Plan

The operating process for turning what `Privileged_Access_Review.xlsx` finds into work that is categorised, actioned, owned, prioritised and formally approved — not a one-off cleanup of the current findings.

**Status:** Draft — pending stakeholder approval
**Scope:** Entra ID, Azure RBAC, Active Directory
**Sources:** `Privileged_Access_Review.xlsx`, `Invoke-AdminReviewPipeline.ps1`, `Automation-Guide.md`

---

## Contents

0. [How this plan covers the story](#0-how-this-plan-covers-the-story)
1. [Categorisation and severity](#1-categorisation-and-severity)
2. [Finding catalog](#2-finding-catalog)
3. [Ownership](#3-ownership)
4. [Priority by effort](#4-priority-by-effort)
5. [Workbook changes required](#5-workbook-changes-required)
6. [Approval workflow](#6-approval-workflow)
7. [Steady-state cadence](#7-steady-state-cadence)

---

## 0. How this plan covers the story

Five acceptance criteria were raised. Each maps to a specific section below rather than to the plan as a whole, so a reviewer can check each one off directly.

| # | Acceptance criterion | Where it's satisfied |
|---|---|---|
| AC1 | Audit findings have been assessed and categorised | [§1 Categorisation](#1-categorisation-and-severity) — severity model built on the tiers the scripts already assign, plus [§2 Finding catalog](#2-finding-catalog) |
| AC2 | Recommended remediation actions have been documented | [§2 Finding catalog](#2-finding-catalog) — one row per finding type, exact trigger, exact action |
| AC3 | An owner has been assigned to each remediation item | [§3 Ownership](#3-ownership) — RACI by finding group, plus the Owner column in §2 |
| AC4 | Remediation actions have been prioritised according to effort | [§4 Priority by effort](#4-priority-by-effort) — impact × effort quadrant behind the Priority column in §2 |
| AC5 | A remediation plan has been approved by stakeholders | [§6 Approval workflow](#6-approval-workflow) — the exact sequence to get from register to signed-off plan |

---

## 1. Categorisation and severity

The scripts already do most of the categorisation work: every admin account carries a `Tier` (0/1/2, defined on the `Role Tiers` tab), an `Assignment Route`, and a set of computed `Risk Flags`. This plan does not re-derive any of that — it adds one layer on top: a **Category** (what kind of gap this is) and a **Severity** (how urgently it needs attention), so findings of very different shapes can sit in one prioritised register.

Severity is derived, not guessed, using four rules applied in order:

1. **Critical** — a control failure that is already *in effect* right now — the account is enabled and the gap is live. Orphaned-but-enabled admin accounts, an AD/Entra active mismatch, an already-expired credential, unconstrained delegation on an admin account.
2. **High** — a Tier 0 finding that is not itself an active breach but removes a safeguard around control-plane access — standing (non-PIM) Tier 0, Tier 0 held via group membership only, weak authentication on a Tier 0 account, Tier 0 privilege spanning more than one plane.
3. **Medium** — the same shape of finding at Tier 1, or a Tier 0 account with a governance/hygiene gap rather than a live grant issue — unowned identities, Conditional Access exclusion hygiene, password age, unenrolled review cycles on Tier 0/1 accounts.
4. **Low** — Tier 2 findings, sprawl, and hygiene items with no direct escalation path — dormant accounts, account sprawl, blind-spot candidates pending a broader ACL sweep.

*Satisfies AC1.*

---

## 2. Finding catalog

Sixteen finding categories cover everything the Dashboard tab currently counts. Trigger references the exact column and value the pipeline already writes — nothing here requires re-reading the raw Graph/AD data, only reading the workbook that's already produced.

| Category | Trigger (column = value) | Severity | Recommended action | Owner | Effort | Pri. | SLA |
|---|---|---|---|---|---|---|---|
| Leaver / orphaned admin account | `ORPHANED? = Yes` | Critical | Confirm leaver status with line manager/HR within 1 business day. Disable the admin account immediately regardless of outcome; delete after the standard retention window once confirmed. | IAM Team / AD Platform Team | Low | P1 | 1 day disable · 5 days close |
| Live access gap (AD/Entra mismatch) | `AD/Entra Active Mismatch = Yes` | Critical | Disable the Entra account by hand — do not wait for the next sync cycle. Open a sync-health investigation with the Entra Connect owner in parallel. | IAM Team + AD Platform Team | Low / Medium | P1 | Same day · 10 days root cause |
| Weak authentication — cloud Tier 0/1 | `Phishing Resistant ≠ Yes`, `Tier ≤ 1` | Critical | Enforce FIDO2 / Windows Hello for Business / certificate-based auth via Conditional Access; block sign-in until the account registers a phishing-resistant method. | IAM Team (policy) + account holder | Low / Medium | P1 | 14 days |
| Weak authentication — on-prem Tier 0 | `Smartcard Required = No`, `AD Tier = 0` | Critical | Issue a smartcard and set Smartcard Logon Required on the account. | AD Platform Team | Medium | P1 | 30 days (hardware lead time) |
| Expired service credential | `Days To Expiry < 0` | Critical | Rotate the credential now; confirm whether a second, uninventoried credential is what's actually being used, and add it if so. | App/Service owning team | Low | P1 | 5 days |
| Domain impersonation path (delegation) | `Delegation = configured (unconstrained)` | High | Convert to constrained or resource-based delegation, or remove it, after confirming which service depends on it. | AD Platform Team | Medium | P2 | 30 days |
| Standing (non-PIM) Tier 0 privilege | `Tier = 0`, `Active Role Count > 0`, not PIM-eligible | High | Convert the active assignment to PIM-eligible, requiring justification and MFA on activation; remove the standing grant. | IAM Team | High (program) / Low (per account once live) | P3 | 90 days program |
| Shadow privilege via group ("group only") | `Assignment Route = Group only` | High | Resolve the Granting Groups / Granting Group IDs, confirm the business need with the group owner. If unneeded, remove the person from the *group* — a role removal does nothing here. If needed, apply the same review rigor as a direct Tier 0 grant. | IAM Team + group owner | Medium | P2 | 20 days |
| Cross-plane concentration | `Privileged In Multiple Planes = Yes`, `Overall Tier = 0` | High | Justify why one person needs privilege in more than one plane. Remove the non-essential plane, or — if genuinely required — apply Tier 0 controls consistently across every plane held. | IAM Team, coordinating across the tab owners flagged in "Also Holds ..." | Medium | P2 | 20 days |
| CA exclusion hygiene | Excl. expired, no expiry set, or excluded & Azure privileged | High | Validate the business justification, set or renew an expiry date, remove if unjustified or expired. Migrate ad-hoc direct exclusions into a managed, named exclusion group. | IAM Team + Security/GRC approval | Low / Medium | P2 | 15 days |
| Unowned privileged identity | `Permission Risk = High`, no Registered Owner | High | Assign an owning team or individual. Disable the identity if it remains unowned after the escalation window closes. | Security/GRC chases; App/Service team accepts | Low | P2 | 20 days |
| Credential hygiene (admin accounts) | `Password Age > 365 days`, or `PasswordNeverExpires = Yes` | Medium | Force a password reset. Remove the never-expires flag, or migrate to a gMSA if the account is actually a service account misfiled as an admin. | AD Platform Team | Low | P2 | 20 days |
| Blind-spot candidate | Admin-named, no privileged group, no ACL-Based Privilege | Medium | Run PingCastle or BloodHound for the delegated-ACL sweep this pipeline doesn't cover. Decommission the account if nothing turns up. | Security/GRC + AD Platform Team | Medium | P3 | 45 days |
| Dormant privileged account | `Days Since Sign-In/Logon > 90` | Medium | Confirm continued need with the holder and their manager; disable if not required. lastLogonTimestamp can lag up to 14 days — don't act on a single borderline reading. | IAM/AD Platform Team + line manager | Low | P3 | 20 days |
| Governance / attestation gap | `Access Status ≠ Active`, or `Review Status = Overdue/Not Enrolled` | Medium | Enrol in the recurring Entra Access Review. Escalate overdue reviews to the line manager; apply *Auto-Removed (No Response)* per the existing decision list if unresponsive past deadline. | IAM Team (process) + line manager | Low | P4 (P1 if Tier ≤ 1 & never enrolled) | Next cycle · 5 days if Tier ≤ 1 |
| Account sprawl | `Total Admin Accounts > 2` | Low | Consolidate to the minimum accounts needed per plane; confirm the purpose of each remaining account with its holder. | IAM Team + account holder | Low | P4 | Next cycle |

*Satisfies AC2, AC3, AC4.*

---

## 3. Ownership

The Owner column in §2 names a team, not a person — assign the named person when the register is populated (§6, step 3). The RACI below resolves the cases where more than one team touches a finding, which is most of the cross-plane and leaver-driven rows.

| Finding group | Responsible (executes) | Accountable (owns outcome) | Consulted | Informed |
|---|---|---|---|---|
| Entra ID (Tier 0/1) | IAM Team engineer | IAM Team lead | Security/GRC — Tier 0 second reviewer | Steering committee |
| Azure RBAC | IAM / Cloud Platform Team | Cloud Platform lead | Subscription & management group owners | Security/GRC |
| Active Directory (on-prem) | AD Platform engineer | AD Platform lead | Security/GRC | IAM Team (cross-plane cases) |
| Leaver-driven (orphaned accounts) | IAM / AD Platform Team (disables) | Same | Line manager / HR (confirms leaver status) | Security/GRC |
| Service identities | App/Service owning team | App/Service owner | IAM Team | Security/GRC |
| Governance / attestation | IAM Team (process) | Security/GRC | Line managers | Steering committee |

*Satisfies AC3.*

---

## 4. Priority by effort

Priority is impact crossed with effort, not severity alone — a Critical finding that takes one click (disable an orphaned account) and a High finding that needs a procurement cycle (smartcard issuance) cannot share a queue. Effort is "can the owning team alone clear this within a normal work cycle" (Low/Medium) versus "this needs its own scope, budget or phased rollout" (High).

### P1 — Do now
**Critical/high impact, low/medium effort.** Standing operating procedure — act immediately, report at the next approval meeting rather than waiting for it.
- Orphaned admin accounts
- AD/Entra active mismatch
- Expired service credentials
- Weak auth on Tier 0/1

### P2 — Fast follow
**Medium/low impact, low/medium effort** (and high-impact items awaiting P3 program rollout). Scheduled within the current review cycle (2–4 weeks), no separate approval needed to start.
- Group-only Tier 0 shadow access
- Cross-plane concentration
- CA exclusion hygiene
- Unowned service identities

### P3 — Planned project
**Critical/high impact, high effort.** Needs its own scope, timeline and milestone sign-off inside this plan's overall approval.
- PIM rollout for standing Tier 0
- Delegated-ACL sweep (PingCastle/BloodHound)

### P4 — Backlog / continuous
**Medium/low impact, any effort.** Folded into the steady-state review cadence. Tracked for trend, not chased individually.
- Dormant accounts
- Account sprawl
- Routine governance enrolment

*Satisfies AC4.*

---

## 5. Workbook changes required

None of the columns in §2 — Category, Owner, Effort, Priority, SLA — exist in the workbook today. They need to be added once, as manual columns, to the three admin-level tabs: `Entra Admins`, `Azure RBAC Admins`, `On-Prem Admins` (and, for orphan-only findings, `Cloud Admin Accounts`).

| Column | Purpose |
|---|---|
| Remediation Category | One of the sixteen categories in §2. |
| Remediation Owner | Team, from §3's RACI — named individual once assigned. |
| Remediation Priority | P1–P4, from §4. |
| Remediation Status | Not Started / In Progress / Blocked / Risk Accepted / Done. |
| Target Completion Date | Derived from the SLA in §2 against the date the finding was raised. |

**Why this is safe to add directly to the workbook.** `Sync-AdminReviewWorkbook.ps1` upserts by matching column *names* against each CSV's own headers — it only ever overwrites a column it recognises from the pipeline output. Any column added here that the CSVs don't produce is, by construction, treated as a protected manual column on every future sync, the same way `Business Justification` and `Decided By` already are. No script change is needed to add these five columns.

Add the accepted values for `Remediation Priority` and `Remediation Status` to the `Reference` tab alongside the existing dropdown lists, and apply data validation from there — consistent with how `Review Decision` and `Access Type` are already validated.

---

## 6. Approval workflow

The exact sequence from a fresh pipeline run to a plan a governance forum has formally signed off.

1. **Baseline the data.** Run `Invoke-AdminReviewPipeline.ps1` end to end (or the split Automation-Guide runbooks), then `Sync-AdminReviewWorkbook.ps1` to load the result into the workbook.
2. **Add the remediation columns.** One-off: the five columns in §5, plus their dropdown lists on the `Reference` tab. Skip if already present from a prior cycle.
3. **Triage.** For every row with a non-blank `Risk Flags`, `ORPHANED? = Yes`, or an `Access Status`/`Review Status` other than Active/Current, apply the catalog in §2: set Category, Owner, Priority, Target Date, Status = Not Started. Tier 0 rows get the same second-reviewer check the workbook already applies to Tier 0 access decisions.
4. **Aggregate.** Pivot the populated register by Owner and by Priority to produce the plan's summary view — headline counts, and the full scope/timeline for each P3 project.
5. **Owner validation.** Circulate the draft register to each owning team — IAM, AD Platform, Security/GRC, affected App/Service owners — for a 5-business-day review of their assigned items. They may contest severity, effort or ownership; they may not remove a finding.
6. **Lock the register.** Incorporate owner feedback from step 5.
7. **Present for approval.** Take the locked register to the governance/security steering committee: headline counts (matching the Dashboard tab), the P1–P4 breakdown with named owners, and full scope/timeline/cost for each P3 project.
8. **Record sign-off.** Capture who approved, the date, and any conditions attached — in the plan document itself or the tracking ticket. A verbal nod in the meeting is not the evidence; the written record is.
9. **Communicate and begin execution.** P1 items may already be in progress under standing operating procedure (§4) — report their status at the same meeting rather than waiting for it to start them.
10. **Track to closure.** Update Remediation Status as work lands. Only a change to the categorisation or priority rules in §1–§4 goes back to the steering committee for re-approval — routine new findings from later runs follow §7 instead.

*Satisfies AC5.*

---

## 7. Steady-state cadence

This plan is not a one-time cleanup exercise — the pipeline is designed to be re-run on a schedule, per `Automation-Guide.md`, and each run needs the same triage without re-opening approval.

- On each scheduled run, repeat §6 steps 3–4 only: triage newly surfaced findings against the existing catalog and priority rules, and add them to the register with the same Owner/Priority/SLA logic. No new stakeholder approval is required for this — it was granted once, for the process, in step 7–8.
- Report progress using the Remediation Status column, alongside the delta reporting `Send-IdentityReport` already produces (new exclusions, new privileged accounts, newly orphaned admins).
- The `GovernancePct` and `AttestationPct` metrics in Automation-Guide's report currently sit at zero because they need exactly this kind of manually-maintained data. Once Remediation Status exists, add a *Remediation completion %* metric alongside them, computed the same way.
- Re-approval is only needed when the categorisation, ownership or priority *rules* change (§1–§4) — for example, adding a new finding category, or moving a category between priority tiers. Individual findings moving through the register never require it.

---

Prepared from the current state of the Privileged Access Review pipeline — `Build-CloudAdminReview.ps1`, `Build-OnPremAdminReview.ps1`, `Merge-AdminReview.ps1`, `Update-AdminPeopleAD.ps1`, `Update-AdminPeopleEntra.ps1`, `Sync-AdminReviewWorkbook.ps1`. Column and value names above are quoted exactly as they appear in `Privileged_Access_Review.xlsx`.

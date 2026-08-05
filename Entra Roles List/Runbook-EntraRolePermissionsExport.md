# Runbook — Export Entra ID Built-in Role Permissions to a Spreadsheet

## Purpose

Produce a filterable spreadsheet that maps every Microsoft Entra ID **built-in role** to the
individual permissions (resource actions) it contains. One row per `(role, permission)` pair, so
you can filter by role to see all its permissions, or filter by permission to see every role that
holds it.

This data is sourced live from Microsoft Graph rather than typed by hand, because Microsoft adds
new resource actions to roles regularly and any static list goes stale quickly.

---

## Output format

A three-column table:

| Column | Name | Example |
|---|---|---|
| A | `RoleDisplayName` | `Global Administrator` |
| B | `Permission` | `microsoft.directory/applications/standard.read` |
| C | `RoleType` | `Built-in` (or `Custom` if custom roles are included) |

Duplicate permissions across different roles are expected and intended — the same action appears
once per role that holds it.

> **Expected size:** built-in roles produce roughly 8,000–10,000+ rows. This is normal and well
> within spreadsheet limits.

---

## Prerequisites

- **Access:** Global Reader (or higher) in the target tenant. This is enough to *read* role
  definitions. The export is read-only and changes nothing.
- **Where to work:** your designated admin host / jump server, where portal and PowerShell access
  are permitted.
- **Files** (keep together in one working folder, e.g. `C:\Temp\EntraRoles\`):
  - `Flatten-EntraRolePermissions.ps1` — flattens a saved Graph JSON export (no module needed)
  - `Get-EntraRolePermissions.ps1` — pulls and flattens in one step (needs the Graph module)
  - `EntraRolePermissions_Template.xlsx` — pre-formatted, filterable workbook to hold the result

Choose **Method A** if the Microsoft Graph PowerShell module is not installed (works immediately
with Global Reader). Choose **Method B** if the module is available.

---

## Method A — No module required (Graph Explorer + flatten script)

### A1. Pull the role definitions from Graph Explorer

1. Browse to `https://developer.microsoft.com/graph/graph-explorer` and sign in.
2. Set the method to **GET** and the version to **v1.0**.
3. Run this query:

   ```
   https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=displayName,templateId,isBuiltIn,rolePermissions
   ```

> **Known gotcha — `400 Bad Request / Request_UnsupportedQuery`:**
> The `roleDefinitions` endpoint does **not** support the `$top` query option. If you get this
> error, remove `$top` (the endpoint returns all roles in one response regardless). If a query
> with `$select` still fails, fall back to the bare endpoint — it returns extra properties that
> the script simply ignores:
>
> ```
> https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions
> ```

### A2. Save the response

Copy the **entire** JSON from the Response preview pane (from the opening `{` to the closing `}`)
into a plain text file and save it as `roledefs.json` in your working folder.

### A3. Check for paging (usually not needed)

Scroll to the bottom of the response. If you see an `@odata.nextLink` value, there are more pages:
run that link, and append the contents of its `value` array into the same file. Without `$top`,
a single page normally contains everything, so you can usually skip this step.

### A4. Run the flatten script

```powershell
cd C:\Temp\EntraRoles
powershell.exe -ExecutionPolicy Bypass -File .\Flatten-EntraRolePermissions.ps1 -InputJson .\roledefs.json
```

This writes `EntraRolePermissions.csv` to the same folder and prints the row count.
`-ExecutionPolicy Bypass` allows the unsigned script to run for that single invocation. If it is
still blocked, execution policy is enforced by Group Policy — use Method B, or arrange a
signed-script exception.

---

## Method B — With the Microsoft Graph PowerShell module

### B1. Confirm the module is present

```powershell
Get-Module Microsoft.Graph.Authentication -ListAvailable
```

If nothing returns, the module is not installed. Installing it on a managed admin host typically
requires a change request — raise one, then return to this method. (Until then, use Method A.)

### B2. Run the script

```powershell
cd C:\Temp\EntraRoles
powershell.exe -ExecutionPolicy Bypass -File .\Get-EntraRolePermissions.ps1
```

A sign-in prompt appears (`Connect-MgGraph` requests the `RoleManagement.Read.Directory` scope,
which sits within Global Reader's capability). Sign in with your normal account. The script pulls
all role definitions, handles paging automatically, writes `EntraRolePermissions.csv`, and
disconnects.

---

## Optional — include custom roles

Both scripts default to **built-in roles only**. To include custom roles in the output, add the
`-IncludeCustom` switch:

```powershell
.\Flatten-EntraRolePermissions.ps1 -InputJson .\roledefs.json -IncludeCustom
.\Get-EntraRolePermissions.ps1 -IncludeCustom
```

> Custom role **names** can be organisation-specific. If you include them, review the output
> before sharing it anywhere public.

---

## Load the data into the template

1. Open `EntraRolePermissions.csv` and `EntraRolePermissions_Template.xlsx` side by side.
2. In the CSV, select all **data** rows (everything except the header row) and copy.
3. In the workbook's **Role Permissions** sheet, paste over the example rows starting at cell `A2`.
4. Delete any leftover rows still containing `<<EXAMPLE>>`.
5. Extend the table to cover all rows: **Table Design → Resize Table**, or drag the handle at the
   bottom-right corner of the table.
6. Filters now work across the full set:
   - Filter **Column A** to see every permission a role holds.
   - Filter **Column B** to see every role that holds a given permission.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `400 Bad Request / Request_UnsupportedQuery` | `$top` is not supported on this endpoint | Remove `$top`, or use the bare endpoint URL |
| `403 Forbidden` in Graph Explorer | Consent or permission issue, not a query issue | Ensure the account has Global Reader; obtain admin consent for the scope if prompted |
| Script will not run / "running scripts is disabled" | Execution policy enforced by policy | Use `-ExecutionPolicy Bypass`; if still blocked, use Method B or a signed-script exception |
| Far fewer rows than expected | Response was paged and only one page was saved | Follow `@odata.nextLink` and combine the `value` arrays (Method A, step A3) |
| Custom roles appearing unexpectedly | `-IncludeCustom` was supplied | Re-run without the switch for built-in only |

---

## Regeneration

Re-run this whenever you need a current view (for example before an access review, role-design
exercise, or audit). The process is identical each time; just overwrite `roledefs.json` and the
CSV, then refresh the workbook.

---

## Notes

- This export contains only **universal Microsoft built-in role definitions**, which are identical
  in every tenant and contain no tenant-, organisation-, or staff-specific information. The output
  is therefore safe to store in a public repository — provided custom roles are not included
  without review.
- The export is strictly read-only and makes no changes to the directory.

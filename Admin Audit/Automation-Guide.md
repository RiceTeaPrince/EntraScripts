# Automating the Identity Reports

Turning the identity inventory and privileged access review scripts into a scheduled Azure Automation workflow that emails an HTML report.

**Estimated build time:** 2–3 days, plus 1–2 weeks elapsed if you need approvals for the managed identity permissions.

*Updated for group-assigned role resolution. If you built from an earlier version, see sections 2, 11, 12 and 15.*

---

## Contents

1. [Architecture](#1-architecture)
2. [What the report should contain](#2-what-the-report-should-contain)
3. [Resources to create](#3-resources-to-create)
4. [Automation Account and managed identity](#4-automation-account-and-managed-identity)
5. [Granting Graph permissions to the managed identity](#5-granting-graph-permissions-to-the-managed-identity)
6. [Azure RBAC for the managed identity](#6-azure-rbac-for-the-managed-identity)
7. [Hybrid Runbook Worker for Active Directory](#7-hybrid-runbook-worker-for-active-directory)
8. [Storage for state and history](#8-storage-for-state-and-history)
9. [Email: the sending identity](#9-email-the-sending-identity)
10. [Shared module](#10-shared-module)
11. [The HTML report generator](#11-the-html-report-generator)
12. [The runbooks](#12-the-runbooks)
13. [Scheduling](#13-scheduling)
14. [Testing](#14-testing)
15. [Alert thresholds](#15-alert-thresholds)
16. [Security considerations](#16-security-considerations)
17. [Troubleshooting](#17-troubleshooting)
18. [Cost](#18-cost)

---

## 1. Architecture

Two execution contexts, because Active Directory cannot be reached from the Azure Automation sandbox.

```
┌─────────────────────────────────────────────────────────────┐
│  Azure Automation Account  (system-assigned managed identity)│
│                                                              │
│  ┌────────────────────────┐   ┌──────────────────────────┐  │
│  │ Runbook: Collect-Cloud │   │ Runbook: Send-Report     │  │
│  │  Azure sandbox         │   │  Azure sandbox           │  │
│  │  Graph + Resource Graph│   │  reads state, builds HTML│  │
│  └───────────┬────────────┘   └────────┬─────────────────┘  │
│              │                          │                    │
│  ┌───────────┴────────────┐             │                    │
│  │ Runbook: Collect-AD    │             │                    │
│  │  HYBRID WORKER         │             │                    │
│  │  domain-joined, RSAT   │             │                    │
│  └───────────┬────────────┘             │                    │
└──────────────┼──────────────────────────┼────────────────────┘
               │                          │
               ▼                          ▼
      ┌─────────────────┐        ┌──────────────────┐
      │ Storage Account │        │ Graph sendMail   │
      │  state/  (diff) │        │  scoped to one   │
      │  history/       │        │  mailbox by ACL  │
      │  reports/       │        └──────────────────┘
      └─────────────────┘
```

**Why three runbooks rather than one.** The AD collection needs a Hybrid Runbook Worker; the cloud collection runs better in the Azure sandbox where the managed identity works natively. Splitting them means a domain outage doesn't kill the cloud report, and each can be scheduled and retried independently.

**Why storage in the middle.** State is what makes the report worth reading. A static list of 47 exclusions gets ignored by run three. "Two new exclusions since Tuesday, one of them Tier 0" gets read every time.

---

## 2. What the report should contain

Design the report around a single question: *what changed, and what do I do about it?*

Structure, top to bottom:

| Section | Content | Why it's in this position |
|---|---|---|
| **Act now** | Threshold breaches and new high-severity findings | If the reader stops after 10 seconds, this is what they saw |
| **What changed** | Deltas since the previous run | The reason to open a recurring email |
| **Current posture** | Headline metrics, current vs previous | Context for the deltas |
| **Detail tables** | Named items behind the action list | Enough to assign work without opening the workbook |
| **Trend** | Selected metrics over the last 12 runs | Shows whether the programme is working |
| **Footer** | Snapshot time, data caveats, link to full data | Provenance |

**Metrics worth including**, drawn from both workbooks:

*Change-based (the valuable half)*
- New CA exclusions since last run, with the identity and policy named
- Exclusions removed
- New privileged accounts (Entra, Azure, AD)
- **New members of role-assignable groups** — the fastest route to privilege in most tenants
- Newly orphaned admin accounts
- Newly dormant identities crossing 90 days

*Threshold-based*
- Tier 0 privilege held **via group membership only** — invisible on the user object
- Tier 0 admins without phishing-resistant MFA
- Tier 0 AD accounts without smartcard required
- Standing (non-PIM) Tier 0 roles
- CA-excluded and Azure privileged
- Credentials expiring within 30 days
- Exclusions expired or with no expiry set
- Identities with no owner

*Progress*
- Governance completeness percentage
- Attestation completeness percentage

Keep the email under about 100 KB of HTML. Beyond that Gmail clips it and Outlook gets slow.

---

## 3. Resources to create

```powershell
$rg       = 'rg-identity-governance-ause'
$location = 'australiaeast'
$aa       = 'aa-identity-governance'
$sa       = 'stidentitygov' + (Get-Random -Minimum 10000 -Maximum 99999)

Connect-AzAccount
New-AzResourceGroup -Name $rg -Location $location

New-AzAutomationAccount -ResourceGroupName $rg -Name $aa -Location $location `
    -AssignSystemIdentity -Plan Basic

New-AzStorageAccount -ResourceGroupName $rg -Name $sa -Location $location `
    -SkuName Standard_LRS -Kind StorageV2 `
    -MinimumTlsVersion TLS1_2 -AllowBlobPublicAccess $false

$ctx = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).Context
foreach ($c in 'state','history','reports') {
    New-AzStorageContainer -Name $c -Context $ctx -Permission Off
}

Write-Host "Storage account: $sa"
```

Keep everything in `australiaeast` — the reports contain identity data and there's no reason to process it offshore.

---

## 4. Automation Account and managed identity

### Runtime

Use PowerShell 7.2 or later. Check what's currently offered — Azure Automation runtime versions change, and 5.1 will not run these scripts well.

### Modules

**Do not import the full `Microsoft.Graph` module.** It contains dozens of sub-modules, takes 30+ minutes to import, and frequently times out. Import only what you need:

```powershell
$modules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Identity.Governance'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Reports'
    'Microsoft.Graph.Groups'
    'Az.Accounts'
    'Az.ResourceGraph'
    'Az.Storage'
)

foreach ($m in $modules) {
    Write-Host "Importing $m..."
    New-AzAutomationModule -ResourceGroupName $rg -AutomationAccountName $aa `
        -Name $m -ContentLinkUri "https://www.powershellgallery.com/api/v2/package/$m"
}
```

Import `Microsoft.Graph.Authentication` **first** and wait for it to reach `Available` before the others — they depend on it and will fail if it isn't ready.

```powershell
# Poll until everything is Available
do {
    $pending = Get-AzAutomationModule -ResourceGroupName $rg -AutomationAccountName $aa |
               Where-Object { $_.Name -in $modules -and $_.ProvisioningState -ne 'Succeeded' }
    if ($pending) { Write-Host "Waiting on: $($pending.Name -join ', ')"; Start-Sleep 60 }
} while ($pending)
```

Expect 20–40 minutes for the full set.

---

## 5. Granting Graph permissions to the managed identity

This cannot be done in the portal. The managed identity needs Graph **application** permissions, assigned as app role assignments.

```powershell
Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All'

# The Automation Account's system-assigned identity
$miObjectId = (Get-AzAutomationAccount -ResourceGroupName $rg -Name $aa).Identity.PrincipalId
$mi = Get-MgServicePrincipal -ServicePrincipalId $miObjectId

# Microsoft Graph's service principal in your tenant
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

$permissions = @(
    'User.Read.All'
    'Directory.Read.All'
    'Application.Read.All'
    'Policy.Read.All'
    'Group.Read.All'
    'AuditLog.Read.All'
    'RoleManagement.Read.Directory'
    'Organization.Read.All'
    'Mail.Send'                    # for the report email
)

foreach ($p in $permissions) {
    $role = $graphSp.AppRoles | Where-Object {
        $_.Value -eq $p -and $_.AllowedMemberTypes -contains 'Application'
    }
    if (-not $role) { Write-Warning "App role not found: $p"; continue }

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id |
                Where-Object { $_.AppRoleId -eq $role.Id }
    if ($existing) { Write-Host "Already assigned: $p"; continue }

    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id `
        -PrincipalId $mi.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
    Write-Host "Granted: $p"
}
```

**These are tenant-wide read permissions and will need approval in most organisations.** Start this early — it's the long pole in the build.

`Mail.Send` is the one to scrutinise. Unrestricted, it lets the identity send as *any* mailbox in the tenant. [Section 9](#9-email-the-sending-identity) restricts it to one.

Record the managed identity's principal ID — you'll need it repeatedly:

```powershell
Write-Host "Managed identity object ID: $miObjectId"
```

---

## 6. Azure RBAC for the managed identity

Reader at the scope you want the Azure RBAC picture to cover, plus storage access:

```powershell
# Reader at management group root for tenant-wide coverage
$mgId = (Get-AzManagementGroup | Where-Object { $_.DisplayName -eq 'Tenant Root Group' }).Name
New-AzRoleAssignment -ObjectId $miObjectId -RoleDefinitionName 'Reader' `
    -Scope "/providers/Microsoft.Management/managementGroups/$mgId"

# Storage
$saId = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).Id
New-AzRoleAssignment -ObjectId $miObjectId `
    -RoleDefinitionName 'Storage Blob Data Contributor' -Scope $saId
```

Reader at management group root is broad. If that won't pass review, assign at each subscription instead — but understand that assignments you can't read simply won't appear in the report, with no error.

---

## 7. Hybrid Runbook Worker for Active Directory

The Azure Automation sandbox has no line of sight to a domain controller. AD collection needs a worker running on a domain-joined machine.

### Prepare the machine

A domain-joined Windows Server, ideally a management server rather than a DC:

```powershell
# On the target server
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Install-Module Az.Accounts, Az.Storage -Scope AllUsers -Force
```

### Register the worker

Extension-based Hybrid Workers are the current approach. Create the group, then install the extension:

```powershell
$hwGroup = 'hw-domain-ause'

New-AzAutomationHybridRunbookWorkerGroup -ResourceGroupName $rg `
    -AutomationAccountName $aa -Name $hwGroup

# Arc-enabled or Azure VM resource ID of the domain-joined server
$vmResourceId = '/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/vm-mgmt-01'

New-AzAutomationHybridRunbookWorker -ResourceGroupName $rg `
    -AutomationAccountName $aa -HybridRunbookWorkerGroupName $hwGroup `
    -Name (New-Guid).Guid -VmResourceId $vmResourceId
```

For on-premises servers not in Azure, onboard through **Azure Arc** first, then install the `HybridWorkerForWindows` extension.

### Run-as identity on the worker

By default, hybrid runbooks execute as the Local System account, which authenticates to AD as the computer account. That works for reading, but it's better practice to use a dedicated identity.

**Use a gMSA** — same reasoning as the service account discussion in the inventory: AD manages the password and no human ever knows it.

```powershell
# On a DC, once per forest if not already done
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

New-ADServiceAccount -Name 'gmsa-idreview' `
    -DNSHostName 'gmsa-idreview.corp.com.au' `
    -PrincipalsAllowedToRetrieveManagedPassword 'vm-mgmt-01$'

# On the worker
Install-ADServiceAccount -Identity 'gmsa-idreview'
Test-ADServiceAccount -Identity 'gmsa-idreview'
```

Then set the Hybrid Worker credential in the Automation Account to use it. The gMSA needs only standard authenticated-user read in AD — no elevation.

---

## 8. Storage for state and history

Layout:

```
state/       cloud-latest.json      previous run, for diffing
             ad-latest.json
history/     2026-08-14-cloud.json  archive, drives trend charts
             2026-08-14-ad.json
reports/     2026-08-14.html        the rendered report
```

Add lifecycle management so history doesn't grow indefinitely:

```powershell
$rule = New-AzStorageAccountManagementPolicyRule -Name 'archive-old-snapshots' `
    -Action (Add-AzStorageAccountManagementPolicyAction `
        -BaseBlobAction Delete -daysAfterModificationGreaterThan 730) `
    -Filter (New-AzStorageAccountManagementPolicyFilter -PrefixMatch 'history/','reports/')

Set-AzStorageAccountManagementPolicy -ResourceGroupName $rg -StorageAccountName $sa -Rule $rule
```

Two years is a reasonable retention for audit evidence. Check it against your own records policy.

---

## 9. Email: the sending identity

### Why Graph rather than SMTP

`Send-MailMessage` is obsolete and Basic Authentication for SMTP is being progressively disabled. Use Graph `sendMail`.

### Restricting Mail.Send

`Mail.Send` as an application permission allows sending as **any mailbox in the tenant**. That's rarely acceptable. Restrict it with an Application Access Policy so the identity can only send from one mailbox.

Create a dedicated shared mailbox first — for example `identity-reports@corp.com.au` — then:

```powershell
Connect-ExchangeOnline

# Security group containing only the sending mailbox
New-DistributionGroup -Name 'SG-IdentityReportSenders' -Type Security `
    -Members 'identity-reports@corp.com.au'

# The managed identity's APPLICATION ID, not its object ID
$miAppId = (Get-MgServicePrincipal -ServicePrincipalId $miObjectId).AppId

New-ApplicationAccessPolicy -AppId $miAppId `
    -PolicyScopeGroupId 'SG-IdentityReportSenders@corp.com.au' `
    -AccessRight RestrictAccess `
    -Description 'Identity governance reporting - send only from identity-reports'

# Verify
Test-ApplicationAccessPolicy -Identity 'identity-reports@corp.com.au' -AppId $miAppId
Test-ApplicationAccessPolicy -Identity 'ceo@corp.com.au' -AppId $miAppId   # should deny
```

Run both tests. The second returning `Denied` is what tells you the policy is actually working. Policy propagation can take up to 30 minutes.

### Alternative

If Exchange Online policies aren't available to you, **Azure Communication Services Email** is a clean alternative — no mailbox, no tenant-wide permission, its own sending domain. Slightly more setup, materially smaller blast radius.

---

## 10. Shared module

Rather than pasting helpers into every runbook, publish a PowerShell module to the Automation Account.

Create `IdentityGovernance.psm1`:

```powershell
function Connect-GovernanceGraph {
    <#  Connects using the Automation Account's managed identity.  #>
    [CmdletBinding()]
    param()
    Connect-MgGraph -Identity -NoWelcome
    $ctx = Get-MgContext
    if (-not $ctx) { throw "Failed to connect to Graph with the managed identity." }
    Write-Output "Connected to tenant $($ctx.TenantId) as managed identity."
}

function Get-GovernanceStorageContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StorageAccountName
    )
    Connect-AzAccount -Identity | Out-Null
    return (New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount)
}

function Save-GovernanceState {
    <#  Writes the current snapshot to state/ and archives a dated copy.  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name,      # 'cloud' or 'ad'
        [Parameter(Mandatory)]$Data
    )
    $json = $Data | ConvertTo-Json -Depth 8 -Compress
    $tmp  = Join-Path $env:TEMP "$Name.json"
    $json | Out-File $tmp -Encoding utf8 -Force

    Set-AzStorageBlobContent -File $tmp -Container 'state' `
        -Blob "$Name-latest.json" -Context $Context -Force | Out-Null
    Set-AzStorageBlobContent -File $tmp -Container 'history' `
        -Blob "$(Get-Date -Format 'yyyy-MM-dd')-$Name.json" -Context $Context -Force | Out-Null

    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

function Get-GovernanceState {
    <#  Reads the previous snapshot. Returns $null on first run.  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Name
    )
    $tmp = Join-Path $env:TEMP "$Name-prev.json"
    try {
        Get-AzStorageBlobContent -Container 'state' -Blob "$Name-latest.json" `
            -Destination $tmp -Context $Context -Force -ErrorAction Stop | Out-Null
        return (Get-Content $tmp -Raw | ConvertFrom-Json)
    } catch {
        Write-Warning "No previous state for '$Name' - first run, or the blob is missing."
        return $null
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-GovernanceDelta {
    <#
        Compares two collections on a key property and returns added, removed
        and retained sets. This is what turns a static list into a report
        someone will actually read.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Previous,
        [object[]]$Current,
        [Parameter(Mandatory)][string]$KeyProperty
    )
    $prevKeys = @{}
    foreach ($p in @($Previous)) { if ($p.$KeyProperty) { $prevKeys[$p.$KeyProperty] = $p } }
    $currKeys = @{}
    foreach ($c in @($Current))  { if ($c.$KeyProperty) { $currKeys[$c.$KeyProperty] = $c } }

    [PSCustomObject]@{
        Added    = @($Current  | Where-Object { $_.$KeyProperty -and -not $prevKeys.ContainsKey($_.$KeyProperty) })
        Removed  = @($Previous | Where-Object { $_.$KeyProperty -and -not $currKeys.ContainsKey($_.$KeyProperty) })
        Retained = @($Current  | Where-Object { $_.$KeyProperty -and $prevKeys.ContainsKey($_.$KeyProperty) })
        IsFirstRun = ($null -eq $Previous)
    }
}

function Send-GovernanceReport {
    <#  Sends the HTML report via Graph sendMail.  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string[]]$To,
        [string[]]$Cc,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$HtmlBody,
        [ValidateSet('Low','Normal','High')][string]$Importance = 'Normal'
    )
    $sizeKb = [math]::Round(([System.Text.Encoding]::UTF8.GetByteCount($HtmlBody) / 1KB), 1)
    if ($sizeKb -gt 100) {
        Write-Warning "Report body is ${sizeKb} KB. Gmail clips above ~102 KB - consider trimming detail tables."
    }

    $message = @{
        message = @{
            subject      = $Subject
            importance   = $Importance
            body         = @{ contentType = 'HTML'; content = $HtmlBody }
            toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
        }
        saveToSentItems = $true
    }
    if ($Cc) {
        $message.message.ccRecipients = @($Cc | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$From/sendMail" `
        -Body ($message | ConvertTo-Json -Depth 10)

    Write-Output "Report sent to $($To -join ', ') (${sizeKb} KB)."
}

Export-ModuleMember -Function *
```

Package and publish it:

```powershell
$modDir = ".\IdentityGovernance"
New-Item -ItemType Directory -Path $modDir -Force | Out-Null
# place IdentityGovernance.psm1 in $modDir
New-ModuleManifest -Path "$modDir\IdentityGovernance.psd1" `
    -RootModule 'IdentityGovernance.psm1' -ModuleVersion '1.0.0' `
    -Author 'Identity Team' -Description 'Shared helpers for identity governance runbooks' `
    -PowerShellVersion '7.2'

Compress-Archive -Path $modDir -DestinationPath ".\IdentityGovernance.zip" -Force
```

Upload the zip to a blob, then import from its SAS URL:

```powershell
$blobCtx = (Get-AzStorageAccount -ResourceGroupName $rg -Name $sa).Context
Set-AzStorageBlobContent -File .\IdentityGovernance.zip -Container 'state' `
    -Blob 'modules/IdentityGovernance.zip' -Context $blobCtx -Force

$sasUri = New-AzStorageBlobSASToken -Container 'state' -Blob 'modules/IdentityGovernance.zip' `
    -Permission r -ExpiryTime (Get-Date).AddHours(2) -FullUri -Context $blobCtx

New-AzAutomationModule -ResourceGroupName $rg -AutomationAccountName $aa `
    -Name 'IdentityGovernance' -ContentLinkUri $sasUri
```

---

## 11. The HTML report generator

### Email HTML is not web HTML

Outlook on Windows renders with the **Word** engine. That means:

- Tables for layout. No flexbox, no grid, no float.
- Inline styles on every element. `<style>` blocks are unreliable.
- Fixed pixel widths, max ~700px.
- Web-safe fonts with fallbacks. No web fonts.
- No background images, no CSS positioning.
- Explicit `cellpadding="0" cellspacing="0" border="0"` on every table.

Save this as a runbook or add it to the shared module.

```powershell
function New-IdentityReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Metrics,
        [hashtable]$Previous = @{},
        [array]$Actions       = @(),
        [array]$NewExclusions = @(),
        [array]$NewPrivileged = @(),
        [array]$Orphaned      = @(),
        [array]$ExpiringCreds = @(),
        [string]$TenantName   = 'Contoso',
        [string]$ReportUrl
    )

    $F      = "-apple-system,'Segoe UI',Arial,Helvetica,sans-serif"
    $navy   = '#1F3864'; $slate = '#595959'; $line = '#D9D9D9'
    $red    = '#C00000'; $amber = '#BF8F00'; $green = '#2E7D32'
    $redBg  = '#FDE8E8'; $amberBg = '#FFF6E0'; $greenBg = '#EAF5EA'

    function Esc([string]$s) {
        if ($null -eq $s) { return '' }
        [System.Net.WebUtility]::HtmlEncode($s)
    }

    # Delta cell: direction tells us whether an increase is bad
    function DeltaCell([string]$key, [int]$now, [string]$goodDirection = 'down') {
        if (-not $Previous.ContainsKey($key)) {
            return "<span style=`"color:$slate;font-size:12px;`">&mdash;</span>"
        }
        $d = $now - [int]$Previous[$key]
        if ($d -eq 0) { return "<span style=`"color:$slate;font-size:12px;`">no change</span>" }
        $sign  = if ($d -gt 0) { '+' } else { '' }
        $bad   = if ($goodDirection -eq 'down') { $d -gt 0 } else { $d -lt 0 }
        $col   = if ($bad) { $red } else { $green }
        return "<span style=`"color:$col;font-size:12px;font-weight:bold;`">$sign$d</span>"
    }

    function MetricRow([string]$label, [string]$key, [string]$goodDirection = 'down', [string]$severity = 'normal') {
        $val = if ($Metrics.ContainsKey($key)) { [int]$Metrics[$key] } else { 0 }
        $valCol = switch ($severity) {
            'high'   { if ($val -gt 0) { $red }   else { $green } }
            'medium' { if ($val -gt 0) { $amber } else { $green } }
            default  { $navy }
        }
        @"
<tr>
  <td style="padding:9px 12px;border-bottom:1px solid $line;font-family:$F;font-size:13px;color:#222;">$(Esc $label)</td>
  <td align="right" style="padding:9px 12px;border-bottom:1px solid $line;font-family:$F;font-size:16px;font-weight:bold;color:$valCol;">$val</td>
  <td align="right" style="padding:9px 12px;border-bottom:1px solid $line;font-family:$F;width:90px;">$(DeltaCell $key $val $goodDirection)</td>
</tr>
"@
    }

    function SectionHeader([string]$text) {
        @"
<tr><td style="padding:22px 12px 8px 12px;font-family:$F;font-size:15px;font-weight:bold;color:$navy;border-bottom:2px solid $navy;">$(Esc $text)</td></tr>
"@
    }

    function DetailTable([string]$title, [array]$rows, [string[]]$cols, [int]$max = 10) {
        if (-not $rows -or $rows.Count -eq 0) { return '' }
        $shown = $rows | Select-Object -First $max
        $head = ($cols | ForEach-Object {
            "<th align=`"left`" style=`"padding:6px 10px;background:#F2F2F2;border-bottom:1px solid $line;font-family:$F;font-size:11px;color:$slate;text-transform:uppercase;letter-spacing:0.4px;`">$(Esc $_)</th>"
        }) -join ''
        $body = ($shown | ForEach-Object {
            $r = $_
            $cells = ($cols | ForEach-Object {
                "<td style=`"padding:7px 10px;border-bottom:1px solid $line;font-family:$F;font-size:12px;color:#333;`">$(Esc ([string]$r.$_))</td>"
            }) -join ''
            "<tr>$cells</tr>"
        }) -join ''
        $more = if ($rows.Count -gt $max) {
            "<tr><td colspan=`"$($cols.Count)`" style=`"padding:7px 10px;font-family:$F;font-size:11px;color:$slate;font-style:italic;`">and $($rows.Count - $max) more &ndash; see the full report</td></tr>"
        } else { '' }
        @"
<tr><td style="padding:14px 12px 4px 12px;font-family:$F;font-size:13px;font-weight:bold;color:#222;">$(Esc $title)</td></tr>
<tr><td style="padding:0 12px 6px 12px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
    <tr>$head</tr>$body$more
  </table>
</td></tr>
"@
    }

    # ---- Act now banner -------------------------------------------------
    $actionBlock = if ($Actions.Count -gt 0) {
        $items = ($Actions | ForEach-Object {
            "<li style=`"margin:0 0 6px 0;font-family:$F;font-size:13px;color:#222;line-height:1.45;`">$(Esc $_)</li>"
        }) -join ''
        @"
<tr><td style="padding:0 12px 4px 12px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:$redBg;border-left:4px solid $red;border-collapse:collapse;">
    <tr><td style="padding:14px 16px;">
      <div style="font-family:$F;font-size:14px;font-weight:bold;color:$red;padding-bottom:8px;">Act now</div>
      <ul style="margin:0;padding-left:18px;">$items</ul>
    </td></tr>
  </table>
</td></tr>
"@
    } else {
        @"
<tr><td style="padding:0 12px 4px 12px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:$greenBg;border-left:4px solid $green;border-collapse:collapse;">
    <tr><td style="padding:14px 16px;font-family:$F;font-size:13px;color:$green;">
      No threshold breaches this run. Deltas below still merit a look.
    </td></tr>
  </table>
</td></tr>
"@
    }

    $reportLink = if ($ReportUrl) {
        "<a href=`"$ReportUrl`" style=`"color:$navy;`">Open the full report</a> &middot; "
    } else { '' }

    # ---- Assemble --------------------------------------------------------
@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identity Governance Report</title></head>
<body style="margin:0;padding:0;background:#F4F5F7;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F4F5F7;">
<tr><td align="center" style="padding:20px 10px;">

<table width="700" cellpadding="0" cellspacing="0" border="0" style="width:700px;max-width:700px;background:#FFFFFF;border-collapse:collapse;border:1px solid $line;">

  <tr><td style="background:$navy;padding:20px 24px;">
    <div style="font-family:$F;font-size:19px;font-weight:bold;color:#FFFFFF;">Identity Governance Report</div>
    <div style="font-family:$F;font-size:12px;color:#B9C6DC;padding-top:4px;">$(Esc $TenantName) &middot; $(Get-Date -Format 'dddd d MMMM yyyy')</div>
  </td></tr>

  <tr><td style="padding:16px 0 0 0;"><table width="100%" cellpadding="0" cellspacing="0" border="0">
    $actionBlock
  </table></td></tr>

  <tr><td><table width="100%" cellpadding="0" cellspacing="0" border="0">

    $(SectionHeader 'Privileged access')
    <tr><td style="padding:0 12px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
      $(MetricRow 'People with Tier 0 access'                    'Tier0People'        'down' 'normal')
      $(MetricRow 'Privileged in BOTH planes'                    'BothPlanes'         'down' 'medium')
      $(MetricRow 'Tier 0 without phishing-resistant MFA'        'Tier0NoPhish'       'down' 'high')
      $(MetricRow 'Tier 0 AD without smartcard required'         'Tier0NoSmartcard'   'down' 'high')
      $(MetricRow 'Standing (non-PIM) Tier 0 roles'              'StandingTier0'      'down' 'medium')
      $(MetricRow 'Privilege via group membership'                'PrivViaGroup'       'down' 'normal')
      $(MetricRow 'Tier 0 via group ONLY (no direct role)'        'Tier0GroupOnly'     'down' 'high')
      $(MetricRow 'Orphaned admin accounts'                      'OrphanedAdmins'     'down' 'high')
      $(MetricRow 'Not attested by a line manager'               'NotAttested'        'down' 'medium')
    </table></td></tr>

    $(SectionHeader 'Conditional Access exclusions')
    <tr><td style="padding:0 12px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
      $(MetricRow 'Identities excluded from CA'                  'Excluded'           'down' 'normal')
      $(MetricRow 'Exclusions EXPIRED'                           'ExclExpired'        'down' 'high')
      $(MetricRow 'Exclusions with NO expiry set'                'ExclNoExpiry'       'down' 'medium')
      $(MetricRow 'Excluded AND Azure privileged'                'ExclAzurePriv'      'down' 'high')
      $(MetricRow 'Excluded directly, not via a group'           'ExclDirect'         'down' 'medium')
      $(MetricRow 'Excluded but not in the inventory'            'ExclNotInventoried' 'down' 'medium')
    </table></td></tr>

    $(SectionHeader 'Service identities')
    <tr><td style="padding:0 12px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
      $(MetricRow 'Credentials expiring within 30 days'          'CredsExpiring30'    'down' 'medium')
      $(MetricRow 'Credentials already expired'                  'CredsExpired'       'down' 'high')
      $(MetricRow 'High-risk permission, no registered owner'    'HighRiskNoOwner'    'down' 'high')
      $(MetricRow 'Identities with no owning team'               'NoOwner'            'down' 'medium')
      $(MetricRow 'Dormant 90+ days'                             'Dormant90'          'down' 'normal')
    </table></td></tr>

    $(SectionHeader 'Progress')
    <tr><td style="padding:0 12px;"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
      $(MetricRow 'Governance completeness (%)'                  'GovernancePct'      'up'   'normal')
      $(MetricRow 'Attestation completeness (%)'                 'AttestationPct'     'up'   'normal')
    </table></td></tr>

    $(SectionHeader 'What changed')
    $(DetailTable 'New CA exclusions'      $NewExclusions @('DisplayName','IdentityType','ExclusionGroups','ExcludedPolicies'))
    $(DetailTable 'New privileged access'  $NewPrivileged @('PersonDisplayName','Plane','Role','Tier'))
    $(DetailTable 'Newly orphaned admins'  $Orphaned      @('AdminAccount','PersonDisplayName','HighestRole'))
    $(DetailTable 'Credentials expiring'   $ExpiringCreds @('DisplayName','CredentialType','DaysToExpiry','OwnerTeam'))

  </table></td></tr>

  <tr><td style="padding:20px 24px;background:#FAFAFA;border-top:1px solid $line;">
    <div style="font-family:$F;font-size:11px;color:$slate;line-height:1.6;">
      $reportLink Generated $(Get-Date -Format 'dd/MM/yyyy HH:mm') AEST by Azure Automation.<br>
      Sign-in activity for service principals uses a beta Graph endpoint and is indicative.
      AD last-logon derives from lastLogonTimestamp and can lag by up to 14 days.
      Azure role assignments outside the reporting identity's read scope will not appear.<br>
      This report contains identity data. Do not forward outside the distribution list.
    </div>
  </td></tr>

</table>
</td></tr></table>
</body></html>
"@
}
```

The `$Actions` array is what makes the report actionable — build it in the runbook from threshold breaches, not from raw counts.

---

## 12. The runbooks

### Runbook A: `Collect-CloudIdentity`

Azure sandbox. Adapt the collection logic from `Build-CAExclusionMap.ps1`, `Build-IdentityInventory.ps1`, `Build-AzureResourceMap.ps1` and `Build-CloudAdminReview.ps1`, replacing the interactive connect with the managed identity.

```powershell
<#  Runbook: Collect-CloudIdentity  #>
param(
    [Parameter(Mandatory)][string]$StorageAccountName
)

$ErrorActionPreference = 'Stop'
Import-Module IdentityGovernance

Connect-GovernanceGraph
$ctx = Get-GovernanceStorageContext -StorageAccountName $StorageAccountName

# --- collection (adapted from the interactive scripts) -------------------
# Reuse the bodies of the existing scripts here. The only changes needed:
#   1. Replace Connect-MgGraph -Scopes ... with Connect-GovernanceGraph
#   2. Replace Connect-AzAccount with Connect-AzAccount -Identity
#   3. Return objects instead of writing CSVs

$exclusions = Get-CAExclusionMap        # from Build-CAExclusionMap.ps1
$identities = Get-IdentityInventory     # from Build-IdentityInventory.ps1
$azureRbac  = Get-AzureResourceMap      # from Build-AzureResourceMap.ps1
$cloudAdmins= Get-CloudAdminReview      # from Build-CloudAdminReview.ps1

$snapshot = [PSCustomObject]@{
    CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Exclusions   = $exclusions
    Identities   = $identities
    AzureRbac    = $azureRbac
    CloudAdmins  = $cloudAdmins
}

Save-GovernanceState -Context $ctx -Name 'cloud' -Data $snapshot
Write-Output "Cloud collection complete: $($exclusions.Count) exclusions, $($cloudAdmins.Count) cloud admins."
```

> **Refactoring note.** Wrap the body of each existing script in a function (`Get-CAExclusionMap` and so on) that returns objects rather than calling `Export-Csv`. Add those functions to the shared module. That way one implementation serves both the interactive workflow and the runbook, and they cannot drift apart.
>
> Both `Build-CAExclusionMap.ps1` and `Build-CloudAdminReview.ps1` expand groups transitively, each with its own cache. When you refactor, lift that into a single shared `Expand-DirectoryGroup` function with one cache for the whole run — a group that excludes identities from Conditional Access is very often the same group that grants a role, and expanding it twice doubles the Graph calls for no benefit.

### Runbook B: `Collect-ADIdentity`

Hybrid Worker. Same pattern, using `Build-ADInventory.ps1` and `Build-OnPremAdminReview.ps1`.

```powershell
<#  Runbook: Collect-ADIdentity  -  runs on the Hybrid Worker  #>
param(
    [Parameter(Mandatory)][string]$StorageAccountName
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Import-Module IdentityGovernance

# On the Hybrid Worker the managed identity is not available, so authenticate
# to storage with the worker's own identity (Arc-enabled machine identity)
Connect-AzAccount -Identity | Out-Null
$ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount

$adAccounts   = Get-ADInventory          # from Build-ADInventory.ps1
$onPremAdmins = Get-OnPremAdminReview    # from Build-OnPremAdminReview.ps1

$snapshot = [PSCustomObject]@{
    CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    ADAccounts   = $adAccounts
    OnPremAdmins = $onPremAdmins
}

Save-GovernanceState -Context $ctx -Name 'ad' -Data $snapshot
Write-Output "AD collection complete: $($adAccounts.Count) accounts, $($onPremAdmins.Count) admins."
```

If the Hybrid Worker is Arc-enabled, `Connect-AzAccount -Identity` uses the machine's Arc identity — grant that identity `Storage Blob Data Contributor` on the storage account as well.

### Runbook C: `Send-IdentityReport`

Reads both snapshots, computes deltas, builds thresholds, renders and sends.

```powershell
<#  Runbook: Send-IdentityReport  #>
param(
    [Parameter(Mandatory)][string]$StorageAccountName,
    [Parameter(Mandatory)][string]$FromAddress,
    [Parameter(Mandatory)][string]$ToAddresses,       # comma separated
    [string]$CcAddresses,
    [string]$TenantDisplayName = 'Contoso'
)

$ErrorActionPreference = 'Stop'
Import-Module IdentityGovernance

Connect-GovernanceGraph
$ctx = Get-GovernanceStorageContext -StorageAccountName $StorageAccountName

# Current snapshots, written by runbooks A and B
$cloud = Get-GovernanceState -Context $ctx -Name 'cloud'
$ad    = Get-GovernanceState -Context $ctx -Name 'ad'
if (-not $cloud) { throw "No cloud snapshot found. Run Collect-CloudIdentity first." }

# Previous run, for diffing
$prevCloud = Get-GovernanceState -Context $ctx -Name 'cloud-previous'
$prevAd    = Get-GovernanceState -Context $ctx -Name 'ad-previous'

# ---- Deltas -------------------------------------------------------------
$exclDelta = Get-GovernanceDelta -Previous $prevCloud.Exclusions -Current $cloud.Exclusions -KeyProperty 'ObjectId'
$adminDelta= Get-GovernanceDelta -Previous $prevCloud.CloudAdmins -Current $cloud.CloudAdmins -KeyProperty 'Object ID'

# ---- Metrics ------------------------------------------------------------
$metrics = @{
    Tier0People        = @($cloud.CloudAdmins | Where-Object { $_.'Overall Tier' -eq 0 }).Count
    BothPlanes         = 0   # computed from the merge, see Merge-AdminReview logic
    Tier0NoPhish       = @($cloud.CloudAdmins | Where-Object { $_.'Overall Tier' -eq 0 -and $_.'Phishing Resistant' -ne 'Yes' -and $_.Enabled -eq 'Yes' }).Count
    Tier0NoSmartcard   = @($ad.OnPremAdmins   | Where-Object { $_.'AD Tier' -eq 0 -and $_.'Smartcard Required' -eq 'No' -and $_.Enabled -eq 'Yes' }).Count
    StandingTier0      = @($cloud.CloudAdmins | Where-Object { $_.'Overall Tier' -eq 0 -and [int]$_.'Active Role Count' -gt 0 }).Count
    PrivViaGroup       = @($cloud.CloudAdmins | Where-Object { [int]$_.'Group Assignments' -gt 0 }).Count
    Tier0GroupOnly     = @($cloud.CloudAdmins | Where-Object { $_.'Overall Tier' -eq 0 -and $_.'Assignment Route' -eq 'Group only' }).Count
    OrphanedAdmins     = @($cloud.CloudAdmins + $ad.OnPremAdmins | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') }).Count
    NotAttested        = 0
    Excluded           = @($cloud.Exclusions).Count
    ExclExpired        = 0   # needs the manual expiry data - see note below
    ExclNoExpiry       = 0
    ExclAzurePriv      = 0
    ExclDirect         = @($cloud.Exclusions | Where-Object { $_.ExclusionMechanism -like '*Direct*' }).Count
    ExclNotInventoried = 0
    CredsExpiring30    = @($cloud.Identities.ServicePrincipals | Where-Object { $_.DaysToExpiry -ge 0 -and $_.DaysToExpiry -le 30 }).Count
    CredsExpired       = @($cloud.Identities.ServicePrincipals | Where-Object { $_.DaysToExpiry -lt 0 }).Count
    HighRiskNoOwner    = @($cloud.Identities.ServicePrincipals | Where-Object { $_.'Permission Risk' -eq 'High' -and -not $_.'Registered Owner (Graph)' }).Count
    NoOwner            = 0
    Dormant90          = @($cloud.Identities.Accounts | Where-Object { [int]$_.DaysSinceSignIn -gt 90 }).Count
    GovernancePct      = 0
    AttestationPct     = 0
}

# Previous metrics for the delta column
$prevMetrics = @{}
try {
    $tmp = Join-Path $env:TEMP 'metrics-prev.json'
    Get-AzStorageBlobContent -Container 'state' -Blob 'metrics-latest.json' `
        -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null
    (Get-Content $tmp -Raw | ConvertFrom-Json).PSObject.Properties |
        ForEach-Object { $prevMetrics[$_.Name] = $_.Value }
} catch { Write-Warning "No previous metrics - first run, deltas will be blank." }

# ---- Thresholds -> the Act now list ------------------------------------
$actions = @()
if ($metrics.OrphanedAdmins -gt 0) {
    $actions += "$($metrics.OrphanedAdmins) orphaned admin account(s): enabled admin access whose standard account is disabled or missing. Almost certainly leavers - disable today."
}
if ($metrics.Tier0NoPhish -gt 0) {
    $actions += "$($metrics.Tier0NoPhish) Tier 0 cloud admin(s) without a phishing-resistant method. A phished Tier 0 admin is a tenant compromise."
}
if ($metrics.Tier0NoSmartcard -gt 0) {
    $actions += "$($metrics.Tier0NoSmartcard) Tier 0 AD account(s) with no smartcard requirement - a password alone protects the domain."
}
if ($exclDelta.Added.Count -gt 0 -and -not $exclDelta.IsFirstRun) {
    $actions += "$($exclDelta.Added.Count) new Conditional Access exclusion(s) since the last run. Confirm each was approved."
}
if ($metrics.Tier0GroupOnly -gt 0) {
    $actions += "$($metrics.Tier0GroupOnly) account(s) hold Tier 0 through group membership alone. They look unprivileged on their own object - remediation is group removal, not role removal."
}
if ($metrics.CredsExpired -gt 0) {
    $actions += "$($metrics.CredsExpired) service principal credential(s) already expired - either broken, or a second credential exists that has not been inventoried."
}
if ($metrics.ExclExpired -gt 0) {
    $actions += "$($metrics.ExclExpired) exclusion(s) past their approved expiry date. Remove or re-approve."
}

# ---- Build and send -----------------------------------------------------
$orphanRows = @($cloud.CloudAdmins + $ad.OnPremAdmins |
    Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') } |
    ForEach-Object {
        [PSCustomObject]@{
            AdminAccount      = if ($_.'Admin UPN') { $_.'Admin UPN' } else { $_.SamAccountName }
            PersonDisplayName = $_.'Person Display Name'
            HighestRole       = if ($_.'Highest Entra Role') { $_.'Highest Entra Role' } else { $_.'Highest AD Group' }
        }
    })

$html = New-IdentityReportHtml `
    -Metrics $metrics -Previous $prevMetrics -Actions $actions `
    -NewExclusions $exclDelta.Added -Orphaned $orphanRows `
    -TenantName $TenantDisplayName

# Archive the rendered report
$reportBlob = "$(Get-Date -Format 'yyyy-MM-dd').html"
$tmpHtml = Join-Path $env:TEMP $reportBlob
$html | Out-File $tmpHtml -Encoding utf8 -Force
Set-AzStorageBlobContent -File $tmpHtml -Container 'reports' -Blob $reportBlob -Context $ctx -Force | Out-Null

# Subject line carries the headline so it reads in a notification preview
$subject = if ($actions.Count -gt 0) {
    "[Action] Identity Governance - $($actions.Count) item(s) need attention"
} else {
    "Identity Governance - $(Get-Date -Format 'd MMM yyyy')"
}

Send-GovernanceReport -From $FromAddress `
    -To ($ToAddresses -split ',' | ForEach-Object { $_.Trim() }) `
    -Cc (if ($CcAddresses) { $CcAddresses -split ',' | ForEach-Object { $_.Trim() } }) `
    -Subject $subject -HtmlBody $html `
    -Importance (if ($actions.Count -gt 0) { 'High' } else { 'Normal' })

# Roll current -> previous, and save metrics for next run's deltas
$metrics | ConvertTo-Json -Depth 4 | Out-File (Join-Path $env:TEMP 'metrics.json') -Encoding utf8 -Force
Set-AzStorageBlobContent -File (Join-Path $env:TEMP 'metrics.json') -Container 'state' `
    -Blob 'metrics-latest.json' -Context $ctx -Force | Out-Null
Start-AzStorageBlobCopy -SrcContainer 'state' -SrcBlob 'cloud-latest.json' `
    -DestContainer 'state' -DestBlob 'cloud-previous.json' -Context $ctx -Force | Out-Null
if ($ad) {
    Start-AzStorageBlobCopy -SrcContainer 'state' -SrcBlob 'ad-latest.json' `
        -DestContainer 'state' -DestBlob 'ad-previous.json' -Context $ctx -Force | Out-Null
}
```

> **On the governance metrics.** `ExclExpired`, `ExclNoExpiry`, `NoOwner`, `GovernancePct` and `AttestationPct` come from the *manually maintained* columns in the workbooks, which the scripts never see. To report on them, either export the workbook to a SharePoint list the runbook can read, or move the governance data into a small Azure Table the workbook and runbook both use. Until then, leave them at zero rather than reporting a misleading number.

### Publishing the runbooks

```powershell
foreach ($name in 'Collect-CloudIdentity','Collect-ADIdentity','Send-IdentityReport') {
    Import-AzAutomationRunbook -ResourceGroupName $rg -AutomationAccountName $aa `
        -Path ".\$name.ps1" -Name $name -Type PowerShell72 -Force -Published
}
```

---

## 13. Scheduling

Stagger the three so collection finishes before the report is built.

```powershell
$base = (Get-Date '06:00').AddDays(1)   # local time

$schedules = @(
    @{ Name='IdentityCollect-Cloud';  Start=$base;                 Runbook='Collect-CloudIdentity' }
    @{ Name='IdentityCollect-AD';     Start=$base.AddMinutes(30);  Runbook='Collect-ADIdentity'    }
    @{ Name='IdentityReport-Send';    Start=$base.AddMinutes(90);  Runbook='Send-IdentityReport'   }
)

foreach ($s in $schedules) {
    New-AzAutomationSchedule -ResourceGroupName $rg -AutomationAccountName $aa `
        -Name $s.Name -StartTime $s.Start -WeekInterval 1 `
        -DaysOfWeek Monday -TimeZone 'Australia/Sydney'

    $params = @{ StorageAccountName = $sa }
    if ($s.Runbook -eq 'Send-IdentityReport') {
        $params += @{
            FromAddress       = 'identity-reports@corp.com.au'
            ToAddresses       = 'iam-team@corp.com.au,security-ops@corp.com.au'
            TenantDisplayName = 'Contoso'
        }
    }

    Register-AzAutomationScheduledRunbook -ResourceGroupName $rg -AutomationAccountName $aa `
        -RunbookName $s.Runbook -ScheduleName $s.Name -Parameters $params
}
```

Register the AD runbook against the Hybrid Worker group:

```powershell
Register-AzAutomationScheduledRunbook -ResourceGroupName $rg -AutomationAccountName $aa `
    -RunbookName 'Collect-ADIdentity' -ScheduleName 'IdentityCollect-AD' `
    -RunOn $hwGroup -Parameters @{ StorageAccountName = $sa }
```

**Cadence.** Weekly on Monday morning suits most teams — findings land at the start of the week when there's capacity to act. Daily produces alert fatigue within a month. Monthly is too slow to catch a new exclusion while anyone remembers making it.

**Timezone.** Set it explicitly to `Australia/Sydney`. Automation schedules default to UTC, and a report arriving at 4pm Sunday gets ignored.

---

## 14. Testing

Work up in stages rather than scheduling straight away.

**1. Managed identity can authenticate**

```powershell
# As a test runbook
Connect-MgGraph -Identity -NoWelcome
Get-MgContext
(Get-MgUser -Top 1).DisplayName
```

**2. Storage read and write**

```powershell
Connect-AzAccount -Identity
$c = New-AzStorageContext -StorageAccountName $sa -UseConnectedAccount
'test' | Out-File $env:TEMP\t.txt
Set-AzStorageBlobContent -File $env:TEMP\t.txt -Container 'state' -Blob 'test.txt' -Context $c -Force
Get-AzStorageBlob -Container 'state' -Context $c
```

**3. Email delivery, to yourself only**

Run `Send-IdentityReport` manually with `-ToAddresses` set to your own address. Check rendering in:

- Outlook desktop (Word engine — the strictest)
- Outlook web
- Outlook mobile
- Gmail, if anyone external receives it

**4. Delta logic**

Run the collection twice, manually change something between runs (add a test account to an exclusion group), and confirm it appears under *What changed*. This is the part most likely to be subtly wrong, and a silent failure here means the report looks fine while telling you nothing.

**5. First-run behaviour**

Delete the `*-previous.json` blobs and confirm the report renders sensibly with no deltas rather than throwing.

---

## 15. Alert thresholds

The weekly report is for routine review. Some findings shouldn't wait a week.

Add a lightweight daily runbook that only sends when something crosses a line:

```powershell
<#  Runbook: Check-IdentityAlerts  -  daily, silent unless something fires  #>
param(
    [Parameter(Mandatory)][string]$StorageAccountName,
    [Parameter(Mandatory)][string]$FromAddress,
    [Parameter(Mandatory)][string]$ToAddresses
)

Import-Module IdentityGovernance
Connect-GovernanceGraph
$ctx = Get-GovernanceStorageContext -StorageAccountName $StorageAccountName

$current  = Get-CAExclusionMap
$previous = (Get-GovernanceState -Context $ctx -Name 'cloud').Exclusions
$delta    = Get-GovernanceDelta -Previous $previous -Current $current -KeyProperty 'ObjectId'

$alerts = @()

# A new exclusion on a privileged identity should never wait a week
foreach ($e in $delta.Added) {
    $alerts += "New CA exclusion: $($e.DisplayName) ($($e.IdentityType)) via $($e.ExclusionGroups), affecting $($e.ExcludedPolicies)"
}

# New members of role-assignable groups.
#
# This is arguably the highest-value alert available. Adding someone to a
# role-assignable group grants privilege immediately, changes no role
# assignment, and touches no admin account - so nothing else in this pipeline
# would flag it. It is also the quietest way to escalate in most tenants.
$currentAdmins = Get-CloudAdminReview
$prevAdmins    = (Get-GovernanceState -Context $ctx -Name 'cloud').CloudAdmins

foreach ($a in $currentAdmins) {
    $was = $prevAdmins | Where-Object { $_.'Object ID' -eq $a.'Object ID' }
    if (-not $was) {
        if ($a.'Overall Tier' -eq 0) {
            $alerts += "New Tier 0 admin account: $($a.'Admin UPN') holding $($a.'Highest Entra Role')"
        }
        continue
    }
    $nowGroups  = @(($a.'Granting Groups'   -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $wasGroups  = @(($was.'Granting Groups' -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $addedGroups = @($nowGroups | Where-Object { $_ -notin $wasGroups })
    foreach ($g in $addedGroups) {
        $alerts += "$($a.'Admin UPN') was added to privileged group '$g' (now holds $($a.'Highest Entra Role'))"
    }
    if ($a.'Overall Tier' -eq 0 -and $was.'Overall Tier' -ne 0) {
        $alerts += "$($a.'Admin UPN') escalated to Tier 0: $($a.'Highest Entra Role')"
    }
}

if ($alerts.Count -eq 0) {
    Write-Output "No alerts."
    return
}

$body = "<html><body style=`"font-family:Arial,sans-serif;font-size:13px;`">"
$body += "<p style=`"font-weight:bold;color:#C00000;`">Identity governance alert</p><ul>"
$body += ($alerts | ForEach-Object { "<li style=`"margin-bottom:6px;`">$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join ''
$body += "</ul><p style=`"color:#595959;font-size:11px;`">Detected $(Get-Date -Format 'dd/MM/yyyy HH:mm') AEST. Full report Monday.</p></body></html>"

Send-GovernanceReport -From $FromAddress -To ($ToAddresses -split ',') `
    -Subject "[Alert] $($alerts.Count) identity governance change(s) detected" `
    -HtmlBody $body -Importance High
```

**Silent when nothing fires.** An alert runbook that emails "nothing to report" daily trains people to filter it, and then the one that matters gets filtered too.

---

## 16. Security considerations

**The report contains sensitive data.** Names of privileged accounts, which controls they bypass, and where the gaps are. That is close to a targeting document. Decide deliberately:

- Restrict the distribution list and review it as carefully as any other privileged group
- Consider summary metrics in the email body with detail tables behind a link to a permissioned SharePoint or Blob location
- The footer includes a do-not-forward note, but that's a convention, not a control — sensitivity labels are the actual mechanism

**The managed identity is itself a privileged identity.** It holds tenant-wide directory read and `Mail.Send`. It should appear in your own service identity inventory, with an owner and a review date. An automation that reports on ungoverned identities while being one itself is an awkward finding.

**Scope `Mail.Send` with an Application Access Policy.** Unrestricted it can send as anyone in the tenant, which is a convincing phishing primitive. Verify with `Test-ApplicationAccessPolicy` against a mailbox it should *not* be able to use.

**No secrets anywhere.** Managed identity throughout — no client secrets, no stored credentials, nothing to rotate or leak.

**Storage.** Private containers, no public access, TLS 1.2 minimum. Consider a private endpoint if the data classification warrants it.

**Audit the automation.** Enable diagnostic settings on the Automation Account to Log Analytics. Someone modifying a runbook to suppress findings is a plausible attack, and job logs are the evidence.

**Change control.** Runbooks that read the directory should be source-controlled and deployed through a pipeline, not edited in the portal.

---

## 17. Troubleshooting

**`Connect-MgGraph -Identity` fails with "no managed identity endpoint".**
Running on a Hybrid Worker, which has no Azure Automation managed identity. Use the machine's Arc identity, or move that logic to a sandbox runbook.

**Graph calls return 403 despite the app role assignment.**
App role assignments can take up to an hour. Confirm with `Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId` and check the role's `Value`, not just its presence.

**Module import stuck in Creating.**
Usually a dependency ordering problem. Delete the failed module, import `Microsoft.Graph.Authentication` alone, wait for `Available`, then retry.

**`sendMail` returns `ErrorAccessDenied`.**
Either the Application Access Policy excludes the sending mailbox, or the policy is still propagating. Test with `Test-ApplicationAccessPolicy`, then wait 30 minutes.

**Report renders correctly in Outlook web, badly in Outlook desktop.**
The Word rendering engine. Almost always caused by CSS in a `<style>` block, a `div`-based layout, or `float`. Move everything to inline styles on table elements.

**Email arrives with content clipped and a "View entire message" link.**
Over Gmail's ~102 KB limit. Reduce the `-max` parameter on the detail tables.

**Runbook times out at three hours.**
Azure sandbox fair-share limit. The most common cause is group expansion: every role-assignable group and every CA exclusion group is expanded transitively, and on a large tenant that is a lot of Graph calls. The scripts cache each group, so the cost scales with the number of distinct groups rather than assignments — but check the verbose output for how many are being expanded before assuming something is stuck. Failing that, split the collection, or move heavy runs to the Hybrid Worker, which has no such cap.

**Deltas always blank.**
The `*-previous.json` roll isn't happening. Confirm the copy at the end of `Send-IdentityReport` succeeded, and that the blob names match exactly.

**AD runbook succeeds but returns nothing.**
Check the Hybrid Worker's run-as identity has read access, and that the RSAT module is installed for the account executing the job — not just for your interactive session.

---

## 18. Cost

Indicative, for a mid-sized tenant on weekly collection:

| Component | Approximate monthly |
|---|---|
| Automation Account | Free tier covers 500 job minutes; typical use fits |
| Job minutes beyond free tier | A few dollars |
| Storage (JSON + HTML, 2-year retention) | Under a dollar |
| Hybrid Worker | Free if the VM already exists |
| Graph and Resource Graph calls | No charge |

Realistically under $10/month unless you run daily collection across a very large tenant. The Hybrid Worker VM, if you have to stand one up for this, will dominate the cost — look for an existing management server first.

---

## Build order

1. Resource group, Automation Account, storage — 1 hour
2. Module imports — 40 minutes, mostly waiting
3. Graph permissions on the managed identity — **start early, approval-dependent**
4. Refactor existing scripts into module functions returning objects — half a day
5. Shared module, published — 1 hour
6. Cloud collection runbook, tested manually — half a day
7. Email setup and Application Access Policy — 2 hours plus propagation
8. Report generator, tested against real data in every client — half a day
9. Hybrid Worker and AD runbook — half a day, plus server provisioning
10. Schedules — 1 hour
11. Daily alert runbook — 2 hours

**Get steps 1–8 working before touching the Hybrid Worker.** The cloud half delivers most of the value and none of the infrastructure friction. Adding AD to a working pipeline is far easier than debugging both at once.

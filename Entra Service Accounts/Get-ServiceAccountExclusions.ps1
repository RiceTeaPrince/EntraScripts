<#
.SYNOPSIS
    Lists service accounts and whether each is excluded from any Conditional Access policy.

.DESCRIPTION
    Self-contained. Produces a single CSV. No workbook, no Azure dependencies.

    Reads every enabled Conditional Access policy, expands each excluding group
    transitively (so nested groups are caught), then reports which service accounts
    land in that set.

    READ-ONLY. Makes no changes to the tenant.

.PARAMETER Identification
    How to decide what counts as a service account. This is the decision that
    determines whether the deliverable is credible - agree it before you run.

      Group   - members of the groups named in -SourceGroup. Most defensible if
                you already maintain such a group.
      Naming  - accounts matching -NamePattern. Most common starting point.
      Both    - union of the two. Default.
      Heuristic - adds accounts with no interactive sign-in but recent
                non-interactive activity. Widest net, needs manual review.

.PARAMETER SourceGroup
    One or more group display names or object IDs whose members are service accounts.

.PARAMETER NamePattern
    Regex matched against display name and UPN. Default covers common conventions.

.PARAMETER IncludeWorkloadIdentities
    Also include service principals and managed identities. Off by default - "service
    account" usually means the user-based kind, so confirm before widening.

.PARAMETER IncludeReportOnly
    Include report-only CA policies. Off by default: a report-only exclusion is not
    yet a live gap.

.EXAMPLE
    .\Get-ServiceAccountExclusions.ps1 -SourceGroup 'SG-Service-Accounts' -Verbose

.EXAMPLE
    .\Get-ServiceAccountExclusions.ps1 -Identification Naming -NamePattern '^(svc|sa)[-_]' -IncludeWorkloadIdentities

.NOTES
    Install-Module Microsoft.Graph -Scope CurrentUser

    Scopes: Policy.Read.All, Group.Read.All, Directory.Read.All,
            User.Read.All, Application.Read.All, AuditLog.Read.All

    AuditLog.Read.All plus Entra ID P1 is only needed for sign-in columns.
    Without it the script still runs; those columns come back blank.
#>

[CmdletBinding()]
param(
    [ValidateSet('Group','Naming','Both','Heuristic')]
    [string]$Identification = 'Both',
    [string[]]$SourceGroup,
    [string]$NamePattern = '^(svc|sa|srv|app|int|auto)[-_. ]|service.?account|automation|integration|daemon|batch|scheduler',
    [switch]$IncludeWorkloadIdentities,
    [switch]$IncludeReportOnly,
    [string]$OutputPath = ".\Service-Account-CA-Exclusions.csv",
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'
$Scopes = @('Policy.Read.All','Group.Read.All','Directory.Read.All','User.Read.All',
            'Application.Read.All','AuditLog.Read.All')

if (-not (Get-MgContext)) {
    if ($TenantId) { Connect-MgGraph -Scopes $Scopes -TenantId $TenantId | Out-Null }
    else           { Connect-MgGraph -Scopes $Scopes | Out-Null }
}
$ctx = Get-MgContext
Write-Host "Tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Cyan

if ($Identification -in @('Group','Both') -and -not $SourceGroup) {
    Write-Warning "No -SourceGroup supplied; falling back to naming pattern only."
    $Identification = 'Naming'
}

$GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

# ==========================================================================
# STEP 1 - Build the set of excluded object IDs
# ==========================================================================
Write-Host "`nReading Conditional Access policies..." -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy -All

$excluded = @{}   # objectId -> @{ Groups; Policies; Mechanisms }
$groupCache = @{}
$considered = 0

function Add-Exclusion($id, $groupName, $policyName, $mechanism) {
    if (-not $excluded.ContainsKey($id)) {
        $excluded[$id] = @{ Groups = @(); Policies = @(); Mechanisms = @() }
    }
    if ($groupName) { $excluded[$id].Groups += $groupName }
    $excluded[$id].Policies    += $policyName
    $excluded[$id].Mechanisms  += $mechanism
}

foreach ($p in $policies) {
    if ($p.State -eq 'disabled') { continue }
    if ($p.State -eq 'enabledForReportingButNotEnforced' -and -not $IncludeReportOnly) { continue }
    $considered++
    Write-Verbose "  $($p.DisplayName) [$($p.State)]"

    foreach ($gid in @($p.Conditions.Users.ExcludeGroups)) {
        if (-not $gid) { continue }
        if (-not $groupCache.ContainsKey($gid)) {
            $name = try { (Get-MgGroup -GroupId $gid -Property Id,DisplayName).DisplayName } catch { "UNRESOLVED ($gid)" }
            $members = try { Get-MgGroupTransitiveMember -GroupId $gid -All } catch {
                Write-Warning "Could not expand group $gid : $($_.Exception.Message)"; @()
            }
            $groupCache[$gid] = @{ Name = $name; Members = $members }
        }
        $g = $groupCache[$gid]
        foreach ($m in $g.Members) {
            $odata = ($m.AdditionalProperties['@odata.type'] -replace '#microsoft\.graph\.','')
            if ($odata -eq 'group') { continue }
            Add-Exclusion $m.Id $g.Name $p.DisplayName 'Group membership'
        }
    }

    foreach ($uid in @($p.Conditions.Users.ExcludeUsers)) {
        if ($uid -and $uid -match $GuidPattern) { Add-Exclusion $uid $null $p.DisplayName 'Direct exclusion' }
    }
    foreach ($spid in @($p.Conditions.ClientApplications.ExcludeServicePrincipals)) {
        if ($spid -and $spid -match $GuidPattern) { Add-Exclusion $spid $null $p.DisplayName 'Direct exclusion' }
    }
}
Write-Host "  $considered policy/policies considered, $($excluded.Keys.Count) excluded object(s) found"

# ==========================================================================
# STEP 2 - Identify service accounts
# ==========================================================================
Write-Host "`nIdentifying service accounts..." -ForegroundColor Cyan
$candidates = [System.Collections.Generic.List[object]]::new()

# --- from designated groups ---
$fromGroup = @{}
if ($Identification -in @('Group','Both') -and $SourceGroup) {
    foreach ($sg in $SourceGroup) {
        $grp = if ($sg -match $GuidPattern) { Get-MgGroup -GroupId $sg }
               else { Get-MgGroup -Filter "displayName eq '$($sg -replace "'","''")'" | Select-Object -First 1 }
        if (-not $grp) { Write-Warning "Group not found: $sg"; continue }
        Write-Verbose "  Expanding source group '$($grp.DisplayName)'"
        foreach ($m in (Get-MgGroupTransitiveMember -GroupId $grp.Id -All)) {
            $odata = ($m.AdditionalProperties['@odata.type'] -replace '#microsoft\.graph\.','')
            if ($odata -eq 'group') { continue }
            $fromGroup[$m.Id] = $grp.DisplayName
        }
    }
    Write-Host "  $($fromGroup.Keys.Count) member(s) from designated group(s)"
}

# --- users ---
$userProps = @('Id','DisplayName','UserPrincipalName','AccountEnabled','UserType','CreatedDateTime','SignInActivity')
$users = try { Get-MgUser -All -Property $userProps -PageSize 999 }
         catch {
             Write-Warning "Falling back without signInActivity (needs Entra ID P1): $($_.Exception.Message)"
             Get-MgUser -All -Property ($userProps | Where-Object { $_ -ne 'SignInActivity' }) -PageSize 999
         }

foreach ($u in $users) {
    $how = @()
    if ($fromGroup.ContainsKey($u.Id)) { $how += "Group: $($fromGroup[$u.Id])" }
    if ($Identification -in @('Naming','Both','Heuristic') -and
        "$($u.DisplayName) $($u.UserPrincipalName)" -match $NamePattern) { $how += 'Naming pattern' }
    if ($Identification -eq 'Heuristic' -and $how.Count -eq 0) {
        $sa = $u.SignInActivity
        if ($sa -and -not $sa.LastSignInDateTime -and $sa.LastNonInteractiveSignInDateTime) {
            $how += 'Heuristic: non-interactive only - REVIEW'
        }
    }
    if ($how.Count -eq 0) { continue }

    $sa = $u.SignInActivity
    $candidates.Add([PSCustomObject]@{
        ObjectId       = $u.Id
        DisplayName    = $u.DisplayName
        Identifier     = $u.UserPrincipalName
        IdentityType   = 'User'
        Enabled        = if ($u.AccountEnabled) { 'Yes' } else { 'No' }
        LastSignIn     = if ($sa -and $sa.LastNonInteractiveSignInDateTime) { ([datetime]$sa.LastNonInteractiveSignInDateTime).ToString('dd/MM/yyyy') }
                         elseif ($sa -and $sa.LastSignInDateTime) { ([datetime]$sa.LastSignInDateTime).ToString('dd/MM/yyyy') }
                         else { '' }
        IdentifiedBy   = ($how -join ' + ')
    })
}

# --- workload identities, if asked for ---
if ($IncludeWorkloadIdentities) {
    Write-Verbose "  Including service principals and managed identities"
    foreach ($sp in (Get-MgServicePrincipal -All -PageSize 999 -Property Id,AppId,DisplayName,ServicePrincipalType,AccountEnabled)) {
        $type = if ($sp.ServicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
        $candidates.Add([PSCustomObject]@{
            ObjectId     = $sp.Id
            DisplayName  = $sp.DisplayName
            Identifier   = $sp.AppId
            IdentityType = $type
            Enabled      = if ($sp.AccountEnabled) { 'Yes' } else { 'No' }
            LastSignIn   = ''
            IdentifiedBy = "Workload identity ($type)"
        })
    }
}

Write-Host "  $($candidates.Count) service account candidate(s)"

# ==========================================================================
# STEP 3 - Join and export
# ==========================================================================
$rows = foreach ($c in $candidates) {
    $e = $excluded[$c.ObjectId]
    [PSCustomObject][ordered]@{
        'Display Name'        = $c.DisplayName
        'UPN / App ID'        = $c.Identifier
        'Object ID'           = $c.ObjectId
        'Identity Type'       = $c.IdentityType
        'Enabled'             = $c.Enabled
        'Last Sign-In'        = $c.LastSignIn
        'CA Excluded'         = if ($e) { 'YES' } else { 'No' }
        'Exclusion Mechanism' = if ($e) { (($e.Mechanisms | Sort-Object -Unique) -join ' + ') } else { '' }
        'Exclusion Groups'    = if ($e) { (($e.Groups   | Sort-Object -Unique) -join '; ') } else { '' }
        'Excluded Policies'   = if ($e) { (($e.Policies | Sort-Object -Unique) -join '; ') } else { '' }
        'Policy Count'        = if ($e) { ($e.Policies | Sort-Object -Unique).Count } else { 0 }
        'Identified By'       = $c.IdentifiedBy
        'Snapshot Date'       = (Get-Date -Format 'dd/MM/yyyy')
    }
}

$rows | Sort-Object @{E={$_.'CA Excluded'};Descending=$true}, 'Identity Type', 'Display Name' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# ==========================================================================
# Summary
# ==========================================================================
$ex = @($rows | Where-Object { $_.'CA Excluded' -eq 'YES' })
Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  Service accounts        : $($rows.Count)"
Write-Host "  Excluded from CA        : $($ex.Count)" -ForegroundColor $(if ($ex.Count) { 'Yellow' } else { 'Green' })
Write-Host "  Not excluded            : $($rows.Count - $ex.Count)"
Write-Host ""
$rows | Group-Object 'Identity Type' | ForEach-Object { Write-Host ("    {0,-18} {1}" -f $_.Name, $_.Count) }

$direct = @($ex | Where-Object { $_.'Exclusion Mechanism' -like '*Direct*' })
if ($direct.Count) {
    Write-Host "`n  $($direct.Count) excluded directly rather than via a group - these bypass group-based review." -ForegroundColor Yellow
}
$review = @($rows | Where-Object { $_.'Identified By' -like '*REVIEW*' })
if ($review.Count) {
    Write-Host "  $($review.Count) identified heuristically - verify before publishing the list." -ForegroundColor Yellow
}
$disabledExcluded = @($ex | Where-Object { $_.Enabled -eq 'No' })
if ($disabledExcluded.Count) {
    Write-Host "  $($disabledExcluded.Count) disabled account(s) still sitting in an exclusion group - easy cleanup." -ForegroundColor Yellow
}

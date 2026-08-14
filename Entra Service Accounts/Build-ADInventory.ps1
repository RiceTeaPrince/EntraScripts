<#
.SYNOPSIS
    Collects on-premises Active Directory accounts, privileged group membership and
    service-account signals for the Entra ID Service Identity Inventory workbook.

.DESCRIPTION
    Produces one CSV for the "AD Accounts" tab, joined to the Entra Accounts tab on
    the account SID.

    Collects:
      - User accounts, group managed service accounts (gMSA) and legacy managed
        service accounts (sMSA)
      - Membership of well-known privileged groups, resolved by RID so it works on
        non-English domains and includes nested membership
      - Service principal names, which mark Kerberos service accounts and are also
        the Kerberoasting surface
      - Delegation configuration, adminCount, password age and expiry settings

    Deliberately NOT collected: delegated permissions expressed as ACLs on OUs and
    objects. That analysis needs a purpose-built tool - PingCastle or BloodHound -
    and a partial reimplementation here would give false assurance. Run one of those
    alongside this inventory rather than instead of it.

    READ-ONLY.

.PARAMETER OutputPath
    CSV path. Defaults to .\AD-Accounts.csv

.PARAMETER SearchBase
    Restrict collection to one OU, e.g. 'OU=Service Accounts,DC=contoso,DC=com,DC=au'.
    Omit to search the whole domain.

.PARAMETER Server
    Domain controller to query. Defaults to the nearest.

.PARAMETER IncludeComputers
    Also collect computer accounts. Off by default - large and rarely relevant to a
    service account inventory, though computer accounts with SPNs matter for
    delegation review.

.PARAMETER ExcludeDisabled
    Omit disabled accounts. Disabled accounts are included by default: a disabled
    but still-present service account is itself a finding.

.EXAMPLE
    .\Build-ADInventory.ps1 -Verbose

.EXAMPLE
    .\Build-ADInventory.ps1 -SearchBase 'OU=Service Accounts,DC=contoso,DC=com,DC=au'

.NOTES
    Requires the ActiveDirectory module (RSAT) and must run on a domain-joined
    machine, or one with a domain trust path. This is a different execution context
    to the Graph scripts, which run from anywhere.

    Needs only standard authenticated-user read access in most domains. No elevation
    required for the properties collected here.

    LastLogonDate derives from lastLogonTimestamp, which replicates lazily - it can
    be up to 14 days behind reality by design. Treat it as "roughly when", not
    "exactly when", and never conclude an account is dormant from a single reading
    close to the threshold.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\AD-Accounts.csv",
    [string]$SearchBase,
    [string]$Server,
    [switch]$IncludeComputers,
    [switch]$ExcludeDisabled
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not available. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
}
Import-Module ActiveDirectory -ErrorAction Stop

$common = @{}
if ($Server)     { $common.Server = $Server }
if ($SearchBase) { $common.SearchBase = $SearchBase }

# Server only - for cmdlets/parameter sets that reject -SearchBase (anything using -Identity)
$serverOnly = @{}
if ($Server) { $serverOnly.Server = $Server }

$domain = Get-ADDomain @serverOnly
$domainSid = $domain.DomainSID.Value
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan
if ($SearchBase) { Write-Host "  scoped to $SearchBase" }

# --------------------------------------------------------------------------
# Privileged groups, resolved by RID so this works on non-English domains
# --------------------------------------------------------------------------
$PrivilegedRids = @{
    512 = 'Domain Admins'; 519 = 'Enterprise Admins'; 518 = 'Schema Admins'
    520 = 'Group Policy Creator Owners'; 517 = 'Cert Publishers'
    526 = 'Key Admins'; 527 = 'Enterprise Key Admins'
}
$BuiltinRids = @{
    544 = 'Administrators'; 548 = 'Account Operators'; 549 = 'Server Operators'
    550 = 'Print Operators'; 551 = 'Backup Operators'
}

Write-Host "`nResolving privileged group membership..." -ForegroundColor Cyan
$privMembers = @{}   # SID -> list of group names

function Add-PrivMember($memberSid, $groupName) {
    if (-not $privMembers.ContainsKey($memberSid)) { $privMembers[$memberSid] = @() }
    $privMembers[$memberSid] += $groupName
}

# Note: privileged group resolution is deliberately domain-wide, never limited by
# -SearchBase. An account inside the scoped OU can be a member of a group outside it.
$privGroups = [System.Collections.Generic.List[object]]::new()
foreach ($rid in $PrivilegedRids.Keys) {
    try { $privGroups.Add((Get-ADGroup -Identity "$domainSid-$rid" @serverOnly -ErrorAction Stop)) } catch { }
}
foreach ($rid in ($BuiltinRids.Keys | Where-Object { $_ -gt 0 })) {
    try { $privGroups.Add((Get-ADGroup -Identity "S-1-5-32-$rid" @serverOnly -ErrorAction Stop)) } catch { }
}
# Name-based, since these have no fixed RID
foreach ($n in @('DnsAdmins','DHCP Administrators','Exchange Organization Management')) {
    try { $g = Get-ADGroup -Filter "Name -eq '$n'" @serverOnly -ErrorAction Stop; if ($g) { $privGroups.Add($g) } } catch { }
}

foreach ($g in $privGroups) {
    try {
        # -Recursive resolves nested groups, which is where surprise privilege lives
        foreach ($m in (Get-ADGroupMember -Identity $g.DistinguishedName -Recursive @serverOnly -ErrorAction Stop)) {
            Add-PrivMember $m.SID.Value $g.Name
        }
        Write-Verbose "  $($g.Name)"
    } catch {
        Write-Warning "Could not enumerate '$($g.Name)': $($_.Exception.Message)"
    }
}
Write-Host "  $($privGroups.Count) privileged group(s), $($privMembers.Keys.Count) distinct member(s)"

# --------------------------------------------------------------------------
# Collect accounts
# --------------------------------------------------------------------------
$props = @('SamAccountName','DisplayName','DistinguishedName','SID','ObjectGUID','Enabled',
           'whenCreated','LastLogonDate','PasswordLastSet','PasswordNeverExpires',
           'PasswordNotRequired','ServicePrincipalName','adminCount','Description',
           'TrustedForDelegation','TrustedToAuthForDelegation','msDS-AllowedToDelegateTo',
           'MemberOf','UserAccountControl','msDS-SupportedEncryptionTypes')

Write-Host "`nCollecting accounts..." -ForegroundColor Cyan
# Each entry is a small wrapper: the untouched AD object plus the kind we inferred
# from which cmdlet returned it. Nothing is added to the AD objects themselves.
$accounts = [System.Collections.Generic.List[object]]::new()

Get-ADUser -Filter * -Properties $props @common | ForEach-Object {
    $accounts.Add([PSCustomObject]@{ Kind = 'User'; Obj = $_ })
}
Write-Host "  $($accounts.Count) user account(s)"

# Managed service accounts - the good pattern, worth counting separately
$msaCount = 0
try {
    Get-ADServiceAccount -Filter * -Properties $props @common | ForEach-Object {
        $kind = if ($_.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
        $accounts.Add([PSCustomObject]@{ Kind = $kind; Obj = $_ }); $msaCount++
    }
} catch { Write-Verbose "No managed service accounts found or not readable: $($_.Exception.Message)" }
Write-Host "  $msaCount managed service account(s)"

if ($IncludeComputers) {
    $before = $accounts.Count
    Get-ADComputer -Filter * -Properties $props @common | ForEach-Object {
        $accounts.Add([PSCustomObject]@{ Kind = 'Computer'; Obj = $_ })
    }
    Write-Host "  $($accounts.Count - $before) computer account(s)"
}

if ($ExcludeDisabled) { $accounts = @($accounts | Where-Object { $_.Obj.Enabled }) }

# Guard against the same object arriving twice - can happen when -Server points at a
# global catalog, or when collection scopes overlap. Keyed on GUID, which is unique
# and immutable.
$dupes = ($accounts | Group-Object { $_.Obj.ObjectGUID } | Where-Object Count -gt 1)
if ($dupes) {
    Write-Warning "$($dupes.Count) account(s) returned more than once - de-duplicating on ObjectGUID."
    $accounts = @($accounts | Group-Object { $_.Obj.ObjectGUID } | ForEach-Object { $_.Group[0] })
}

# --------------------------------------------------------------------------
# Shape
# --------------------------------------------------------------------------
$now = Get-Date

function Get-DelegationType($a) {
    $flags = @()
    if ($a.TrustedForDelegation)           { $flags += 'Unconstrained' }
    if ($a.TrustedToAuthForDelegation)     { $flags += 'Constrained w/ protocol transition' }
    elseif ($a.'msDS-AllowedToDelegateTo') { $flags += 'Constrained' }
    if ($flags.Count -eq 0) { return 'None' }
    return ($flags -join '; ')
}

function Get-OU($dn) {
    if ($dn -match '^CN=[^,]+,(.+)$') { return $Matches[1] }
    return ''
}

$rows = foreach ($entry in $accounts) {
    $a       = $entry.Obj
    $spns    = @($a.ServicePrincipalName)
    $privOf  = if ($privMembers.ContainsKey($a.SID.Value)) { ($privMembers[$a.SID.Value] | Sort-Object -Unique) -join '; ' } else { '' }
    $pwAge   = if ($a.PasswordLastSet) { [int]($now - $a.PasswordLastSet).TotalDays } else { $null }

    [PSCustomObject][ordered]@{
        'SamAccountName'        = $a.SamAccountName
        'Display Name'          = $a.DisplayName
        'Distinguished Name'    = $a.DistinguishedName
        'SID'                   = $a.SID.Value
        'Object GUID'           = $a.ObjectGUID
        'Account Type'          = $entry.Kind
        'Enabled'               = if ($a.Enabled) { 'Yes' } else { 'No' }
        'Created'               = if ($a.whenCreated) { $a.whenCreated.ToString('dd/MM/yyyy') } else { '' }
        'Last Logon'            = if ($a.LastLogonDate) { $a.LastLogonDate.ToString('dd/MM/yyyy') } else { '' }
        'Password Last Set'     = if ($a.PasswordLastSet) { $a.PasswordLastSet.ToString('dd/MM/yyyy') } else { '' }
        'Password Never Expires'= if ($a.PasswordNeverExpires) { 'Yes' } else { 'No' }
        'Password Age (days)'   = $pwAge
        'SPN Count'             = $spns.Count
        'Service Principal Names' = ($spns -join '; ')
        'AdminCount'            = if ($a.adminCount -eq 1) { '1' } else { '' }
        'Privileged Groups'     = $privOf
        'Total Group Count'     = @($a.MemberOf).Count
        'Delegation'            = Get-DelegationType $a
        'OU'                    = Get-OU $a.DistinguishedName
        'Description'           = $a.Description
    }
}

$rows | Sort-Object @{E={[bool]$_.'Privileged Groups'};Descending=$true}, @{E={$_.'SPN Count'};Descending=$true}, 'SamAccountName' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$withSpn      = @($rows | Where-Object { [int]$_.'SPN Count' -gt 0 -and $_.'Account Type' -eq 'User' })
$priv         = @($rows | Where-Object { $_.'Privileged Groups' })
$neverExpires = @($rows | Where-Object { $_.'Password Never Expires' -eq 'Yes' -and $_.Enabled -eq 'Yes' })
$stalePw      = @($rows | Where-Object { $_.'Password Age (days)' -and [int]$_.'Password Age (days)' -gt 365 -and $_.Enabled -eq 'Yes' })
$unconstrained= @($rows | Where-Object { $_.Delegation -like 'Unconstrained*' })
$staleAdmin   = @($rows | Where-Object { $_.AdminCount -eq '1' -and -not $_.'Privileged Groups' })
$gmsa         = @($rows | Where-Object { $_.'Account Type' -eq 'gMSA' })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  Accounts collected            : $($rows.Count)"
Write-Host ""
Write-Host "  Kerberos service accounts (user objects with an SPN) : $($withSpn.Count)" -ForegroundColor Yellow
Write-Host "    These are your classic on-prem service accounts, and also the"
Write-Host "    Kerberoasting surface. Long random passwords or gMSA are the fix."
Write-Host "  Group managed service accounts (gMSA)                : $($gmsa.Count)"
Write-Host "    The ratio of gMSA to SPN-bearing user accounts is a fair measure"
Write-Host "    of how far the service account estate has been modernised."
Write-Host ""
Write-Host "  In a privileged group                                : $($priv.Count)" -ForegroundColor Yellow
Write-Host "  Enabled with PasswordNeverExpires                    : $($neverExpires.Count)" -ForegroundColor Yellow
Write-Host "  Enabled with password older than a year              : $($stalePw.Count)" -ForegroundColor Yellow
if ($unconstrained.Count) {
    Write-Host "  Unconstrained delegation                             : $($unconstrained.Count)" -ForegroundColor Red
    Write-Host "    Serious. Any of these compromised yields domain-wide impersonation."
}
if ($staleAdmin.Count) {
    Write-Host "  Stale adminCount=1 (no current privileged group)     : $($staleAdmin.Count)"
    Write-Host "    Previously privileged. The flag persists and blocks inheritance."
}
Write-Host ""
Write-Host "Next: paste into the 'AD Accounts' tab at cell A2 (columns A-T)." -ForegroundColor Cyan
Write-Host "For delegated ACL analysis - the permissions this script does NOT cover -" -ForegroundColor Cyan
Write-Host "run PingCastle or BloodHound alongside this inventory." -ForegroundColor Cyan

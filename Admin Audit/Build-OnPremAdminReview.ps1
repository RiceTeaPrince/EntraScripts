<#
.SYNOPSIS
    Collects privileged access held by on-premises administrator accounts (username-a)
    for the Privileged Access Review workbook.

.DESCRIPTION
    Finds AD accounts matching the on-prem admin naming convention and collects every
    privileged group they belong to, resolved recursively so nested membership counts.
    Also collects the credential posture of each admin account and links it back to
    the person's standard AD account, so a leaver whose standard account is disabled
    while the admin account stays live becomes visible.

    Groups are tiered. Tier 0 means control-plane: membership permits full domain
    compromise, directly or by a well-known escalation path. The tiering is defined
    in $GroupTiers below and is intended to be edited to match your own model.

    READ-ONLY.

.PARAMETER AdminPattern
    Regex identifying admin accounts by SamAccountName. Default matches username-a.

.PARAMETER BaseUsernameCapture
    Regex with one capture group extracting the base username. Default strips '-a'.

.PARAMETER SearchBase
    Restrict collection to one OU. Omit to search the whole domain.

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -Verbose

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -SearchBase 'OU=Admin Accounts,DC=corp,DC=com,DC=au'

.NOTES
    Requires the ActiveDirectory module (RSAT) and a domain-joined machine.
    Standard authenticated-user read access is sufficient for these properties.

    LastLogonDate derives from lastLogonTimestamp, which replicates lazily and can
    sit up to 14 days behind. Treat it as approximate.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\OnPrem-Admins.csv",
    [string]$AdminPattern = '-a$',
    [string]$BaseUsernameCapture = '^(.+)-a$',
    [string]$SearchBase,
    [string]$Server
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module not available. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
}
Import-Module ActiveDirectory -ErrorAction Stop

$common = @{}
if ($Server)     { $common.Server = $Server }
if ($SearchBase) { $common.SearchBase = $SearchBase }

$domain = if ($Server) { Get-ADDomain -Server $Server } else { Get-ADDomain }
$domainSid = $domain.DomainSID.Value
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan

# ==========================================================================
# Group tiering. Tier 0 = full domain compromise, directly or via a
# well-known escalation path. Edit to match your model.
# ==========================================================================
$GroupTiers = @{
    'Domain Admins' = 0; 'Enterprise Admins' = 0; 'Schema Admins' = 0
    'Administrators' = 0; 'Account Operators' = 0; 'Backup Operators' = 0
    'Server Operators' = 0; 'Print Operators' = 0
    # DnsAdmins is Tier 0 by escalation: members can load a DLL into a service
    # running as SYSTEM on a domain controller.
    'DnsAdmins' = 0
    'Key Admins' = 0; 'Enterprise Key Admins' = 0
    'Group Policy Creator Owners' = 1; 'Cert Publishers' = 1
    'DHCP Administrators' = 1; 'Organization Management' = 1
    'Remote Desktop Users' = 2; 'Distributed COM Users' = 2
}
function Get-GroupTier([string]$g) {
    if ($GroupTiers.ContainsKey($g)) { return $GroupTiers[$g] }
    if ($g -match 'Admin')  { return 1 }
    return 2
}

# --------------------------------------------------------------------------
# Privileged groups, resolved by RID where possible so this survives
# non-English domains and renamed groups.
# --------------------------------------------------------------------------
Write-Host "Resolving privileged group membership..." -ForegroundColor Cyan
$domainRids  = @(512,518,519,520,517,526,527)
$builtinRids = @(544,548,549,550,551)
$privGroups  = [System.Collections.Generic.List[object]]::new()

foreach ($rid in $domainRids)  { try { $privGroups.Add((Get-ADGroup -Identity "$domainSid-$rid" -ErrorAction Stop)) } catch { } }
foreach ($rid in $builtinRids) { try { $privGroups.Add((Get-ADGroup -Identity "S-1-5-32-$rid" -ErrorAction Stop)) } catch { } }
foreach ($n in ($GroupTiers.Keys | Where-Object { $GroupTiers[$_] -le 1 })) {
    try {
        $g = Get-ADGroup -Filter "Name -eq '$n'" -ErrorAction Stop
        if ($g -and -not ($privGroups | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) { $privGroups.Add($g) }
    } catch { }
}

$memberOf = @{}
foreach ($g in $privGroups) {
    try {
        foreach ($m in (Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction Stop)) {
            if (-not $memberOf.ContainsKey($m.SID.Value)) { $memberOf[$m.SID.Value] = @() }
            $memberOf[$m.SID.Value] += $g.Name
        }
        Write-Verbose "  $($g.Name)"
    } catch { Write-Warning "Could not enumerate '$($g.Name)': $($_.Exception.Message)" }
}
Write-Host "  $($privGroups.Count) privileged group(s), $($memberOf.Keys.Count) distinct member(s)"

# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------
$props = @('SamAccountName','DisplayName','DistinguishedName','SID','Enabled','whenCreated',
           'LastLogonDate','PasswordLastSet','PasswordNeverExpires','adminCount','MemberOf',
           'Description','TrustedForDelegation','TrustedToAuthForDelegation','msDS-AllowedToDelegateTo',
           'SmartcardLogonRequired','Department','Title','Manager')

Write-Host "Collecting accounts..." -ForegroundColor Cyan
$all = Get-ADUser -Filter * -Properties $props @common
$admins = @($all | Where-Object { $_.SamAccountName -match $AdminPattern })
Write-Host "  $($all.Count) account(s), $($admins.Count) matching the on-prem admin convention" -ForegroundColor Cyan
if ($admins.Count -eq 0) {
    Write-Warning "No accounts matched '$AdminPattern'. Check the pattern before assuming there are none."
}

$standardBySam = @{}
foreach ($u in $all) {
    if ($u.SamAccountName -match $AdminPattern) { continue }
    $standardBySam[$u.SamAccountName.ToLower()] = $u
}

function Get-Delegation($a) {
    if ($a.TrustedForDelegation)           { return 'Unconstrained' }
    if ($a.TrustedToAuthForDelegation)     { return 'Constrained w/ protocol transition' }
    if ($a.'msDS-AllowedToDelegateTo')     { return 'Constrained' }
    return 'None'
}

$now = Get-Date
$rows = foreach ($a in $admins) {

    $base = if ($a.SamAccountName -match $BaseUsernameCapture) { $Matches[1].ToLower() } else { $a.SamAccountName.ToLower() }
    $std  = $standardBySam[$base]

    $groups = @(if ($memberOf.ContainsKey($a.SID.Value)) { $memberOf[$a.SID.Value] | Sort-Object -Unique })
    $highest = if ($groups.Count) {
        @($groups | Sort-Object @{ E = { Get-GroupTier $_ } }, @{ E = { $_ } })[0]
    } else { 'None' }
    $tier = if ($groups.Count) { ($groups | ForEach-Object { Get-GroupTier $_ } | Measure-Object -Minimum).Minimum } else { '' }
    $pwAge = if ($a.PasswordLastSet) { [int]($now - $a.PasswordLastSet).TotalDays } else { $null }

    [PSCustomObject][ordered]@{
        'SamAccountName'         = $a.SamAccountName
        'Display Name'           = $a.DisplayName
        'Distinguished Name'     = $a.DistinguishedName
        'SID'                    = $a.SID.Value
        'Base Username'          = $base
        'Enabled'                = if ($a.Enabled) { 'Yes' } else { 'No' }
        'Created'                = if ($a.whenCreated) { $a.whenCreated.ToString('dd/MM/yyyy') } else { '' }
        'Last Logon'             = if ($a.LastLogonDate) { $a.LastLogonDate.ToString('dd/MM/yyyy') } else { '' }
        'Password Last Set'      = if ($a.PasswordLastSet) { $a.PasswordLastSet.ToString('dd/MM/yyyy') } else { '' }
        'Password Age (days)'    = $pwAge
        'Password Never Expires' = if ($a.PasswordNeverExpires) { 'Yes' } else { 'No' }
        'Smartcard Required'     = if ($a.SmartcardLogonRequired) { 'Yes' } else { 'No' }
        'Privileged Groups'      = if ($groups.Count) { $groups -join '; ' } else { 'None' }
        'Privileged Group Count' = $groups.Count
        'Highest AD Group'       = $highest
        'AD Tier'                = $tier
        'AdminCount'             = if ($a.adminCount -eq 1) { '1' } else { '' }
        'Total Group Count'      = @($a.MemberOf).Count
        'Delegation'             = Get-Delegation $a
        'Standard Account'       = if ($std) { $std.SamAccountName } else { '' }
        'Standard Acct Enabled'  = if ($std) { if ($std.Enabled) { 'Yes' } else { 'No' } } else { 'NOT FOUND' }
        'Person Display Name'    = if ($std) { $std.DisplayName } else { $a.DisplayName }
        'Department'             = if ($std) { $std.Department } else { $a.Department }
        'Job Title'              = if ($std) { $std.Title } else { $a.Title }
    }
}

$rows | Sort-Object 'AD Tier', @{E={$_.'Privileged Group Count'};Descending=$true}, 'SamAccountName' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$t0       = @($rows | Where-Object { $_.'AD Tier' -eq 0 })
$noPriv   = @($rows | Where-Object { $_.'Privileged Groups' -eq 'None' })
$orphaned = @($rows | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })
$stalePw  = @($rows | Where-Object { $_.'Password Age (days)' -and [int]$_.'Password Age (days)' -gt 365 -and $_.Enabled -eq 'Yes' })
$noSc     = @($rows | Where-Object { $_.'Smartcard Required' -eq 'No' -and $_.'AD Tier' -eq 0 -and $_.Enabled -eq 'Yes' })
$deleg    = @($rows | Where-Object { $_.Delegation -ne 'None' })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  On-prem admin accounts               : $($rows.Count)"
Write-Host "  Tier 0 (domain compromise capable)   : $($t0.Count)" -ForegroundColor Yellow
Write-Host "  Password older than a year (enabled) : $($stalePw.Count)" -ForegroundColor Yellow
if ($noSc.Count)     { Write-Host "  Tier 0 without smartcard required    : $($noSc.Count)" -ForegroundColor Yellow }
if ($orphaned.Count) {
    Write-Host "  ORPHANED - admin enabled, standard account disabled or missing : $($orphaned.Count)" -ForegroundColor Red
    Write-Host "    Likely leavers. Admin accounts are separate objects and are routinely missed at offboarding."
}
if ($deleg.Count)  { Write-Host "  Configured for delegation            : $($deleg.Count)" -ForegroundColor Red }
if ($noPriv.Count) {
    Write-Host "  Admin-named but in NO privileged group : $($noPriv.Count)"
    Write-Host "    Either the privilege was removed and the account was not, or it is granted by a route this script does not see (delegated ACLs)."
}
Write-Host "`nNext: paste into the 'On-Prem Admins' tab at cell A2 (columns A-X)." -ForegroundColor Cyan

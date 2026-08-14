<#
.SYNOPSIS
    Collects Active Directory groups for the 'Groups' tab of the Entra ID Service
    Identity Inventory workbook.

.DESCRIPTION
    Exists to make the AD Delegation tab readable. Most access control entries name
    a group as trustee rather than an individual account - that is the entire point
    of delegation - so without a group inventory the delegation register cannot say
    who is actually behind a right, and every group trustee reads NOT IN INVENTORY.

    Collects group identity, category and scope, direct and recursive membership
    counts, and whether the group is privileged either directly or by nesting.

    Nesting is resolved with LDAP_MATCHING_RULE_IN_CHAIN rather than
    Get-ADGroupMember -Recursive, because -Recursive returns only leaf objects and
    silently omits the nested groups themselves. A group nested three levels inside
    Domain Admins is exactly the thing worth finding, and the obvious approach
    misses it.

    READ-ONLY.

.PARAMETER OutputPath
    CSV path. Defaults to .\AD-Groups.csv

.PARAMETER SearchBase
    Restrict collection to one OU subtree.

.PARAMETER Server
    Domain controller to query. Use a specific DC on port 389, not a global catalog.

.PARAMETER SkipRecursiveCount
    Skip the recursive membership count. That count is one LDAP query per group
    using a matching rule that is not well indexed, so on a domain with thousands
    of groups it dominates the runtime. Skipping leaves the 'Recursive Members'
    column blank; direct counts and privilege detection still work.

.PARAMETER PrivilegedOnly
    Collect only privileged groups and their nested members. Fast, and enough to
    make the delegation register readable for the rows that matter most.

.EXAMPLE
    .\Build-ADGroups.ps1 -Verbose

.EXAMPLE
    .\Build-ADGroups.ps1 -PrivilegedOnly

.EXAMPLE
    .\Build-ADGroups.ps1 -SkipRecursiveCount -OutputPath .\groups.csv

.NOTES
    Requires the ActiveDirectory module (RSAT) and a domain-joined machine or a
    trust path. Needs only standard authenticated-user read access.

    Paste into the 'Groups' tab at A2, columns A to O. Joins to the AD Delegation
    tab on SID.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\AD-Groups.csv",
    [string]$SearchBase,
    [string]$Server,
    [switch]$SkipRecursiveCount,
    [switch]$PrivilegedOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not available. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
}
Import-Module ActiveDirectory -ErrorAction Stop

# Same splatting convention as the other two scripts: $serverOnly for anything
# using -Identity, which is in a different parameter set to -SearchBase.
$common = @{}
if ($Server)     { $common.Server = $Server }
if ($SearchBase) { $common.SearchBase = $SearchBase }

$serverOnly = @{}
if ($Server) { $serverOnly.Server = $Server }

$domain    = Get-ADDomain @serverOnly
$domainSid = $domain.DomainSID.Value
Write-Host "Domain: $($domain.DNSRoot)" -ForegroundColor Cyan

# A distinguished name goes into an LDAP filter, so the filter metacharacters
# must be escaped. Backslash first, or it double-escapes the others.
function ConvertTo-LdapFilterValue($s) {
    $s = $s -replace '\\', '\5c'
    $s = $s -replace '\(',  '\28'
    $s = $s -replace '\)',  '\29'
    $s = $s -replace '\*',  '\2a'
    return $s
}

# --------------------------------------------------------------------------
# Privileged groups, by RID so this works on non-English domains
# --------------------------------------------------------------------------
Write-Host "`nIdentifying privileged groups..." -ForegroundColor Cyan
$privDns = [System.Collections.Generic.HashSet[string]]::new()

foreach ($rid in 512,519,518,520,517,526,527) {
    try { $privDns.Add((Get-ADGroup -Identity "$domainSid-$rid" @serverOnly -ErrorAction Stop).DistinguishedName) | Out-Null } catch { }
}
foreach ($rid in 544,548,549,550,551) {
    try { $privDns.Add((Get-ADGroup -Identity "S-1-5-32-$rid" @serverOnly -ErrorAction Stop).DistinguishedName) | Out-Null } catch { }
}
foreach ($n in @('DnsAdmins','DHCP Administrators','Exchange Organization Management')) {
    try {
        $g = Get-ADGroup -Filter "Name -eq '$n'" @serverOnly -ErrorAction Stop
        if ($g) { foreach ($x in @($g)) { $privDns.Add($x.DistinguishedName) | Out-Null } }
    } catch { }
}

# Groups NESTED inside a privileged group are privileged too. -Recursive would not
# find these: it returns leaf objects only and drops the intermediate groups.
$nestedPriv = [System.Collections.Generic.HashSet[string]]::new()
foreach ($dn in $privDns) {
    $esc = ConvertTo-LdapFilterValue $dn
    try {
        Get-ADGroup -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$esc)" @serverOnly -ErrorAction Stop |
            ForEach-Object { $nestedPriv.Add($_.DistinguishedName) | Out-Null }
    } catch { Write-Verbose "Nesting query failed for $dn : $($_.Exception.Message)" }
}
foreach ($dn in $nestedPriv) { $privDns.Add($dn) | Out-Null }
Write-Host "  $($privDns.Count) privileged group(s), including $($nestedPriv.Count) found only by nesting"

# --------------------------------------------------------------------------
# Collect groups
# --------------------------------------------------------------------------
Write-Host "`nCollecting groups..." -ForegroundColor Cyan
$props = @('SamAccountName','DisplayName','DistinguishedName','SID','ObjectGUID',
           'GroupCategory','GroupScope','member','adminCount','ManagedBy',
           'whenCreated','Description')

$groups = [System.Collections.Generic.List[object]]::new()
if ($PrivilegedOnly) {
    foreach ($dn in $privDns) {
        try { $groups.Add((Get-ADGroup -Identity $dn -Properties $props @serverOnly -ErrorAction Stop)) } catch { }
    }
} else {
    Get-ADGroup -Filter * -Properties $props @common | ForEach-Object { $groups.Add($_) }
}
Write-Host "  $($groups.Count) group(s)"

if (-not $SkipRecursiveCount -and $groups.Count -gt 500) {
    Write-Warning "$($groups.Count) groups and recursive counting is on. This is one LDAP query per group and will take a while. Ctrl-C and re-run with -SkipRecursiveCount if that is not what you want."
}

function Get-OU($dn) {
    if ($dn -match '^CN=[^,]+,(.+)$') { return $Matches[1] }
    return ''
}
function Get-Cn($dn) {
    if ($dn -match '^CN=([^,]+),') { return $Matches[1] }
    return $dn
}

$rows = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($g in $groups) {
    $i++
    if ($i % 100 -eq 0) { Write-Progress -Activity 'Counting membership' -Status "$i of $($groups.Count)" -PercentComplete (100*$i/$groups.Count) }

    $direct = @($g.member).Count

    $recursive = $null
    if (-not $SkipRecursiveCount) {
        $esc = ConvertTo-LdapFilterValue $g.DistinguishedName
        try {
            $recursive = @(Get-ADObject -LDAPFilter "(&(memberOf:1.2.840.113556.1.4.1941:=$esc)(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount)))" @serverOnly -ErrorAction Stop).Count
        } catch {
            Write-Verbose "Recursive count failed for $($g.SamAccountName): $($_.Exception.Message)"
        }
    }

    $rows.Add([PSCustomObject][ordered]@{
        'Group Name'          = $g.SamAccountName
        'Display Name'        = $g.DisplayName
        'Distinguished Name'  = $g.DistinguishedName
        'SID'                 = $g.SID.Value
        'Object GUID'         = $g.ObjectGUID
        'Group Category'      = $g.GroupCategory
        'Group Scope'         = $g.GroupScope
        'Direct Members'      = $direct
        'Recursive Members'   = $recursive
        'Privileged Group?'   = if ($privDns.Contains($g.DistinguishedName)) { 'Yes' } else { 'No' }
        'AdminCount'          = if ($g.adminCount -eq 1) { 1 } else { $null }
        'Managed By'          = if ($g.ManagedBy) { Get-Cn $g.ManagedBy } else { '' }
        'Created'             = if ($g.whenCreated) { $g.whenCreated.ToString('dd/MM/yyyy') } else { '' }
        'Description'         = $g.Description
        'OU'                  = Get-OU $g.DistinguishedName
    })
}
Write-Progress -Activity 'Counting membership' -Completed

$rows | Sort-Object @{E={$_.'Privileged Group?' -eq 'Yes'};Descending=$true},
                    @{E={[int]$_.'Direct Members'};Descending=$true}, 'Group Name' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$priv    = @($rows | Where-Object { $_.'Privileged Group?' -eq 'Yes' })
$empty   = @($rows | Where-Object { $_.'Direct Members' -eq 0 })
$large   = @($rows | Where-Object { $_.'Recursive Members' -ne $null -and [int]$_.'Recursive Members' -gt 100 })
$noOwner = @($rows | Where-Object { -not $_.'Managed By' })
$stale   = @($rows | Where-Object { $_.AdminCount -eq 1 -and $_.'Privileged Group?' -eq 'No' })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  Groups collected              : $($rows.Count)"
Write-Host ""
Write-Host "  Privileged, directly or by nesting                   : $($priv.Count)" -ForegroundColor Yellow
Write-Host "    Nested membership is where surprise privilege lives. A group three"
Write-Host "    levels inside Domain Admins confers the same rights as being in it."
Write-Host "  Empty groups                                         : $($empty.Count)"
Write-Host "    Harmless until someone delegates rights to one, then adds a member."
if ($large.Count) {
    Write-Host "  More than 100 effective members                      : $($large.Count)" -ForegroundColor Yellow
    Write-Host "    Check the delegation register before granting any of these a right;"
    Write-Host "    the blast radius is the recursive count, not the direct one."
}
Write-Host "  No ManagedBy set                                     : $($noOwner.Count)"
if ($stale.Count) {
    Write-Host "  Stale adminCount=1, not currently privileged         : $($stale.Count)"
    Write-Host "    Previously privileged. The flag persists and blocks inheritance."
}
Write-Host ""
Write-Host "Next: paste into the 'Groups' tab at A2 (columns A-O)." -ForegroundColor Cyan
Write-Host "Load this before drawing conclusions from the AD Delegation tab - without" -ForegroundColor Cyan
Write-Host "it, most trustees there read NOT IN INVENTORY." -ForegroundColor Cyan

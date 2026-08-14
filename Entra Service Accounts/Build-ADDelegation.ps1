<#
.SYNOPSIS
    Extracts non-default Active Directory access control entries - the delegated
    permissions that Build-ADInventory.ps1 deliberately does not cover.

.DESCRIPTION
    Reads the discretionary ACL of directory objects, resolves every ACE into
    readable form, and writes a delegation register as CSV.

    Resolves at runtime, from your own schema and configuration partitions:
      - Attribute and class GUIDs (so 'WriteProperty on bf9679c0-...' becomes
        'Write member')
      - Extended right GUIDs (so 'ExtendedRight on 00299570-...' becomes
        'Reset Password')

    Trustees are recorded by SID first and name second, so the output is correct
    on non-English domains and still readable when a trustee has been deleted.

    Interprets rights into capabilities an auditor or a ticket can act on: full
    control, modify permissions, take ownership, reset password, write group
    membership, write SPN, write key credentials, create child objects. Flags the
    DCSync pair (Replicating Directory Changes + ...All) by cross-referencing ACEs
    on the domain root, which no single-ACE view can catch.

    READ-ONLY.

    WHAT THIS DOES NOT DO
    This produces a register, not an attack graph. It tells you who holds which
    right on which object. It cannot tell you that account A can reset B, who is
    in a group with local admin on a server where C has a session, therefore A can
    reach Domain Admin in three hops. That transitive path analysis is what
    BloodHound exists for, and part of its input (sessions, local group membership
    on member servers) is not in the directory at all, so no LDAP-only script can
    reconstruct it. PingCastle likewise scores a domain against a maintained rule
    set that is worth more than anything hand-rolled.

    Use this for the inventory and the remediation backlog. Use those for the
    question "which of these actually gets someone to Domain Admin".

.PARAMETER OutputPath
    CSV path. Defaults to .\AD-Delegation.csv

.PARAMETER Scope
    Containers  - OUs, containers, the domain root and AdminSDHolder. Default.
                  This is where delegation is nearly always applied.
    Privileged  - privileged groups and adminCount=1 users. Catches rights granted
                  directly on sensitive objects rather than inherited from an OU.
    All         - every object in scope. Thorough and slow; expect hours and a
                  very large CSV on a domain of any size.

.PARAMETER SearchBase
    Restrict to one OU subtree.

.PARAMETER Server
    Domain controller to query. Use a specific DC on port 389, not a global catalog.

.PARAMETER IncludeInherited
    Report inherited ACEs as well. Off by default - an inherited ACE is a copy of
    one defined higher up, so reporting only the definition point keeps the
    register at a reviewable size. Turn this on to see effective rights per object.

.PARAMETER IncludeDefaultTrustees
    Include ACEs granted to SYSTEM, SELF, CREATOR OWNER, Domain Admins, Enterprise
    Admins, Administrators and Enterprise Domain Controllers. Off by default: these
    are present on nearly every object by design and drown the signal. Note that
    Account Operators, Server Operators, Print Operators, Backup Operators,
    Pre-Windows 2000 Compatible Access, Authenticated Users and Everyone are always
    reported - they are default in placement but meaningful in effect.

.PARAMETER IncludeReadRights
    Include read-only ACEs. Off by default; read access is rarely the finding.

.PARAMETER ExpandTrusteeGroups
    Recursively count members behind each group trustee, so 'Helpdesk has reset
    password on the Staff OU' becomes 'Helpdesk (47 effective principals) ...'.
    Adds a Get-ADGroupMember call per distinct group trustee.

.EXAMPLE
    .\Build-ADDelegation.ps1 -Verbose

.EXAMPLE
    .\Build-ADDelegation.ps1 -Scope Privileged -ExpandTrusteeGroups

.EXAMPLE
    .\Build-ADDelegation.ps1 -SearchBase 'OU=Corp,DC=contoso,DC=com,DC=au' -IncludeInherited

.NOTES
    Requires the ActiveDirectory module (RSAT) and a domain-joined machine or a
    trust path. Reading ACLs needs only READ_CONTROL, which authenticated users
    hold on most objects by default - no elevation required. Where the ACL cannot
    be read, the object is listed in the skipped count rather than silently dropped.

    Companion to Build-ADInventory.ps1. Join the two on the trustee SID: the
    inventory tells you what an account is, this tells you what it can do.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\AD-Delegation.csv",
    [ValidateSet('Containers','Privileged','All')]
    [string]$Scope = 'Containers',
    [string]$SearchBase,
    [string]$Server,
    [switch]$IncludeInherited,
    [switch]$IncludeDefaultTrustees,
    [switch]$IncludeReadRights,
    [switch]$ExpandTrusteeGroups
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory module is not available. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
}
Import-Module ActiveDirectory -ErrorAction Stop

# Same splatting convention as Build-ADInventory.ps1: $serverOnly for anything
# using -Identity, which is in a different parameter set to -SearchBase.
$common = @{}
if ($Server)     { $common.Server = $Server }
if ($SearchBase) { $common.SearchBase = $SearchBase }

$serverOnly = @{}
if ($Server) { $serverOnly.Server = $Server }

$domain    = Get-ADDomain @serverOnly
$domainSid = $domain.DomainSID.Value
$rootDSE   = Get-ADRootDSE @serverOnly
$schemaNC  = $rootDSE.schemaNamingContext
$configNC  = $rootDSE.configurationNamingContext

Write-Host "Domain: $($domain.DNSRoot)  (scope: $Scope)" -ForegroundColor Cyan

# The AD: provider drive points at the current domain. Bind a second drive when a
# specific DC is requested, otherwise ACLs come from whichever DC the drive found.
$adDrive = 'AD'
if ($Server) {
    if (-not (Get-PSDrive -Name 'ADTARGET' -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name 'ADTARGET' -PSProvider ActiveDirectory -Server $Server -Root '' -Scope Script | Out-Null
    }
    $adDrive = 'ADTARGET'
}

# --------------------------------------------------------------------------
# GUID maps, read from this forest's own schema and configuration partitions.
# Never hardcode these - they are stable in practice but the schema is the
# authoritative source, and custom attributes only exist here.
# --------------------------------------------------------------------------
Write-Host "`nBuilding schema GUID map..." -ForegroundColor Cyan
$guidMap = @{}
$guidMap[[Guid]::Empty] = '(all)'

Get-ADObject -SearchBase $schemaNC -LDAPFilter '(schemaIDGUID=*)' `
             -Properties lDAPDisplayName, schemaIDGUID @serverOnly |
    ForEach-Object {
        $g = [Guid]::new($_.schemaIDGUID)
        if (-not $guidMap.ContainsKey($g)) { $guidMap[$g] = $_.lDAPDisplayName }
    }

Get-ADObject -SearchBase "CN=Extended-Rights,$configNC" -LDAPFilter '(objectClass=controlAccessRight)' `
             -Properties displayName, rightsGuid @serverOnly |
    ForEach-Object {
        $g = [Guid]$_.rightsGuid
        if (-not $guidMap.ContainsKey($g)) { $guidMap[$g] = $_.displayName }
    }
Write-Host "  $($guidMap.Count) GUID(s) resolved"

function Resolve-Guid($g) {
    if ($null -eq $g) { return '(all)' }
    if ($guidMap.ContainsKey($g)) { return $guidMap[$g] }
    return $g.ToString()
}

# Attribute GUIDs looked up by name, so a schema difference cannot silently break
# risk classification the way a hardcoded GUID would.
function Get-AttrGuid($ldapName) {
    $hit = $guidMap.GetEnumerator() | Where-Object { $_.Value -eq $ldapName } | Select-Object -First 1
    if ($hit) { return $hit.Key }
    return $null
}
$G_member      = Get-AttrGuid 'member'
$G_keyCred     = Get-AttrGuid 'msDS-KeyCredentialLink'
$G_spn         = Get-AttrGuid 'servicePrincipalName'
$G_rbcd        = Get-AttrGuid 'msDS-AllowedToActOnBehalfOfOtherIdentity'
$G_gpLink      = Get-AttrGuid 'gPLink'
$G_scriptPath  = Get-AttrGuid 'scriptPath'
$G_userClass   = Get-AttrGuid 'user'
$G_compClass   = Get-AttrGuid 'computer'
$G_groupClass  = Get-AttrGuid 'group'

# Verified against the Microsoft AD schema reference. Only these four are fixed,
# because the DCSync pair must be detected even if displayName is unavailable.
$G_replGet     = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
$G_replGetAll  = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
$G_replFilt    = [Guid]'89e95b76-444d-4c62-991a-0facbeda640c'  # ...In-Filtered-Set
$G_forcePwd    = [Guid]'00299570-246d-11d0-a768-00aa006e0529'  # User-Force-Change-Password

# --------------------------------------------------------------------------
# Trustees suppressed by default - default by placement AND by effect
# --------------------------------------------------------------------------
$defaultTrustees = @(
    'S-1-5-18'                  # SYSTEM
    'S-1-5-10'                  # SELF
    'S-1-3-0'                   # CREATOR OWNER
    'S-1-5-9'                   # ENTERPRISE DOMAIN CONTROLLERS
    'S-1-5-32-544'              # Administrators
    "$domainSid-512"            # Domain Admins
    "$domainSid-519"            # Enterprise Admins
    "$domainSid-518"            # Schema Admins
    "$domainSid-516"            # Domain Controllers
)

# --------------------------------------------------------------------------
# Target objects
# --------------------------------------------------------------------------
Write-Host "`nEnumerating target objects..." -ForegroundColor Cyan
$targets = [System.Collections.Generic.List[object]]::new()

switch ($Scope) {
    'Containers' {
        Get-ADObject -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS))' `
                     -Properties objectClass, name @common | ForEach-Object { $targets.Add($_) }
    }
    'Privileged' {
        $ridList = 512,519,518,520,517,526,527
        foreach ($rid in $ridList) {
            try { $targets.Add((Get-ADObject -Identity "$domainSid-$rid" -Properties objectClass,name @serverOnly)) } catch { }
        }
        foreach ($rid in 544,548,549,550,551) {
            try { $targets.Add((Get-ADObject -Identity "S-1-5-32-$rid" -Properties objectClass,name @serverOnly)) } catch { }
        }
        Get-ADObject -LDAPFilter '(adminCount=1)' -Properties objectClass, name @common |
            ForEach-Object { $targets.Add($_) }
    }
    'All' {
        Write-Warning "Scope 'All' reads the ACL of every object. This is slow. Ctrl-C now if unintended."
        Get-ADObject -LDAPFilter '(objectClass=*)' -Properties objectClass, name @common |
            ForEach-Object { $targets.Add($_) }
    }
}

# AdminSDHolder is a classic persistence point and sits outside the usual scopes
if ($Scope -ne 'All' -and -not $SearchBase) {
    try {
        $targets.Add((Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)" `
                                   -Properties objectClass, name @serverOnly))
    } catch { Write-Verbose "AdminSDHolder not readable: $($_.Exception.Message)" }
}

$targets = @($targets | Group-Object DistinguishedName | ForEach-Object { $_.Group[0] })
Write-Host "  $($targets.Count) object(s) to examine"

# --------------------------------------------------------------------------
# Rights interpretation
# --------------------------------------------------------------------------
$ADR = [System.DirectoryServices.ActiveDirectoryRights]

function Test-ReadOnlyAce($rights) {
    $writeish = @('CreateChild','DeleteChild','Self','WriteProperty','DeleteTree','Delete',
                  'GenericWrite','WriteDacl','WriteOwner','GenericAll','ExtendedRight')
    foreach ($w in $writeish) { if ($rights.HasFlag($ADR::$w)) { return $false } }
    return $true
}

function Get-Capability {
    param($ace)

    $r        = $ace.ActiveDirectoryRights
    $objType  = $ace.ObjectType
    $caps     = [System.Collections.Generic.List[string]]::new()
    $risk     = 'Low'

    if ($r.HasFlag($ADR::GenericAll)) {
        # Full control - no point decomposing, it implies everything below
        return [PSCustomObject]@{ Capability = 'Full control over the object'; Risk = 'High' }
    }

    if ($r.HasFlag($ADR::WriteDacl)) {
        $caps.Add('Modify permissions (can grant itself full control)'); $risk = 'High'
    }
    if ($r.HasFlag($ADR::WriteOwner)) {
        $caps.Add('Take ownership (owner can rewrite the ACL)'); $risk = 'High'
    }
    if ($r.HasFlag($ADR::GenericWrite)) {
        $caps.Add('Write all properties'); $risk = 'High'
    }

    if ($r.HasFlag($ADR::ExtendedRight)) {
        if ($objType -eq [Guid]::Empty) {
            $caps.Add('All extended rights (includes password reset)'); $risk = 'High'
        }
        elseif ($objType -eq $G_forcePwd) {
            $caps.Add('Reset password')
            if ($risk -eq 'Low') { $risk = 'Medium' }
        }
        elseif ($objType -eq $G_replGet -or $objType -eq $G_replGetAll -or $objType -eq $G_replFilt) {
            $caps.Add("Directory replication: $(Resolve-Guid $objType)")
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
        else {
            $caps.Add("Extended right: $(Resolve-Guid $objType)")
        }
    }

    if ($r.HasFlag($ADR::WriteProperty) -or $r.HasFlag($ADR::Self)) {
        $verb = if ($r.HasFlag($ADR::Self) -and -not $r.HasFlag($ADR::WriteProperty)) { 'Validated write' } else { 'Write' }
        if ($objType -eq [Guid]::Empty) {
            $caps.Add("$verb to all properties"); $risk = 'High'
        }
        elseif ($null -ne $G_member -and $objType -eq $G_member) {
            $caps.Add('Write group membership (can add itself to the group)')
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
        elseif ($null -ne $G_keyCred -and $objType -eq $G_keyCred) {
            $caps.Add('Write key credentials (shadow-credential takeover)'); $risk = 'High'
        }
        elseif ($null -ne $G_rbcd -and $objType -eq $G_rbcd) {
            $caps.Add('Write resource-based constrained delegation'); $risk = 'High'
        }
        elseif ($null -ne $G_spn -and $objType -eq $G_spn) {
            $caps.Add('Write SPN (enables targeted Kerberoasting)')
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
        elseif ($null -ne $G_gpLink -and $objType -eq $G_gpLink) {
            $caps.Add('Link Group Policy to this container')
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
        elseif ($null -ne $G_scriptPath -and $objType -eq $G_scriptPath) {
            $caps.Add('Write logon script path')
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
        else {
            $caps.Add("$verb $(Resolve-Guid $objType)")
        }
    }

    if ($r.HasFlag($ADR::CreateChild)) {
        $what = if ($objType -eq [Guid]::Empty) { 'any object' } else { Resolve-Guid $objType }
        $caps.Add("Create $what")
        if (($null -ne $G_compClass  -and $objType -eq $G_compClass) -or
            ($null -ne $G_userClass  -and $objType -eq $G_userClass) -or
            ($null -ne $G_groupClass -and $objType -eq $G_groupClass) -or
             $objType -eq [Guid]::Empty) {
            if ($risk -ne 'High') { $risk = 'Medium' }
        }
    }
    if ($r.HasFlag($ADR::DeleteChild) -or $r.HasFlag($ADR::DeleteTree) -or $r.HasFlag($ADR::Delete)) {
        $caps.Add('Delete objects')
        if ($risk -eq 'Low') { $risk = 'Medium' }
    }

    if ($caps.Count -eq 0) { $caps.Add($r.ToString()) }
    return [PSCustomObject]@{ Capability = ($caps -join '; '); Risk = $risk }
}

# --------------------------------------------------------------------------
# Trustee resolution, cached
# --------------------------------------------------------------------------
$trusteeCache = @{}
function Resolve-Trustee($sid) {
    $key = $sid.Value
    if ($trusteeCache.ContainsKey($key)) { return $trusteeCache[$key] }

    $info = [PSCustomObject]@{ Name = $key; Class = 'Unknown'; EffectiveCount = $null }
    try {
        $info.Name = $sid.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $info.Name = "$key (unresolvable - possibly a deleted account)"
    }
    try {
        $o = Get-ADObject -Identity $key -Properties objectClass @serverOnly -ErrorAction Stop
        $info.Class = $o.objectClass
        if ($ExpandTrusteeGroups -and $o.objectClass -eq 'group') {
            try {
                $info.EffectiveCount = @(Get-ADGroupMember -Identity $key -Recursive @serverOnly -ErrorAction Stop).Count
            } catch { }
        }
    } catch {
        # Well-known SIDs (SELF, Authenticated Users) have no domain object. Expected.
        if ($key -like 'S-1-5-32-*' -or $key -like 'S-1-1-*' -or $key -like 'S-1-5-1?') { $info.Class = 'Well-known' }
    }

    $trusteeCache[$key] = $info
    return $info
}

# --------------------------------------------------------------------------
# Read the ACLs
# --------------------------------------------------------------------------
Write-Host "`nReading access control lists..." -ForegroundColor Cyan
$rows     = [System.Collections.Generic.List[object]]::new()
$skipped  = [System.Collections.Generic.List[string]]::new()
$owners   = [System.Collections.Generic.List[object]]::new()
$n = 0

foreach ($t in $targets) {
    $n++
    if ($n % 250 -eq 0) { Write-Progress -Activity 'Reading ACLs' -Status "$n of $($targets.Count)" -PercentComplete (100*$n/$targets.Count) }

    $acl = $null
    try {
        # The AD provider treats '/' as a path separator; escape it in the DN
        $safeDn = $t.DistinguishedName -replace '/', '\/'
        $acl = Get-Acl -Path "$($adDrive):\$safeDn" -ErrorAction Stop
    } catch {
        $skipped.Add("$($t.DistinguishedName) - $($_.Exception.Message)")
        continue
    }

    # Owner: a non-default owner can rewrite the ACL regardless of what it says
    if ($acl.Owner) {
        $ownerName = $acl.Owner.ToString()
        if ($ownerName -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|BUILTIN') {
            $owners.Add([PSCustomObject]@{ DN = $t.DistinguishedName; Owner = $ownerName })
        }
    }

    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

    foreach ($ace in $rules) {
        if ($ace.IsInherited -and -not $IncludeInherited) { continue }
        if (-not $IncludeReadRights -and (Test-ReadOnlyAce $ace.ActiveDirectoryRights)) { continue }

        $sidValue = $ace.IdentityReference.Value
        if (-not $IncludeDefaultTrustees -and $defaultTrustees -contains $sidValue) { continue }

        $cap     = Get-Capability $ace
        $trustee = Resolve-Trustee $ace.IdentityReference

        # Deny ACEs are usually protective, not a finding - note but do not rate
        $risk = if ($ace.AccessControlType -eq 'Deny') { 'Informational (Deny)' } else { $cap.Risk }

        $rows.Add([PSCustomObject][ordered]@{
            'Object'              = $t.name
            'Object DN'           = $t.DistinguishedName
            'Object Class'        = $t.objectClass
            'Trustee'             = $trustee.Name
            'Trustee SID'         = $sidValue
            'Trustee Type'        = $trustee.Class
            'Effective Principals'= $trustee.EffectiveCount
            'Allow/Deny'          = $ace.AccessControlType
            'Capability'          = $cap.Capability
            'Risk'                = $risk
            'Raw Rights'          = $ace.ActiveDirectoryRights.ToString()
            'Applies To Property' = Resolve-Guid $ace.ObjectType
            'Applies To Class'    = Resolve-Guid $ace.InheritedObjectType
            'Inheritance'         = $ace.InheritanceType
            'Inherited'           = if ($ace.IsInherited) { 'Yes' } else { 'No' }
        })
    }
}
Write-Progress -Activity 'Reading ACLs' -Completed

# --------------------------------------------------------------------------
# DCSync: only visible by pairing two ACEs on the domain root
# --------------------------------------------------------------------------
$dcsync = @()
$replRows = $rows | Where-Object { $_.'Object DN' -eq $domain.DistinguishedName -and $_.Capability -like '*replication*' -and $_.'Allow/Deny' -eq 'Allow' }
foreach ($grp in ($replRows | Group-Object 'Trustee SID')) {
    $caps = ($grp.Group.Capability -join ' ')
    if ($caps -match 'Changes All' -and $caps -match 'Changes(?! All)') {
        $dcsync += $grp.Group[0]
        foreach ($r in $grp.Group) { $r.Risk = 'Critical (DCSync)' }
    }
}

$rows | Sort-Object @{E={ switch -Regex ($_.Risk) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} default {4} } }},
                    'Object', 'Trustee' |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$high     = @($rows | Where-Object { $_.Risk -eq 'High' })
$medium   = @($rows | Where-Object { $_.Risk -eq 'Medium' })
$fullCtrl = @($rows | Where-Object { $_.Capability -like 'Full control*' -and $_.'Allow/Deny' -eq 'Allow' })
$writeDacl= @($rows | Where-Object { $_.Capability -like '*Modify permissions*' })
$pwdReset = @($rows | Where-Object { $_.Capability -like '*Reset password*' -or $_.Capability -like '*All extended rights*' })
$broad    = @($rows | Where-Object { $_.'Trustee SID' -in @('S-1-1-0','S-1-5-11','S-1-5-7','S-1-5-32-545','S-1-5-32-554') })

Write-Host "`nWritten to $OutputPath" -ForegroundColor Green
Write-Host "  ACEs recorded                 : $($rows.Count)"
Write-Host "  Distinct trustees             : $($trusteeCache.Keys.Count)"
if ($skipped.Count) { Write-Host "  Objects skipped (unreadable)  : $($skipped.Count)" -ForegroundColor DarkYellow }
Write-Host ""

if ($dcsync.Count) {
    Write-Host "  DCSync-capable trustees                              : $($dcsync.Count)" -ForegroundColor Red
    Write-Host "    Holds both replication rights on the domain root. Can extract"
    Write-Host "    every password hash in the domain, including krbtgt. Treat any"
    Write-Host "    non-DC, non-sync-account holder as a Tier 0 finding."
    foreach ($d in $dcsync) { Write-Host "      - $($d.Trustee)" -ForegroundColor Red }
    Write-Host ""
}
Write-Host "  Full control (GenericAll)                            : $($fullCtrl.Count)" -ForegroundColor Yellow
Write-Host "  Can modify permissions (WriteDacl/WriteOwner)        : $($writeDacl.Count)" -ForegroundColor Yellow
Write-Host "    Equivalent to full control - the holder can simply grant it."
Write-Host "  Can reset passwords                                  : $($pwdReset.Count)" -ForegroundColor Yellow
Write-Host "  Granted to broad groups (Everyone, Authenticated     : $($broad.Count)" -ForegroundColor Yellow
Write-Host "    Users, Domain Users, Pre-Windows 2000 Compat)"
Write-Host ""
Write-Host "  High risk   : $($high.Count)"
Write-Host "  Medium risk : $($medium.Count)"

if ($owners.Count) {
    Write-Host ""
    Write-Host "  Objects with a non-standard owner                    : $($owners.Count)" -ForegroundColor Yellow
    Write-Host "    An owner can rewrite the ACL, so ownership outranks whatever the"
    Write-Host "    permissions currently say. Worth reviewing even where the DACL looks clean."
    $owners | Select-Object -First 10 | ForEach-Object { Write-Host "      - $($_.Owner) owns $($_.DN)" }
    if ($owners.Count -gt 10) { Write-Host "      ... and $($owners.Count - 10) more" }
}

if ($skipped.Count) {
    Write-Host ""
    Write-Host "  Unreadable objects are listed in `$skipped for this session." -ForegroundColor DarkYellow
    $skipped | Select-Object -First 5 | ForEach-Object { Write-Host "      - $_" -ForegroundColor DarkGray }
}

Write-Host ""
Write-Host "Join to the AD Accounts tab on Trustee SID to see what each trustee is." -ForegroundColor Cyan
Write-Host "This is a register of who holds what, not an attack path graph. Run" -ForegroundColor Cyan
Write-Host "BloodHound for transitive paths and PingCastle for scored rules alongside it." -ForegroundColor Cyan

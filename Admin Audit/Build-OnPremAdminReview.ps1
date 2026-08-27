<#
.SYNOPSIS
    Collects privileged access held by on-premises administrator accounts (username-a)
    for the Privileged Access Review workbook.

.DESCRIPTION
    Finds AD accounts matching the on-prem admin naming convention and collects every
    privileged group they belong to. Membership is resolved one level of nesting at a
    time (not flattened by a single -Recursive call), so each grant records whether it
    is direct or arrived via a nested group, and which nested group that was - the same
    distinction Build-CloudAdminReview.ps1 makes for role-assignable groups.

    Also collects the credential posture of each admin account and links it back to
    the person's standard AD account, so a leaver whose standard account is disabled
    while the admin account stays live becomes visible.

    Groups are tiered. Tier 0 means control-plane: membership permits full domain
    compromise, directly or by a well-known escalation path. The tiering is defined
    in $GroupTiers below and is intended to be edited to match your own model. All
    tiers in $GroupTiers are resolved and checked, not just Tier 0/1 as before -
    Tier 2 groups such as Remote Desktop Users are now actually enumerated.

    -DelegatedGroupPattern extends coverage beyond the built-in groups and the
    explicit $GroupTiers list: any group whose Name matches the regex is pulled in
    too, so custom/delegated privileged groups (e.g. 'Tier1-ServerAdmins', a
    site-specific '-ops' group) aren't silently missed just because nobody added
    them to $GroupTiers by hand. Matches not already in $GroupTiers default to Tier 1
    if the name contains 'Admin', otherwise Tier 2 (see Get-GroupTier).

    Also writes a second CSV - the "normal user accounts" comparison set. This is
    the exact list of non-admin-pattern AD user accounts used internally to resolve
    each admin account's standard account and decide orphan status; previously it
    existed only as an in-memory lookup table with no output of its own. Exporting
    it lets a reviewer see and sanity-check the baseline the orphan check is run
    against, rather than trusting it silently.

    Finally, a third CSV covers privilege granted by ACL/delegation rather than
    group membership - GenericAll, GenericWrite, WriteDacl, WriteOwner, a
    WriteProperty grant on the 'member' attribute, or an extended-right grant
    covering Reset Password or DCSync (DS-Replication-Get-Changes /
    -Get-Changes-All / -Get-Changes-In-Filtered-Set). Membership checks (however
    deep the nesting) cannot see this: someone can control a privileged group,
    reset a Tier 0 account's password, or pull every credential in the domain via
    a replication request, without ever appearing in a group's membership. Checked
    targets are every resolved privileged group, the AdminSDHolder container, the
    Domain Controllers OU, the OU(s) that hold admin accounts, each individual
    admin account object, the domain root (where DCSync rights live), and every
    GPO linked to a Tier 0 OU (delegated GPO edit rights are a common path to push
    code to domain controllers without ever touching a privileged group - GPO
    checking needs the GroupPolicy module and additionally flags ANY explicit
    WriteProperty grant, not just one matching a specific attribute GUID, since
    GPO content delegation is commonly granted on several different GPC
    attributes). This is NOT a domain-wide ACL sweep (that would mean reading the
    DACL of every object in the directory) - it is scoped to the objects this
    script already considers Tier 0/1-relevant. Only explicit (non-inherited)
    Allow ACEs are considered, and a short list of expected holders (Domain/
    Enterprise Admins, BUILTIN\Administrators, SYSTEM, Enterprise Domain
    Controllers, SELF, Creator Owner) is filtered out so the output is findings,
    not the domain's normal control structure. A group holding a flagged right is
    expanded to the users that are ultimately able to exercise it, the same way
    privileged group membership itself is expanded. Any account this turns up -
    flagged accounts that also don't hold membership-based privilege are exactly
    the accounts a membership-only view would have missed entirely - is folded
    back into both the admin and normal-user exports as an 'ACL-Based Privilege'
    column.

    adminCount=1 (the AdminSDHolder-protection marker) is also surfaced on the
    normal-user export. A standard/normal account carrying that marker had
    privileged group membership at some point - AdminSDHolder stamps it but does
    not clean it up when the membership is later removed - so it is a residue
    signal worth checking even when current group membership looks clean.

    The admin export also flags Kerberoasting exposure (a Service Principal Name
    set on the account - its TGS ticket can be requested and cracked offline by
    anyone with any domain foothold) and AS-REP roasting exposure ('Do not require
    Kerberos preauthentication' set - the same offline-crack exposure, requested
    even more cheaply). Both matter far more here than on an ordinary account,
    because the account being roasted is privileged by definition.

    READ-ONLY.

.PARAMETER AdminPattern
    Regex identifying admin accounts by SamAccountName. Default matches username-a.

.PARAMETER BaseUsernameCapture
    Regex with one capture group extracting the base username. Default strips '-a'.

.PARAMETER SearchBase
    Restrict collection to one OU. Omit to search the whole domain.

.PARAMETER DelegatedGroupPattern
    Regex matched against every group's Name to catch custom/delegated privileged
    groups beyond the built-in RID groups and the explicit $GroupTiers list, e.g.
    '-ops$', 'Tier[12]', 'Help ?Desk'. Requires enumerating every group in the
    search scope (Get-ADGroup -Filter *), so it costs one extra query pass. Omit to
    skip this and rely on the explicit list only.

.PARAMETER NormalUsersOutputPath
    CSV path for the normal (non-admin) user account export - the comparison
    baseline used to determine orphaned admin accounts.

.PARAMETER AclOutputPath
    CSV path for the delegated-access (ACL-based privilege) export.

.PARAMETER SkipAclCheck
    Skip the ACL/delegation scan. It reads the DACL of every privileged group,
    every admin account, and a few Tier 0 containers - one Get-Acl call each - so
    for a very large admin population this is the costliest part of the script.
    Use this to fall back to membership-only detection.

.PARAMETER SafePrincipals
    Names of additional principals (e.g. a break-glass service account, a PAM
    tool's connector account) to treat as an expected DACL holder and exclude from
    the ACL scan's findings, on top of the built-in list (Domain Admins, Enterprise
    Admins, Administrators, SYSTEM, Enterprise Domain Controllers, SELF, Creator
    Owner).

.PARAMETER SkipGpoCheck
    Skip only the GPO-permission part of the ACL scan (DCSync and the rest of the
    ACL scan still run). Use this if the GroupPolicy module isn't installed and you
    want to silence the warning, or if GPO enumeration is too slow to run routinely.

.PARAMETER Tier0OUs
    Extra OU distinguished names to include in the GPO permission check, beyond the
    Domain Controllers OU and the OU(s) that hold admin accounts (which are always
    included). Use this for OUs holding other Tier 0 assets this script has no way
    to infer on its own, e.g. an OU containing your PKI or PAM servers.

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -Verbose

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -SearchBase 'OU=Admin Accounts,DC=corp,DC=com,DC=au'

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -DelegatedGroupPattern '(?i)admin|-ops$|Tier[12]'

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -SafePrincipals 'PAM-Connector','Tier0-BreakGlass'

.EXAMPLE
    .\Build-OnPremAdminReview.ps1 -Tier0OUs 'OU=PKI Servers,DC=corp,DC=com,DC=au'

.NOTES
    Requires the ActiveDirectory module (RSAT) and a domain-joined machine.
    Standard authenticated-user read access is sufficient for these properties.

    The GPO permission check additionally requires the GroupPolicy module
    (RSAT-GPMC). It is skipped with a warning, not an error, if that module isn't
    installed - the rest of the ACL scan still runs.

    LastLogonDate derives from lastLogonTimestamp, which replicates lazily and can
    sit up to 14 days behind. Treat it as approximate.

    The ACL scan reads DACLs through the module's default AD: PSDrive, which binds
    to whichever domain controller the ActiveDirectory module auto-discovered. It
    does not honour -Server the way the rest of this script's cmdlet calls do. If
    you need the ACL scan against a specific domain, run this from a machine
    domain-joined to it rather than relying on -Server, or use -SkipAclCheck.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\OnPrem-Admins.csv",
    [string]$NormalUsersOutputPath = ".\Normal-Users.csv",
    [string]$AclOutputPath = ".\OnPrem-DelegatedAccess.csv",
    [string]$AdminPattern = '-a$',
    [string]$BaseUsernameCapture = '^(.+)-a$',
    [string]$SearchBase,
    [string]$Server,
    [string]$DelegatedGroupPattern,
    [switch]$SkipAclCheck,
    [string[]]$SafePrincipals,
    [switch]$SkipGpoCheck,
    [string[]]$Tier0OUs
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
foreach ($n in $GroupTiers.Keys) {
    try {
        $g = Get-ADGroup -Filter "Name -eq '$n'" -ErrorAction Stop
        if ($g -and -not ($privGroups | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) { $privGroups.Add($g) }
    } catch { }
}
if ($DelegatedGroupPattern) {
    Write-Host "  Scanning all groups for custom/delegated matches of '$DelegatedGroupPattern'..." -ForegroundColor Cyan
    $custom = @(Get-ADGroup -Filter * @common | Where-Object { $_.Name -match $DelegatedGroupPattern })
    foreach ($g in $custom) {
        if (-not ($privGroups | Where-Object { $_.DistinguishedName -eq $g.DistinguishedName })) {
            $privGroups.Add($g)
            Write-Verbose "  +$($g.Name) (delegated match, tier $(Get-GroupTier $g.Name))"
        }
    }
}

# --------------------------------------------------------------------------
# Membership is walked one level at a time rather than flattened by a single
# -Recursive call, so each grant can be tagged as direct or as arriving via a
# named nested group - the same distinction the cloud script makes for
# role-assignable groups. Only one level of nested-group naming is kept (the
# immediate child of the privileged group), even though membership under that
# child is still expanded recursively, which matches how Build-CloudAdminReview
# reports "via <group>" for its own group expansion.
# --------------------------------------------------------------------------
$memberOf = @{}   # SID -> List[ @{ Group; Direct; ViaGroup } ]
function Add-Membership([string]$Sid, [string]$Group, [bool]$Direct, [string]$ViaGroup) {
    if (-not $memberOf.ContainsKey($Sid)) { $memberOf[$Sid] = [System.Collections.Generic.List[object]]::new() }
    $memberOf[$Sid].Add([PSCustomObject]@{ Group = $Group; Direct = $Direct; ViaGroup = $ViaGroup })
}

foreach ($g in $privGroups) {
    try {
        foreach ($m in (Get-ADGroupMember -Identity $g.DistinguishedName -ErrorAction Stop)) {
            if ($m.objectClass -eq 'group') {
                try {
                    foreach ($nm in (Get-ADGroupMember -Identity $m.DistinguishedName -Recursive -ErrorAction Stop)) {
                        if ($nm.objectClass -eq 'user') { Add-Membership $nm.SID.Value $g.Name $false $m.Name }
                    }
                } catch { Write-Warning "Could not expand nested group '$($m.Name)' under '$($g.Name)': $($_.Exception.Message)" }
            } elseif ($m.objectClass -eq 'user') {
                Add-Membership $m.SID.Value $g.Name $true ''
            }
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
           'SmartcardLogonRequired','Department','Title','Manager',
           'ServicePrincipalName','DoesNotRequirePreAuth')

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

# Reverse of $standardBySam - which admin account(s), if any, belong to a given
# standard account. Used to build the Normal-Users.csv comparison export.
$adminByBase = @{}
foreach ($a in $admins) {
    $b = if ($a.SamAccountName -match $BaseUsernameCapture) { $Matches[1].ToLower() } else { $a.SamAccountName.ToLower() }
    if (-not $adminByBase.ContainsKey($b)) { $adminByBase[$b] = [System.Collections.Generic.List[object]]::new() }
    $adminByBase[$b].Add($a)
}

# DN -> DisplayName, so Manager can be shown as a name rather than a raw DN
$byDN = @{}
foreach ($u in $all) { $byDN[$u.DistinguishedName] = $u.DisplayName }

# SamAccountName (lower) -> ADUser, so enabled/disabled status for anyone found by
# the ACL scan below can be read from what's already in memory instead of another
# round trip per account.
$bySamAccountName = @{}
foreach ($u in $all) { $bySamAccountName[$u.SamAccountName.ToLower()] = $u }

function Get-Delegation($a) {
    if ($a.TrustedForDelegation)           { return 'Unconstrained' }
    if ($a.TrustedToAuthForDelegation)     { return 'Constrained w/ protocol transition' }
    if ($a.'msDS-AllowedToDelegateTo')     { return 'Constrained' }
    return 'None'
}

# --------------------------------------------------------------------------
# Delegated access (ACL-based privilege).
#
# Group membership - however deeply nested - is not the only way to control a
# privileged object. Someone holding GenericAll/WriteDacl/WriteOwner on a
# privileged group, write access to its 'member' attribute, or a Reset Password
# extended right over an admin account's OU, can compromise it without ever
# appearing in its membership. This section reads the DACL of every object this
# script already treats as Tier 0/1-relevant - it is not a domain-wide sweep.
# --------------------------------------------------------------------------
$serverOnly = @{}
if ($Server) { $serverOnly.Server = $Server }

$MemberAttrGuid = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'   # 'member' attribute

# Named extended rights worth calling out specifically. GUIDs verified against the
# AD schema reference (learn.microsoft.com/windows/win32/adschema).
$ExtendedRightNames = @{
    '00299570-246d-11d0-a768-00aa006e0529' = 'Reset Password'                                # User-Force-Change-Password
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'                     # DCSync, half 1 of 2
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'                 # DCSync, half 2 of 2
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'     # DCSync w/ RODC filtered attribute sets
}

$SafeSids = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
    "$domainSid-500",   # Administrator
    "$domainSid-512",   # Domain Admins
    "$domainSid-516",   # Domain Controllers
    "$domainSid-518",   # Schema Admins
    "$domainSid-519",   # Enterprise Admins
    'S-1-5-32-544',     # BUILTIN\Administrators
    'S-1-5-18',         # SYSTEM
    'S-1-5-9',          # Enterprise Domain Controllers
    'S-1-5-10',         # SELF
    'S-1-3-0'           # CREATOR OWNER
))
foreach ($n in $SafePrincipals) {
    try {
        $o = Get-ADObject -Filter "Name -eq '$n' -or SamAccountName -eq '$n'" -Properties ObjectSid @common -ErrorAction Stop | Select-Object -First 1
        if ($o) { $SafeSids.Add($o.ObjectSid.Value) | Out-Null }
    } catch { Write-Warning "Could not resolve -SafePrincipals entry '$n': $($_.Exception.Message)" }
}

function Get-DangerousAces {
    param(
        [string]$DistinguishedName,
        [string]$TargetLabel,
        $TargetTier,
        # GPO content is more often delegated via a WriteProperty grant on specific
        # GPC attributes (gPCFileSysPath, gPCMachineExtensionNames, etc.) than via
        # GenericWrite. Those attribute GUIDs vary enough by schema version/extension
        # that hardcoding them risked silently missing real delegations, so for GPOs
        # this flags ANY explicit WriteProperty grant rather than a specific GUID -
        # broader than the member-attribute-only check used for groups, deliberately.
        [switch]$FlagAnyWriteProperty
    )
    $found = [System.Collections.Generic.List[object]]::new()
    try { $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop }
    catch { Write-Warning "Could not read ACL on '$TargetLabel': $($_.Exception.Message)"; return $found }

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow' -or $ace.IsInherited) { continue }
        $r = $ace.ActiveDirectoryRights.ToString()
        $right = $null
        if     ($r -match 'GenericAll')   { $right = 'GenericAll' }
        elseif ($r -match 'WriteDacl')    { $right = 'WriteDacl' }
        elseif ($r -match 'WriteOwner')   { $right = 'WriteOwner' }
        elseif ($r -match 'GenericWrite') { $right = 'GenericWrite' }
        elseif ($r -match 'WriteProperty') {
            if ($FlagAnyWriteProperty) { $right = "WriteProperty ($($ace.ObjectType))" }
            elseif ($ace.ObjectType -eq $MemberAttrGuid -or $ace.ObjectType -eq [guid]::Empty) { $right = 'WriteProperty (member)' }
        } elseif ($r -match 'ExtendedRight') {
            $key = $ace.ObjectType.ToString()
            if ($ExtendedRightNames.ContainsKey($key)) { $right = "ExtendedRight ($($ExtendedRightNames[$key]))" }
            elseif ($ace.ObjectType -eq [guid]::Empty)  { $right = 'ExtendedRight (All)' }
        }
        if (-not $right) { continue }

        $sid = $null
        if ($ace.IdentityReference.Value -match '^S-1-') { $sid = $ace.IdentityReference.Value }
        else { try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { } }
        if (-not $sid -or $SafeSids.Contains($sid)) { continue }

        # TargetTier is cast to string here because it mixes int (groups, via Get-GroupTier)
        # with '' (OUs and individual admin accounts, which have no group tier of their own) -
        # Sort-Object on a column mixing types can throw under $ErrorActionPreference = 'Stop'.
        $found.Add([PSCustomObject]@{ TargetLabel = $TargetLabel; TargetTier = "$TargetTier"; Right = $right; PrincipalSid = $sid })
    }
    return $found
}

$aclFindings = [System.Collections.Generic.List[object]]::new()
if ($SkipAclCheck) {
    Write-Host "Skipping delegated ACL check (-SkipAclCheck)" -ForegroundColor Yellow
} else {
    Write-Host "Checking delegated ACLs on privileged groups and Tier 0 containers..." -ForegroundColor Cyan
    $aclRaw = [System.Collections.Generic.List[object]]::new()

    foreach ($g in $privGroups) {
        $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $g.DistinguishedName -TargetLabel "Group: $($g.Name)" -TargetTier (Get-GroupTier $g.Name)))
    }

    $adminSdHolderDn = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
    $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $adminSdHolderDn -TargetLabel 'AdminSDHolder' -TargetTier 0))

    if ($domain.DomainControllersContainer) {
        $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $domain.DomainControllersContainer -TargetLabel 'Domain Controllers OU' -TargetTier 0))
    }

    $adminOUs = @($admins | ForEach-Object { $_.DistinguishedName -replace '^CN=[^,]+,','' } | Sort-Object -Unique)
    foreach ($ou in $adminOUs) {
        $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $ou -TargetLabel "Admin Accounts OU: $ou" -TargetTier ''))
    }

    foreach ($a in $admins) {
        $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $a.DistinguishedName -TargetLabel "Admin Account: $($a.SamAccountName)" -TargetTier ''))
    }

    # Domain root: this is where DCSync rights live. Anyone holding both
    # DS-Replication-Get-Changes and DS-Replication-Get-Changes-All here can pull
    # every credential in the domain via a replication request - full compromise,
    # without ever touching a privileged group or a Tier 0 account.
    $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $domain.DistinguishedName -TargetLabel 'Domain Root (DCSync exposure)' -TargetTier 0))

    if ($SkipGpoCheck) {
        Write-Host "Skipping GPO permission check (-SkipGpoCheck)" -ForegroundColor Yellow
    } elseif (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Warning "GroupPolicy module not available - skipping GPO permission check. Install RSAT-GPMC, or use -SkipGpoCheck to silence this."
    } else {
        Import-Module GroupPolicy -ErrorAction Stop
        Write-Host "Checking GPO permissions on Tier 0 OUs..." -ForegroundColor Cyan

        $tier0Ous = @($domain.DomainControllersContainer) + @($adminOUs) + @($Tier0OUs) |
                    Where-Object { $_ } | Sort-Object -Unique
        $seenGpoIds = @{}
        foreach ($ouDn in $tier0Ous) {
            try {
                $inheritance = Get-GPInheritance -Target $ouDn -ErrorAction Stop
                $links = @($inheritance.GpoLinks) + @($inheritance.InheritedGpoLinks)
                foreach ($link in $links) {
                    $gpoIdStr = $link.GpoId.ToString()
                    if ($seenGpoIds.ContainsKey($gpoIdStr)) { continue }
                    $seenGpoIds[$gpoIdStr] = $true
                    $gpoDn = "CN=$($link.GpoId.ToString('B').ToUpper()),CN=Policies,CN=System,$($domain.DistinguishedName)"
                    $label = "GPO: $($link.DisplayName) (linked: $ouDn)"
                    $aclRaw.AddRange([object[]](Get-DangerousAces -DistinguishedName $gpoDn -TargetLabel $label -TargetTier 0 -FlagAnyWriteProperty))
                }
            } catch { Write-Warning "Could not read GPO links for '$ouDn': $($_.Exception.Message)" }
        }
        Write-Host "  $($seenGpoIds.Keys.Count) distinct GPO(s) linked to a Tier 0 OU checked"
    }

    Write-Host "  $($aclRaw.Count) non-standard ACE(s) found, resolving principals..."

    $principalCache = @{}
    function Resolve-Principal([string]$Sid) {
        if ($principalCache.ContainsKey($Sid)) { return $principalCache[$Sid] }
        $obj = $null
        try { $obj = Get-ADObject -Identity $Sid -Properties SamAccountName,ObjectClass @serverOnly -ErrorAction Stop } catch { }
        $principalCache[$Sid] = $obj
        return $obj
    }
    function Get-EnabledStatus([string]$Sam) {
        if (-not $Sam) { return '' }
        $u = $bySamAccountName[$Sam.ToLower()]
        if (-not $u) { return 'Unknown' }
        if ($u.Enabled) { return 'Yes' } else { return 'No' }
    }

    foreach ($f in $aclRaw) {
        $p = Resolve-Principal $f.PrincipalSid
        if (-not $p) {
            $aclFindings.Add([PSCustomObject][ordered]@{
                'Target' = $f.TargetLabel; 'Target Tier' = $f.TargetTier; 'Right' = $f.Right
                'Granted To' = "UNRESOLVED SID ($($f.PrincipalSid))"; 'Granted To Type' = 'Unknown'
                'Effective User' = ''; 'Effective User Enabled' = ''; 'Via Group' = ''
            })
            continue
        }
        if ($p.ObjectClass -eq 'group') {
            $members = @(try { Get-ADGroupMember -Identity $p.DistinguishedName -Recursive @serverOnly -ErrorAction Stop } catch { @() })
            $userMembers = @($members | Where-Object { $_.objectClass -eq 'user' })
            if ($userMembers.Count -eq 0) {
                $aclFindings.Add([PSCustomObject][ordered]@{
                    'Target' = $f.TargetLabel; 'Target Tier' = $f.TargetTier; 'Right' = $f.Right
                    'Granted To' = $p.SamAccountName; 'Granted To Type' = 'Group (empty)'
                    'Effective User' = ''; 'Effective User Enabled' = ''; 'Via Group' = $p.SamAccountName
                })
            } else {
                foreach ($um in $userMembers) {
                    $aclFindings.Add([PSCustomObject][ordered]@{
                        'Target' = $f.TargetLabel; 'Target Tier' = $f.TargetTier; 'Right' = $f.Right
                        'Granted To' = $p.SamAccountName; 'Granted To Type' = 'Group'
                        'Effective User' = $um.SamAccountName
                        'Effective User Enabled' = Get-EnabledStatus $um.SamAccountName
                        'Via Group' = $p.SamAccountName
                    })
                }
            }
        } else {
            $aclFindings.Add([PSCustomObject][ordered]@{
                'Target' = $f.TargetLabel; 'Target Tier' = $f.TargetTier; 'Right' = $f.Right
                'Granted To' = $p.SamAccountName; 'Granted To Type' = $p.ObjectClass
                'Effective User' = if ($p.ObjectClass -eq 'user') { $p.SamAccountName } else { '' }
                'Effective User Enabled' = if ($p.ObjectClass -eq 'user') { Get-EnabledStatus $p.SamAccountName } else { '' }
                'Via Group' = ''
            })
        }
    }
}

if (-not $SkipAclCheck) {
    $aclFindings | Sort-Object 'Target Tier','Target' | Export-Csv -Path $AclOutputPath -NoTypeInformation -Encoding UTF8
}

# SamAccountName (lower) -> List[string] of "<Right> on <Target>" descriptions, so
# the admin and normal-user rows below can show ACL-based privilege inline.
$aclBySam = @{}
foreach ($f in $aclFindings) {
    if (-not $f.'Effective User') { continue }
    $key = $f.'Effective User'.ToLower()
    if (-not $aclBySam.ContainsKey($key)) { $aclBySam[$key] = [System.Collections.Generic.List[string]]::new() }
    $desc = "$($f.Right) on $($f.Target)"
    if ($f.'Via Group') { $desc += " (via $($f.'Via Group'))" }
    $aclBySam[$key].Add($desc)
}

$now = Get-Date
$rows = foreach ($a in $admins) {

    $base = if ($a.SamAccountName -match $BaseUsernameCapture) { $Matches[1].ToLower() } else { $a.SamAccountName.ToLower() }
    $std  = $standardBySam[$base]

    $memberships = @(if ($memberOf.ContainsKey($a.SID.Value)) { $memberOf[$a.SID.Value] })
    $groupNames  = @($memberships | ForEach-Object { $_.Group } | Sort-Object -Unique)
    $highest = if ($groupNames.Count) {
        @($groupNames | Sort-Object @{ E = { Get-GroupTier $_ } }, @{ E = { $_ } })[0]
    } else { 'None' }
    $tier = if ($groupNames.Count) { ($groupNames | ForEach-Object { Get-GroupTier $_ } | Measure-Object -Minimum).Minimum } else { '' }
    $pwAge = if ($a.PasswordLastSet) { [int]($now - $a.PasswordLastSet).TotalDays } else { $null }

    # Render each grant as "Group" or "Group (nested via NestedGroup)" so the route
    # travels with the group name instead of being lost in a bare list.
    function Format-Membership($m) {
        if ($m.Direct) { return $m.Group }
        return "$($m.Group) (nested via $($m.ViaGroup))"
    }
    $membershipStrings = @($memberships | ForEach-Object { Format-Membership $_ } | Sort-Object -Unique)
    $directCount = @($memberships | Where-Object { $_.Direct }).Count
    $nestedCount = @($memberships | Where-Object { -not $_.Direct }).Count
    $route = if ($directCount -gt 0 -and $nestedCount -gt 0) { 'Direct + Nested' }
             elseif ($nestedCount -gt 0) { 'Nested only' }
             elseif ($directCount -gt 0) { 'Direct only' } else { '' }
    $nestedVia = @($memberships | Where-Object { -not $_.Direct } | ForEach-Object { $_.ViaGroup } | Sort-Object -Unique)

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
        'Kerberoastable (SPN)'   = if (@($a.ServicePrincipalName).Count -gt 0) { 'Yes' } else { 'No' }
        'Service Principal Names'= if (@($a.ServicePrincipalName).Count -gt 0) { ($a.ServicePrincipalName -join '; ') } else { '' }
        'AS-REP Roastable'       = if ($a.DoesNotRequirePreAuth) { 'Yes' } else { 'No' }
        'Privileged Groups'      = if ($membershipStrings.Count) { $membershipStrings -join '; ' } else { 'None' }
        'Privileged Group Count' = $groupNames.Count
        'Highest AD Group'       = $highest
        'AD Tier'                = $tier
        'Membership Route'       = $route
        'Nested Via'             = if ($nestedVia.Count) { $nestedVia -join '; ' } else { '' }
        'AdminCount'             = if ($a.adminCount -eq 1) { '1' } else { '' }
        'ACL-Based Privilege'    = if ($aclBySam.ContainsKey($a.SamAccountName.ToLower())) { 'Yes' } else { 'No' }
        'ACL Privilege Detail'   = if ($aclBySam.ContainsKey($a.SamAccountName.ToLower())) { $aclBySam[$a.SamAccountName.ToLower()] -join '; ' } else { '' }
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
# Normal user accounts - the comparison baseline the orphan check above runs
# against. This is the same set as $standardBySam, exported so it can be
# reviewed on its own rather than trusted as an invisible lookup table.
# --------------------------------------------------------------------------
Write-Host "Building normal user account list..." -ForegroundColor Cyan
$normalUsers = @($all | Where-Object { $_.SamAccountName -notmatch $AdminPattern })

$normalRows = foreach ($u in $normalUsers) {
    $linkedAdmins = @(if ($adminByBase.ContainsKey($u.SamAccountName.ToLower())) { $adminByBase[$u.SamAccountName.ToLower()] })
    $pwAge = if ($u.PasswordLastSet) { [int]($now - $u.PasswordLastSet).TotalDays } else { $null }

    [PSCustomObject][ordered]@{
        'SamAccountName'            = $u.SamAccountName
        'Display Name'              = $u.DisplayName
        'Distinguished Name'        = $u.DistinguishedName
        'SID'                       = $u.SID.Value
        'Enabled'                   = if ($u.Enabled) { 'Yes' } else { 'No' }
        'Created'                   = if ($u.whenCreated) { $u.whenCreated.ToString('dd/MM/yyyy') } else { '' }
        'Last Logon'                = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('dd/MM/yyyy') } else { '' }
        'Password Last Set'         = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('dd/MM/yyyy') } else { '' }
        'Password Age (days)'       = $pwAge
        'Department'                = $u.Department
        'Job Title'                 = $u.Title
        'Manager'                   = if ($u.Manager -and $byDN.ContainsKey($u.Manager)) { $byDN[$u.Manager] } else { '' }
        'Has Admin Account'         = if ($linkedAdmins.Count) { 'Yes' } else { 'No' }
        'Admin Accounts'            = ($linkedAdmins.SamAccountName -join '; ')
        'Any Admin Account Enabled' = if (@($linkedAdmins | Where-Object Enabled).Count) { 'Yes' } elseif ($linkedAdmins.Count) { 'No' } else { '' }
        'AdminCount (Protected)'    = if ($u.adminCount -eq 1) { 'Yes' } else { 'No' }
        'ACL-Based Privilege'       = if ($aclBySam.ContainsKey($u.SamAccountName.ToLower())) { 'Yes' } else { 'No' }
        'ACL Privilege Detail'      = if ($aclBySam.ContainsKey($u.SamAccountName.ToLower())) { $aclBySam[$u.SamAccountName.ToLower()] -join '; ' } else { '' }
    }
}

$normalRows | Sort-Object @{E={$_.Enabled};Descending=$true}, 'SamAccountName' |
    Export-Csv -Path $NormalUsersOutputPath -NoTypeInformation -Encoding UTF8

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$t0       = @($rows | Where-Object { $_.'AD Tier' -eq 0 })
$noPriv   = @($rows | Where-Object { $_.'Privileged Groups' -eq 'None' })
$orphaned = @($rows | Where-Object { $_.Enabled -eq 'Yes' -and $_.'Standard Acct Enabled' -in @('No','NOT FOUND') })
$stalePw  = @($rows | Where-Object { $_.'Password Age (days)' -and [int]$_.'Password Age (days)' -gt 365 -and $_.Enabled -eq 'Yes' })
$noSc     = @($rows | Where-Object { $_.'Smartcard Required' -eq 'No' -and $_.'AD Tier' -eq 0 -and $_.Enabled -eq 'Yes' })
$deleg    = @($rows | Where-Object { $_.Delegation -ne 'None' })
$viaNested = @($rows | Where-Object { $_.'Membership Route' -eq 'Nested only' })

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
$kerberoastable = @($rows | Where-Object { $_.'Kerberoastable (SPN)' -eq 'Yes' -and $_.Enabled -eq 'Yes' })
$asRepRoastable = @($rows | Where-Object { $_.'AS-REP Roastable' -eq 'Yes' -and $_.Enabled -eq 'Yes' })
if ($kerberoastable.Count) {
    Write-Host "  Kerberoastable (SPN set, enabled)     : $($kerberoastable.Count)" -ForegroundColor Red
    Write-Host "    A Tier 0/1 account with an SPN can have its TGS ticket requested and cracked offline by"
    Write-Host "    anyone with a domain foothold, no privilege required to request it."
}
if ($asRepRoastable.Count) {
    Write-Host "  AS-REP roastable (no preauth, enabled) : $($asRepRoastable.Count)" -ForegroundColor Red
    Write-Host "    Same offline-crack exposure as Kerberoasting, requested even more cheaply."
}
if ($viaNested.Count) {
    Write-Host "  Privilege held ONLY via nested group  : $($viaNested.Count)" -ForegroundColor Yellow
    Write-Host "    No direct membership in the privileged group itself - would have been invisible to a"
    Write-Host "    report that only checked direct membership."
}
if ($noPriv.Count) {
    $noPrivAclOnly = @($noPriv | Where-Object { $_.'ACL-Based Privilege' -eq 'Yes' })
    Write-Host "  Admin-named but in NO privileged group : $($noPriv.Count)"
    Write-Host "    Either the privilege was removed and the account was not, or it is granted by a route this"
    Write-Host "    script does not see (an ACL target outside the ones this script checks)."
    if ($noPrivAclOnly.Count) {
        Write-Host "    $($noPrivAclOnly.Count) of these DO hold ACL-based privilege - see 'ACL Privilege Detail'." -ForegroundColor Red
    }
}

$normalDisabled = @($normalRows | Where-Object { $_.Enabled -eq 'No' })
$normalDisabledLiveAdmin = @($normalRows | Where-Object { $_.Enabled -eq 'No' -and $_.'Any Admin Account Enabled' -eq 'Yes' })

Write-Host "`nWritten to $NormalUsersOutputPath" -ForegroundColor Green
Write-Host "  Normal (non-admin-pattern) user accounts : $($normalRows.Count)"
Write-Host "  Disabled                                  : $($normalDisabled.Count)"
if ($normalDisabledLiveAdmin.Count) {
    Write-Host "  Disabled standard account, admin account still enabled : $($normalDisabledLiveAdmin.Count)" -ForegroundColor Red
    Write-Host "    Same leavers as the ORPHANED count above, seen from the standard-account side."
}
$normalProtected = @($normalRows | Where-Object { $_.'AdminCount (Protected)' -eq 'Yes' })
if ($normalProtected.Count) {
    Write-Host "  adminCount=1 on a normal-looking account : $($normalProtected.Count)" -ForegroundColor Yellow
    Write-Host "    AdminSDHolder stamps this when an account gains privileged group membership and never"
    Write-Host "    removes it when that membership is later taken away. Worth checking even if the account"
    Write-Host "    holds no privilege today."
}

# --------------------------------------------------------------------------
# ACL / delegated-access summary
# --------------------------------------------------------------------------
if (-not $SkipAclCheck) {
    $aclResolved     = @($aclFindings | Where-Object { $_.'Effective User' })
    $aclDistinctSam  = @($aclResolved | Select-Object -ExpandProperty 'Effective User' -Unique)
    $aclEnabled      = @($aclDistinctSam | Where-Object { (Get-EnabledStatus $_) -eq 'Yes' })
    $aclNoGroupPriv  = @($aclDistinctSam | Where-Object {
        $u = $bySamAccountName[$_.ToLower()]
        $u -and -not $memberOf.ContainsKey($u.SID.Value)
    })
    $aclOnNormal     = @($aclDistinctSam | Where-Object { $_ -notmatch $AdminPattern })
    $aclUnresolved   = @($aclFindings | Where-Object { $_.'Granted To Type' -eq 'Unknown' })

    Write-Host "`nWritten to $AclOutputPath" -ForegroundColor Green
    Write-Host "  Non-standard ACE(s) on checked Tier 0/1 objects : $($aclFindings.Count)"
    Write-Host "  Distinct account(s) able to exercise one        : $($aclDistinctSam.Count)"
    if ($aclEnabled.Count) { Write-Host "  ...and currently enabled                        : $($aclEnabled.Count)" -ForegroundColor Yellow }
    if ($aclNoGroupPriv.Count) {
        Write-Host "  ...with NO privileged group membership at all   : $($aclNoGroupPriv.Count)" -ForegroundColor Red
        Write-Host "    Invisible to membership-based detection, however deep the nesting. Privilege here is"
        Write-Host "    granted entirely by ACL/delegation."
    }
    if ($aclOnNormal.Count) {
        Write-Host "  ...on an account that isn't admin-pattern-named : $($aclOnNormal.Count)" -ForegroundColor Red
        Write-Host "    Doesn't even look like an admin account by naming convention. Start here."
    }
    if ($aclUnresolved.Count) {
        Write-Host "  Unresolved SID(s) in a DACL                     : $($aclUnresolved.Count)" -ForegroundColor Yellow
        Write-Host "    A principal that no longer exists - a leftover grant to a deleted account or group."
    }

    $dcSyncFindings = @($aclFindings | Where-Object { $_.Target -eq 'Domain Root (DCSync exposure)' })
    if ($dcSyncFindings.Count) {
        $dcSyncBySam = $dcSyncFindings | Where-Object { $_.'Effective User' } | Group-Object 'Effective User'
        $fullDcSync  = @($dcSyncBySam | Where-Object {
            $rights = @($_.Group.Right)
            (@($rights | Where-Object { $_ -like '*DS-Replication-Get-Changes)*' })).Count -gt 0 -and
            (@($rights | Where-Object { $_ -like '*DS-Replication-Get-Changes-All)*' })).Count -gt 0
        })
        Write-Host "  DCSync-relevant grant(s) on domain root          : $($dcSyncFindings.Count)" -ForegroundColor Red
        if ($fullDcSync.Count) {
            Write-Host "    $($fullDcSync.Count) account(s) hold BOTH replication rights needed for full DCSync -" -ForegroundColor Red
            Write-Host "    credential-dumping capable without ever holding a privileged group membership."
        }
    }

    $gpoFindings = @($aclFindings | Where-Object { $_.Target -like 'GPO: *' })
    if ($gpoFindings.Count) {
        $gpoDistinctSam = @($gpoFindings | Where-Object { $_.'Effective User' } | Select-Object -ExpandProperty 'Effective User' -Unique)
        Write-Host "  Non-standard grant(s) on a Tier 0-linked GPO      : $($gpoFindings.Count)" -ForegroundColor Red
        Write-Host "    $($gpoDistinctSam.Count) account(s) can edit a GPO applied to the Domain Controllers OU or"
        Write-Host "    an admin accounts OU - a path to push code to Tier 0 without touching a privileged group."
    }
}

Write-Host "`nNext: paste On-Prem Admins into the 'On-Prem Admins' tab at cell A2 (columns A-AE)." -ForegroundColor Cyan
Write-Host "      paste Normal Users into a 'Normal Users' tab at cell A2 (columns A-R), if you want it in the workbook." -ForegroundColor Cyan
if (-not $SkipAclCheck) {
    Write-Host "      paste Delegated Access into a 'Delegated Access' tab at cell A2 (columns A-H), if you want it in the workbook." -ForegroundColor Cyan
}

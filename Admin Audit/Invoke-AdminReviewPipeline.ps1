<#
.SYNOPSIS
    Runs the Privileged Access Review scripts in the correct order, in one call.

.DESCRIPTION
    The workbook pipeline has a real dependency order that isn't enforced by
    anything except a human remembering it:

        1. Build-OnPremAdminReview.ps1   (AD)               -> OnPrem-Admins.csv, Normal-Users.csv, OnPrem-DelegatedAccess.csv
        2. Build-CloudAdminReview.ps1    (Graph + Az)        -> Cloud-Admin-Accounts.csv, Entra-Admins.csv, Azure-RBAC-Admins.csv, Normal-CloudUsers.csv
        3. Merge-AdminReview.ps1         (offline, needs 1+2)-> Admin-People.csv
        4. Update-AdminPeopleAD.ps1      (AD, needs 3)       -> adds 'AD Manager' / 'AD Account Active' to Admin-People.csv
        5. Update-AdminPeopleEntra.ps1   (Graph, needs 4)    -> adds 'Entra Account Active' / 'AD/Entra Active Mismatch'
        6. Sync-AdminReviewWorkbook.ps1  (opt-in, needs 1-5) -> writes all five CSVs into the workbook tabs, in place

    Step 3 will silently produce a stale or incomplete Admin-People.csv if it's
    run before 1 and 2 finish (it reads whatever CSVs happen to be sitting on
    disk, however old). Step 5 throws outright if step 4 hasn't run - it depends
    on the 'AD Account Active' column that script writes. This script exists
    so that ordering is guaranteed by code, not by memory.

    Step 6 is different from the rest: it's the only stage that writes into a
    file that can carry real reviewer work (once the workbook has been used for
    an actual review), so unlike stages 1-5 it never runs unless you explicitly
    pass -SyncWorkbookPath. See Sync-AdminReviewWorkbook.ps1's own docstring for
    what it does and does not touch in the workbook.

    Every script here is READ-ONLY against AD/Graph/Az - the only writes are the
    CSVs in -OutputDirectory. This orchestrator makes no AD, Graph, or Azure
    changes of its own.

    Runs everything on ONE machine in ONE session: AD needs the ActiveDirectory
    module and domain access, cloud needs Microsoft.Graph (and Az.ResourceGraph
    unless -SkipAzureRbac) with an interactive sign-in. That fits a reviewer's
    own domain-joined workstation. It does NOT fit the split hybrid-worker
    architecture in Automation-Guide.md, where AD collection and cloud
    collection deliberately run on two different execution contexts because
    Azure Automation's sandbox has no line of sight to a domain controller -
    for that unattended/scheduled path, adapt each script's body into the
    runbooks described there instead of calling this script from one.

    Deliberately does NOT expose -SearchBase / -UserSearchBases /
    -GroupSearchBases. Build-OnPremAdminReview.ps1's own .EXAMPLE showing
    -UserSearchBases scoped to an admin-only OU is a known footgun: scope the
    standard-account sweep out and every enabled admin reads 'Standard Acct
    Enabled = NOT FOUND', which flags them orphaned regardless of whether their
    real AD account exists and is enabled. Always sweeps the whole domain.

    Stops on the first stage that throws, by default - each stage's output
    feeds the next, so continuing past a failed stage produces a workbook
    that looks complete but is built on missing or stale data. Use
    -ContinueOnError only if you specifically want the CSVs already on disk
    from a previous run to be reused by the stages after the failure (e.g.
    -SkipCloudBuild to intentionally reuse an older Cloud-Admin-Accounts.csv).

.PARAMETER OutputDirectory
    Folder the six CSVs are read from and written to. Created if missing.
    Defaults to the current directory, matching how the five scripts behave
    when run by hand. Resolved to a full path up front so every stage writes
    to the same place regardless of the working directory a later stage might
    change.

.PARAMETER Server
    Domain controller (or domain) for both AD stages (Build-OnPremAdminReview.ps1
    and Update-AdminPeopleAD.ps1). Omit to let the ActiveDirectory module
    auto-discover one.

.PARAMETER StandardAccountDomain
    UPN suffix of everyday accounts, e.g. 'corp.com.au'. Passed to both cloud
    stages (Build-CloudAdminReview.ps1 and Update-AdminPeopleEntra.ps1) so they
    resolve standard accounts the same way. Omit to match on UPN prefix across
    every domain in the tenant instead.

.PARAMETER SkipOnPremBuild
    Skip Build-OnPremAdminReview.ps1 (stage 1) and reuse whatever OnPrem-Admins.csv
    / Normal-Users.csv already exist in -OutputDirectory. Update-AdminPeopleAD.ps1
    (stage 4) still runs unless -SkipAdRefresh is also set - it does a cheap
    per-person lookup independent of stage 1's bulk sweep.

.PARAMETER SkipCloudBuild
    Skip Build-CloudAdminReview.ps1 (stage 2) and reuse whatever
    Cloud-Admin-Accounts.csv / Entra-Admins.csv / Azure-RBAC-Admins.csv /
    Normal-CloudUsers.csv already exist in -OutputDirectory.

.PARAMETER SkipAdRefresh
    Skip Update-AdminPeopleAD.ps1 (stage 4). Forces -SkipEntraReconcile too -
    Update-AdminPeopleEntra.ps1 (stage 5) throws without the 'AD Account Active'
    column stage 4 writes, so there is nothing valid for it to do.

.PARAMETER SkipEntraReconcile
    Skip Update-AdminPeopleEntra.ps1 (stage 5) - the AD-disabled-but-Entra-still-
    active check. Everything else still runs.

.PARAMETER SkipAzureRbac
    Passed through to Build-CloudAdminReview.ps1. Skip Azure RBAC collection;
    Azure-RBAC-Admins.csv is still written, with headers only.

.PARAMETER SkipAclCheck
    Passed through to Build-OnPremAdminReview.ps1. Skip the delegated-ACL scan
    (GenericAll/WriteDacl/WriteOwner/DCSync-etc. on privileged objects) -
    the costliest part of that script for a large admin population.

.PARAMETER SkipGpoCheck
    Passed through to Build-OnPremAdminReview.ps1. Skip only the GPO-permission
    part of the ACL scan.

.PARAMETER DelegatedGroupPattern
    Passed through to Build-OnPremAdminReview.ps1 -DelegatedGroupPattern.

.PARAMETER SafePrincipals
    Passed through to Build-OnPremAdminReview.ps1 -SafePrincipals.

.PARAMETER Tier0OUs
    Passed through to Build-OnPremAdminReview.ps1 -Tier0OUs.

.PARAMETER UseTenantScope
    Passed through to Build-CloudAdminReview.ps1 -UseTenantScope.

.PARAMETER SyncWorkbookPath
    Path to Privileged_Access_Review.xlsx (or wherever your copy lives). When
    given, runs Sync-AdminReviewWorkbook.ps1 as stage 6 after everything else
    finishes, writing this run's CSVs into the workbook's tabs. Omit to skip
    stage 6 entirely (the default) and keep pasting by hand.

.PARAMETER NoWorkbookBackup
    Passed through to Sync-AdminReviewWorkbook.ps1 -NoBackup. Has no effect
    unless -SyncWorkbookPath is also given. Not recommended - see that
    script's own docstring for why.

.PARAMETER ContinueOnError
    Report a failed stage and continue to the next one instead of stopping the
    whole pipeline. Off by default - see .DESCRIPTION for why stopping is the
    safer default here.

.EXAMPLE
    .\Invoke-AdminReviewPipeline.ps1 -StandardAccountDomain 'corp.com.au'

    Full run against the whole domain and tenant, output alongside this script.

.EXAMPLE
    .\Invoke-AdminReviewPipeline.ps1 -StandardAccountDomain 'corp.com.au' -OutputDirectory '.\2026-09-01'

    Full run, output into a dated subfolder.

.EXAMPLE
    .\Invoke-AdminReviewPipeline.ps1 -StandardAccountDomain 'corp.com.au' -SkipCloudBuild

    Reuse an existing cloud export from earlier today, but refresh everything
    on the AD side and re-merge.

.NOTES
    Requires, for the stages actually run: the ActiveDirectory module (RSAT) and
    domain access for stages 1 and 4; Microsoft.Graph and (unless -SkipAzureRbac)
    Az.ResourceGraph, plus an interactive Connect-MgGraph / Connect-AzAccount,
    for stages 2 and 5. Connects once per provider, up front, with the union of
    scopes every stage that will run needs - not per-stage - so a stage doesn't
    silently run under a narrower scope left over from a previous session.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = '.',
    [string]$Server,
    [string]$StandardAccountDomain,

    [switch]$SkipOnPremBuild,
    [switch]$SkipCloudBuild,
    [switch]$SkipAdRefresh,
    [switch]$SkipEntraReconcile,

    [switch]$SkipAzureRbac,
    [switch]$SkipAclCheck,
    [switch]$SkipGpoCheck,
    [string]$DelegatedGroupPattern,
    [string[]]$SafePrincipals,
    [string[]]$Tier0OUs,
    [switch]$UseTenantScope,

    [string]$SyncWorkbookPath,
    [switch]$NoWorkbookBackup,

    [switch]$ContinueOnError
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# Validate the stage combination before touching AD/Graph/Az. Stage 5 cannot
# do anything meaningful without stage 4's output - Update-AdminPeopleEntra.ps1
# throws outright on a missing 'AD Account Active' column, and Merge-AdminReview.ps1
# never carries that column forward on its own (it rebuilds Admin-People.csv from
# the six input CSVs each run, none of which have it).
# --------------------------------------------------------------------------
if ($SkipAdRefresh -and -not $SkipEntraReconcile) {
    Write-Warning "-SkipAdRefresh skips the 'AD Account Active' column Update-AdminPeopleEntra.ps1 requires - forcing -SkipEntraReconcile too."
    $SkipEntraReconcile = $true
}
if ($SkipOnPremBuild -and $SkipCloudBuild) {
    throw "-SkipOnPremBuild and -SkipCloudBuild together skip both build stages - Merge-AdminReview.ps1 would have nothing to merge. Drop one of these switches, or run the individual scripts yourself if you really want neither."
}
if ($SyncWorkbookPath) {
    if (-not (Test-Path $SyncWorkbookPath)) { throw "-SyncWorkbookPath '$SyncWorkbookPath' not found." }
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) { throw "ImportExcel module not found, but -SyncWorkbookPath was given. Install-Module ImportExcel -Scope CurrentUser" }
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
function Script([string]$Name) { Join-Path $root $Name }

# Admin-People.csv's column count depends on which of stages 4/5 actually ran
# (-SkipAdRefresh forces -SkipEntraReconcile too, so 22/24/26 are the only
# possible totals) - used below to tell a manual-paste reviewer the right
# column letter instead of a number that's only correct for a full run.
function ConvertTo-ColumnLetter([int]$Number) {
    $letters = ''
    while ($Number -gt 0) {
        $rem = ($Number - 1) % 26
        $letters = [char](65 + $rem) + $letters
        $Number = [int](($Number - $rem - 1) / 26)
    }
    return $letters
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
function OutPath([string]$Name) { Join-Path $OutputDirectory $Name }

# Fixed filenames, not parameterised further - every stage after the first two
# needs to agree on exactly where each CSV landed, and that agreement is the
# entire point of this script existing.
$onPremAdminsPath   = OutPath 'OnPrem-Admins.csv'
$normalUsersPath    = OutPath 'Normal-Users.csv'
$onPremAclPath      = OutPath 'OnPrem-DelegatedAccess.csv'
$cloudAccountsPath  = OutPath 'Cloud-Admin-Accounts.csv'
$entraAdminsPath    = OutPath 'Entra-Admins.csv'
$azureRbacPath      = OutPath 'Azure-RBAC-Admins.csv'
$normalCloudPath    = OutPath 'Normal-CloudUsers.csv'
$adminPeoplePath    = OutPath 'Admin-People.csv'

Write-Host "Output directory: $OutputDirectory" -ForegroundColor Cyan

# --------------------------------------------------------------------------
# Connect once, up front, with the union of scopes every stage that will
# actually run needs - not lazily per stage. Build-CloudAdminReview.ps1 and
# Update-AdminPeopleEntra.ps1 each assume a connection already exists (the
# latter never calls Connect-MgGraph itself); connecting here, once, means
# stage 5 doesn't inherit a narrower scope left over from some earlier session
# and doesn't silently fail to connect at all when -SkipCloudBuild skips the
# stage that would otherwise have connected for it.
# --------------------------------------------------------------------------
$needsGraph = (-not $SkipCloudBuild) -or (-not $SkipEntraReconcile)
$needsAz    = (-not $SkipCloudBuild) -and (-not $SkipAzureRbac)

if ($needsGraph) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph module not available, but a cloud stage needs it. Install it, or pass -SkipCloudBuild -SkipEntraReconcile to skip both Graph-dependent stages."
    }
    if (-not (Get-MgContext)) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All','Group.Read.All' | Out-Null
    }
}
if ($needsAz) {
    if (-not (Get-Module -ListAvailable -Name Az.ResourceGraph)) {
        Write-Warning "Az.ResourceGraph not installed - Build-CloudAdminReview.ps1 will skip Azure RBAC collection on its own. Install-Module Az.ResourceGraph, or pass -SkipAzureRbac to silence this."
    } elseif (-not (Get-AzContext)) {
        Write-Host "Connecting to Azure..." -ForegroundColor Cyan
        Connect-AzAccount | Out-Null
    }
}

# --------------------------------------------------------------------------
# Stage runner: prints a banner, times the stage, and either stops the whole
# pipeline or records the failure and moves on, per -ContinueOnError.
# --------------------------------------------------------------------------
$stageResults = [System.Collections.Generic.List[object]]::new()
$pipelineStart = Get-Date

function Invoke-Stage {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][hashtable]$Arguments
    )
    Write-Host "`n========== $Name ==========" -ForegroundColor Magenta
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $ScriptPath @Arguments
        $sw.Stop()
        $stageResults.Add([PSCustomObject]@{ Stage = $Name; Status = 'OK'; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
        Write-Host "---------- $Name completed in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s ----------" -ForegroundColor Magenta
    } catch {
        $sw.Stop()
        $stageResults.Add([PSCustomObject]@{ Stage = $Name; Status = "FAILED: $($_.Exception.Message)"; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
        Write-Host "---------- $Name FAILED after $([math]::Round($sw.Elapsed.TotalSeconds, 1))s ----------" -ForegroundColor Red
        if ($ContinueOnError) {
            Write-Warning "$Name failed: $($_.Exception.Message)`nContinuing to the next stage (-ContinueOnError) - downstream output may be built on stale or missing data from this stage."
        } else {
            Write-Host "`nPipeline stopped. Re-run with -ContinueOnError to push through failures instead (see .DESCRIPTION for the tradeoff)." -ForegroundColor Red
            throw
        }
    }
}

# --------------------------------------------------------------------------
# 1. Build-OnPremAdminReview.ps1
# --------------------------------------------------------------------------
if (-not $SkipOnPremBuild) {
    $args1 = @{
        OutputPath            = $onPremAdminsPath
        NormalUsersOutputPath = $normalUsersPath
        AclOutputPath         = $onPremAclPath
    }
    if ($Server)                { $args1.Server = $Server }
    if ($DelegatedGroupPattern) { $args1.DelegatedGroupPattern = $DelegatedGroupPattern }
    if ($SkipAclCheck)          { $args1.SkipAclCheck = $true }
    if ($SafePrincipals)        { $args1.SafePrincipals = $SafePrincipals }
    if ($SkipGpoCheck)          { $args1.SkipGpoCheck = $true }
    if ($Tier0OUs)               { $args1.Tier0OUs = $Tier0OUs }
    Invoke-Stage -Name '1. Build-OnPremAdminReview' -ScriptPath (Script 'Build-OnPremAdminReview.ps1') -Arguments $args1
} else {
    Write-Host "`nSkipping stage 1 (Build-OnPremAdminReview) - reusing $onPremAdminsPath if present." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 2. Build-CloudAdminReview.ps1
# --------------------------------------------------------------------------
if (-not $SkipCloudBuild) {
    $args2 = @{
        CloudAccountsOutputPath = $cloudAccountsPath
        EntraOutputPath         = $entraAdminsPath
        AzureRbacOutputPath     = $azureRbacPath
        NormalUsersOutputPath   = $normalCloudPath
    }
    if ($StandardAccountDomain) { $args2.StandardAccountDomain = $StandardAccountDomain }
    if ($SkipAzureRbac)         { $args2.SkipAzureRbac = $true }
    if ($UseTenantScope)        { $args2.UseTenantScope = $true }
    Invoke-Stage -Name '2. Build-CloudAdminReview' -ScriptPath (Script 'Build-CloudAdminReview.ps1') -Arguments $args2
} else {
    Write-Host "`nSkipping stage 2 (Build-CloudAdminReview) - reusing cloud CSVs in $OutputDirectory if present." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 3. Merge-AdminReview.ps1 - always runs. Handles a missing input CSV with a
# warning and 'Unknown'/'No' fallbacks on its own; it only hard-fails if
# BOTH Cloud-Admin-Accounts.csv and OnPrem-Admins.csv are absent, which the
# -SkipOnPremBuild/-SkipCloudBuild guard above already prevents as a combination.
# --------------------------------------------------------------------------
$args3 = @{
    CloudAccountsPath = $cloudAccountsPath
    EntraPath         = $entraAdminsPath
    AzureRbacPath     = $azureRbacPath
    OnPremPath        = $onPremAdminsPath
    NormalOnPremPath  = $normalUsersPath
    NormalCloudPath   = $normalCloudPath
    OutputPath        = $adminPeoplePath
}
Invoke-Stage -Name '3. Merge-AdminReview' -ScriptPath (Script 'Merge-AdminReview.ps1') -Arguments $args3

# --------------------------------------------------------------------------
# 4. Update-AdminPeopleAD.ps1
# --------------------------------------------------------------------------
if (-not $SkipAdRefresh) {
    $args4 = @{ AdminPeoplePath = $adminPeoplePath }
    if ($Server) { $args4.Server = $Server }
    Invoke-Stage -Name '4. Update-AdminPeopleAD' -ScriptPath (Script 'Update-AdminPeopleAD.ps1') -Arguments $args4
} else {
    Write-Host "`nSkipping stage 4 (Update-AdminPeopleAD)." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 5. Update-AdminPeopleEntra.ps1
# --------------------------------------------------------------------------
if (-not $SkipEntraReconcile) {
    $args5 = @{ AdminPeoplePath = $adminPeoplePath }
    if ($StandardAccountDomain) { $args5.StandardAccountDomain = $StandardAccountDomain }
    Invoke-Stage -Name '5. Update-AdminPeopleEntra' -ScriptPath (Script 'Update-AdminPeopleEntra.ps1') -Arguments $args5
} else {
    Write-Host "`nSkipping stage 5 (Update-AdminPeopleEntra)." -ForegroundColor Yellow
}

# --------------------------------------------------------------------------
# 6. Sync-AdminReviewWorkbook.ps1 - opt-in only. Unlike stages 1-5, this one
# writes into a file that carries real reviewer work (once the workbook has
# been used for a real review) - it isn't run unless -SyncWorkbookPath is
# explicitly given.
# --------------------------------------------------------------------------
if ($SyncWorkbookPath) {
    $args6 = @{
        WorkbookPath      = $SyncWorkbookPath
        AdminPeoplePath   = $adminPeoplePath
        CloudAccountsPath = $cloudAccountsPath
        EntraPath         = $entraAdminsPath
        AzureRbacPath     = $azureRbacPath
        OnPremPath        = $onPremAdminsPath
    }
    if ($NoWorkbookBackup) { $args6.NoBackup = $true }
    Invoke-Stage -Name '6. Sync-AdminReviewWorkbook' -ScriptPath (Script 'Sync-AdminReviewWorkbook.ps1') -Arguments $args6
}

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
$totalSeconds = [math]::Round(((Get-Date) - $pipelineStart).TotalSeconds, 1)
Write-Host "`n========== Pipeline summary ($totalSeconds`s total) ==========" -ForegroundColor Cyan
foreach ($r in $stageResults) {
    $color = if ($r.Status -eq 'OK') { 'Green' } else { 'Red' }
    Write-Host ("  {0,-30} {1,8}s  {2}" -f $r.Stage, $r.Seconds, $r.Status) -ForegroundColor $color
}

$failed = @($stageResults | Where-Object { $_.Status -ne 'OK' })
if ($failed.Count) {
    Write-Host "`n$($failed.Count) stage(s) failed. Admin-People.csv may be missing, stale, or built on partial data - check the stage output above before pasting into the workbook." -ForegroundColor Red
} else {
    if ($SyncWorkbookPath) {
        Write-Host "`nAll stages completed. $adminPeoplePath and the other CSVs were already written into $SyncWorkbookPath by stage 6 - no manual paste needed." -ForegroundColor Green
    } else {
        $peopleCols = 22
        if (-not $SkipAdRefresh)      { $peopleCols += 2 }
        if (-not $SkipEntraReconcile) { $peopleCols += 2 }
        Write-Host "`nAll stages completed. Paste $adminPeoplePath into the 'People' tab at cell A2 (columns A-$(ConvertTo-ColumnLetter $peopleCols))." -ForegroundColor Green
        Write-Host "See each stage's own '`nWritten to ...' output above for the other CSVs and their target tabs." -ForegroundColor Cyan
    }
}

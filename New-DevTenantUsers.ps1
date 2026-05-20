#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Bulk creates dummy Entra ID users for a development tenancy, simulating an
    Australian government agency: Department of Digital Services (DDS).

.DESCRIPTION
    Creates the following user categories:
      1. Standard end users  (executive, ICT, policy, finance, comms, remote)
      2. Privileged / specialist users  (break-glass, service accounts,
         shared accounts, contractors, PAW accounts, partner liaison)
      3. Administrator personas  (20 distinct Entra / M365 admin roles)
      4. Disabled / offboarded user  (for lifecycle workflow testing)

    ALL accounts are created with:
      Password               : PUcGB2x%fV@v4NA9*@ZBNru5*Gwe%8%F
      PasswordNeverExpires   : true  (set via Update-MgUser after creation)
      ForceChangePassword    : false
      Domain                 : certificationswredmond.onmicrosoft.com
      UsageLocation / Country: AU / Australia

.PREREQUISITES
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
    Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory"

.NOTES
    FOR DEVELOPMENT / LAB USE ONLY.
    Never deploy these credentials or accounts in a production environment.
#>

[CmdletBinding(SupportsShouldProcess)]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"   # log errors but keep running

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
$Domain        = "certificationswredmond.onmicrosoft.com"
$PlainPassword = "PUcGB2x%fV@v4NA9*@ZBNru5*Gwe%8%F"
$UsageLocation = "AU"
$Agency        = "Department of Digital Services"

$PasswordProfile = @{
    Password                      = $PlainPassword
    ForceChangePasswordNextSignIn = $false
}

# Track results for the summary table
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

# ──────────────────────────────────────────────────────────────────────────────
# HELPER: Create a single user and return the MgUser object
# ──────────────────────────────────────────────────────────────────────────────
function New-TenantUser {
    param (
        [string] $GivenName,
        [string] $Surname,
        [string] $UPNPrefix,
        [string] $JobTitle,
        [string] $Department,
        [string] $OfficeLocation,
        [string] $MobilePhone    = "+61 2 6100 0000",
        [bool]   $AccountEnabled = $true
    )

    $DisplayName  = "$GivenName $Surname"
    $UPN          = "$UPNPrefix@$Domain"
    $MailNickname = $UPNPrefix -replace "[^a-zA-Z0-9._-]", ""   # sanitise

    Write-Host "  Creating: $DisplayName  [$UPN]" -ForegroundColor Cyan

    $params = @{
        DisplayName       = $DisplayName
        GivenName         = $GivenName
        Surname           = $Surname
        UserPrincipalName = $UPN
        MailNickname      = $MailNickname
        JobTitle          = $JobTitle
        Department        = $Department
        OfficeLocation    = $OfficeLocation
        MobilePhone       = $MobilePhone
        CompanyName       = $Agency
        UsageLocation     = $UsageLocation
        AccountEnabled    = $AccountEnabled
        PasswordProfile   = $PasswordProfile
        City              = "Canberra"
        State             = "Australian Capital Territory"
        Country           = "Australia"
        PostalCode        = "2600"
    }

    try {
        $user = New-MgUser @params -ErrorAction Stop

        # Set password to never expire (requires separate PATCH call)
        Update-MgUser -UserId $user.Id -PasswordPolicies "DisablePasswordExpiration" -ErrorAction SilentlyContinue

        Write-Host "    OK" -ForegroundColor Green
        $script:Results.Add([PSCustomObject]@{
            DisplayName = $DisplayName
            UPN         = $UPN
            Department  = $Department
            JobTitle    = $JobTitle
            Enabled     = $AccountEnabled
            AdminRole   = "-"
            Status      = "Created"
        })
        return $user
    }
    catch {
        Write-Warning "    FAILED: $_"
        $script:Results.Add([PSCustomObject]@{
            DisplayName = $DisplayName
            UPN         = $UPN
            Department  = $Department
            JobTitle    = $JobTitle
            Enabled     = $AccountEnabled
            AdminRole   = "-"
            Status      = "FAILED: $_"
        })
        return $null
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# HELPER: Assign a built-in directory role by displayName
# ──────────────────────────────────────────────────────────────────────────────
function Add-DirectoryRole {
    param (
        [string] $UserId,
        [string] $RoleDisplayName
    )

    $template = Get-MgDirectoryRoleTemplate -All |
        Where-Object { $_.DisplayName -eq $RoleDisplayName }

    if (-not $template) {
        Write-Warning "    Role template not found: '$RoleDisplayName'"
        return
    }

    $role = Get-MgDirectoryRole -All |
        Where-Object { $_.DisplayName -eq $RoleDisplayName }

    if (-not $role) {
        try {
            $role = New-MgDirectoryRole -RoleTemplateId $template.Id -ErrorAction Stop
        }
        catch {
            Write-Warning "    Could not activate role '$RoleDisplayName': $_"
            return
        }
    }

    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
        } -ErrorAction Stop
        Write-Host "    Role assigned: $RoleDisplayName" -ForegroundColor Green

        # Update the last result entry's AdminRole field
        $last = $script:Results[$script:Results.Count - 1]
        if ($last) { $last.AdminRole = $RoleDisplayName }
    }
    catch {
        Write-Warning "    Role assignment failed for '$RoleDisplayName': $_"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# CONNECT TO MICROSOFT GRAPH
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  DDS Dev Tenancy - Bulk User Provisioning Script" -ForegroundColor Yellow
Write-Host "  Department of Digital Services (certificationswredmond)" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
Connect-MgGraph `
    -Scopes "User.ReadWrite.All","Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory" `
    -NoWelcome

Write-Host "Authenticated as: $((Get-MgContext).Account)" -ForegroundColor Green
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 -- STANDARD END USERS
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "--- SECTION 1: Standard End Users ---" -ForegroundColor Yellow

# -- 1A. Executive / Senior Leadership
Write-Host ""
Write-Host "[1A] Executive Leadership" -ForegroundColor Magenta

New-TenantUser -GivenName "Margaret" -Surname "Hollingsworth" -UPNPrefix "margaret.hollingsworth" `
    -JobTitle "Secretary" `
    -Department "Office of the Secretary" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "David" -Surname "Kearney" -UPNPrefix "david.kearney" `
    -JobTitle "Deputy Secretary, Digital Transformation" `
    -Department "Digital Transformation Group" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Priya" -Surname "Anantharaman" -UPNPrefix "priya.anantharaman" `
    -JobTitle "First Assistant Secretary, Cybersecurity" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "James" -Surname "Cartwright" -UPNPrefix "james.cartwright" `
    -JobTitle "Chief Financial Officer" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Leonie" -Surname "Turnbull" -UPNPrefix "leonie.turnbull" `
    -JobTitle "Chief People Officer" `
    -Department "People & Culture" -OfficeLocation "Canberra - Main Building"

# -- 1B. Information Technology
Write-Host ""
Write-Host "[1B] Information Technology" -ForegroundColor Magenta

New-TenantUser -GivenName "Samuel" -Surname "Fitzpatrick" -UPNPrefix "samuel.fitzpatrick" `
    -JobTitle "ICT Service Desk Analyst" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "Anh" -Surname "Nguyen" -UPNPrefix "anh.nguyen" `
    -JobTitle "Systems Engineer" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "Taryn" -Surname "McAllister" -UPNPrefix "taryn.mcallister" `
    -JobTitle "Network Engineer" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "Brendan" -Surname "Sorrell" -UPNPrefix "brendan.sorrell" `
    -JobTitle "Cybersecurity Analyst" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Fatima" -Surname "Al-Rashidi" -UPNPrefix "fatima.al-rashidi" `
    -JobTitle "Application Developer" `
    -Department "Digital Platforms" -OfficeLocation "Sydney - George St"

# -- 1C. Policy & Programs
Write-Host ""
Write-Host "[1C] Policy & Programs" -ForegroundColor Magenta

New-TenantUser -GivenName "William" -Surname "Brennan" -UPNPrefix "william.brennan" `
    -JobTitle "Director, Digital Policy" `
    -Department "Policy & Strategy" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Chloe" -Surname "Whitmore" -UPNPrefix "chloe.whitmore" `
    -JobTitle "Policy Adviser" `
    -Department "Policy & Strategy" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Rohan" -Surname "Mehta" -UPNPrefix "rohan.mehta" `
    -JobTitle "Program Manager" `
    -Department "Digital Transformation Group" -OfficeLocation "Melbourne - Collins St"

New-TenantUser -GivenName "Jessica" -Surname "O'Brien" -UPNPrefix "jessica.obrien" `
    -JobTitle "APS6 Policy Officer" `
    -Department "Policy & Strategy" -OfficeLocation "Canberra - Main Building"

# -- 1D. Finance & Procurement
Write-Host ""
Write-Host "[1D] Finance & Procurement" -ForegroundColor Magenta

New-TenantUser -GivenName "Tracey" -Surname "Dunbar" -UPNPrefix "tracey.dunbar" `
    -JobTitle "Finance Officer" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Michael" -Surname "Papadopoulos" -UPNPrefix "michael.papadopoulos" `
    -JobTitle "Procurement Specialist" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"

# -- 1E. People & Culture
Write-Host ""
Write-Host "[1E] People & Culture" -ForegroundColor Magenta

New-TenantUser -GivenName "Sandra" -Surname "Kowalski" -UPNPrefix "sandra.kowalski" `
    -JobTitle "HR Business Partner" `
    -Department "People & Culture" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Nathan" -Surname "Tremblay" -UPNPrefix "nathan.tremblay" `
    -JobTitle "Learning & Development Coordinator" `
    -Department "People & Culture" -OfficeLocation "Canberra - Main Building"

# -- 1F. Communications & Media
Write-Host ""
Write-Host "[1F] Communications & Media" -ForegroundColor Magenta

New-TenantUser -GivenName "Eloise" -Surname "Henderson" -UPNPrefix "eloise.henderson" `
    -JobTitle "Media Adviser" `
    -Department "Communications" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "Marcus" -Surname "Yuen" -UPNPrefix "marcus.yuen" `
    -JobTitle "Web Content Officer" `
    -Department "Communications" -OfficeLocation "Sydney - George St"

# -- 1G. Remote / Distributed Staff
Write-Host ""
Write-Host "[1G] Remote / Distributed Staff" -ForegroundColor Magenta

New-TenantUser -GivenName "Kerry" -Surname "Blackwood" -UPNPrefix "kerry.blackwood" `
    -JobTitle "APS4 Administrative Officer" `
    -Department "Operations" -OfficeLocation "Brisbane - Remote"

New-TenantUser -GivenName "Dylan" -Surname "Watkins" -UPNPrefix "dylan.watkins" `
    -JobTitle "Stakeholder Engagement Officer" `
    -Department "Policy & Strategy" -OfficeLocation "Perth - St Georges Tce"

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 -- PRIVILEGED / SPECIALIST USER TYPES
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "--- SECTION 2: Privileged / Specialist Users ---" -ForegroundColor Yellow

# -- 2A. Break-Glass Emergency Account (disabled by default)
Write-Host ""
Write-Host "[2A] Break-Glass Account (created DISABLED)" -ForegroundColor Magenta

New-TenantUser -GivenName "BreakGlass" -Surname "Emergency" -UPNPrefix "breakglass.emergency" `
    -JobTitle "Emergency Access Account - Enable only in declared emergency" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex" `
    -AccountEnabled $false

# -- 2B. Service / Application Accounts
Write-Host ""
Write-Host "[2B] Service Accounts" -ForegroundColor Magenta

New-TenantUser -GivenName "SVC" -Surname "AzureDevOps" -UPNPrefix "svc.azuredevops" `
    -JobTitle "Service Account - Azure DevOps Pipeline" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "SVC" -Surname "MDEOnboarding" -UPNPrefix "svc.mdeonboarding" `
    -JobTitle "Service Account - MDE Onboarding" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "SVC" -Surname "SIEMConnector" -UPNPrefix "svc.siemconnector" `
    -JobTitle "Service Account - Sentinel / SIEM Integration" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "SVC" -Surname "BackupAgent" -UPNPrefix "svc.backupagent" `
    -JobTitle "Service Account - Backup & Recovery Agent" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

# -- 2C. Shared / Functional Accounts
Write-Host ""
Write-Host "[2C] Shared / Functional Accounts" -ForegroundColor Magenta

New-TenantUser -GivenName "DDS" -Surname "ServiceDesk" -UPNPrefix "servicedesk" `
    -JobTitle "Shared - ICT Service Desk Inbox" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "DDS" -Surname "FOIRequests" -UPNPrefix "foi.requests" `
    -JobTitle "Shared - FOI Requests Inbox" `
    -Department "Legal & Governance" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "DDS" -Surname "MinCorrespondence" -UPNPrefix "ministerial.correspondence" `
    -JobTitle "Shared - Ministerial Correspondence" `
    -Department "Office of the Secretary" -OfficeLocation "Canberra - Main Building"

New-TenantUser -GivenName "DDS" -Surname "ProcurementInbox" -UPNPrefix "procurement.inbox" `
    -JobTitle "Shared - Procurement Inbox" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"

# -- 2D. External Contractor Accounts
Write-Host ""
Write-Host "[2D] Contractor Accounts (.ext suffix)" -ForegroundColor Magenta

New-TenantUser -GivenName "Oliver" -Surname "Vance" -UPNPrefix "oliver.vance.ext" `
    -JobTitle "Contractor - Cloud Infrastructure Engineer" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "Mei" -Surname "Zhou" -UPNPrefix "mei.zhou.ext" `
    -JobTitle "Contractor - Penetration Tester" `
    -Department "Cybersecurity Division" -OfficeLocation "Sydney - George St"

New-TenantUser -GivenName "Aaron" -Surname "Gallagher" -UPNPrefix "aaron.gallagher.ext" `
    -JobTitle "Contractor - Change Manager" `
    -Department "Digital Transformation Group" -OfficeLocation "Melbourne - Collins St"

# -- 2E. Partner / Interagency Liaison
Write-Host ""
Write-Host "[2E] Partner Agency Liaison" -ForegroundColor Magenta

New-TenantUser -GivenName "Sarah" -Surname "Connelly" -UPNPrefix "sarah.connelly.partner" `
    -JobTitle "ATO Liaison Officer (Partner Agency)" `
    -Department "Interagency Coordination" -OfficeLocation "Canberra - Main Building"

# -- 2F. PAW / Secondary Admin Accounts
Write-Host ""
Write-Host "[2F] Privileged Access Workstation (PAW) Accounts" -ForegroundColor Magenta

New-TenantUser -GivenName "PAW" -Surname "SFitzpatrick" -UPNPrefix "adm.samuel.fitzpatrick" `
    -JobTitle "PAW Account - ICT Operations (S. Fitzpatrick)" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

New-TenantUser -GivenName "PAW" -Surname "ANguyen" -UPNPrefix "adm.anh.nguyen" `
    -JobTitle "PAW Account - Systems Engineer (A. Nguyen)" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"

# -- 2G. Kiosk / Shared Device Account
Write-Host ""
Write-Host "[2G] Kiosk / Shared Device Account" -ForegroundColor Magenta

New-TenantUser -GivenName "Kiosk" -Surname "ReceptionACT" -UPNPrefix "kiosk.reception.act" `
    -JobTitle "Kiosk - Canberra Reception Lobby" `
    -Department "Operations" -OfficeLocation "Canberra - Main Building"

# -- 2H. Disabled / Offboarded
Write-Host ""
Write-Host "[2H] Offboarded / Disabled User" -ForegroundColor Magenta

New-TenantUser -GivenName "Robert" -Surname "Quigley" -UPNPrefix "robert.quigley" `
    -JobTitle "Former APS5 Policy Officer (Offboarded)" `
    -Department "Policy & Strategy" -OfficeLocation "Canberra - Main Building" `
    -AccountEnabled $false

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 -- ADMINISTRATOR PERSONAS (with Entra role assignments)
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "--- SECTION 3: Administrator Personas ---" -ForegroundColor Yellow
Write-Host "(Dedicated admin accounts following least-privilege / PAW best practice)" -ForegroundColor DarkGray

# -- 3A. Global Administrator
Write-Host ""; Write-Host "[3A] Global Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Rachel" -Surname "Drummond" -UPNPrefix "rachel.drummond.ga" `
    -JobTitle "Global Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Global Administrator" }

# -- 3B. Global Reader
Write-Host ""; Write-Host "[3B] Global Reader" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Thomas" -Surname "Abernethy" -UPNPrefix "thomas.abernethy.gr" `
    -JobTitle "Global Reader (Audit & Assurance)" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Global Reader" }

# -- 3C. Security Administrator
Write-Host ""; Write-Host "[3C] Security Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Liam" -Surname "Okonkwo" -UPNPrefix "liam.okonkwo.secadm" `
    -JobTitle "Security Administrator" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Security Administrator" }

# -- 3D. Security Reader
Write-Host ""; Write-Host "[3D] Security Reader" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Natasha" -Surname "Perkins" -UPNPrefix "natasha.perkins.secr" `
    -JobTitle "Security Reader (SOC Analyst L2)" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Security Reader" }

# -- 3E. Conditional Access Administrator
Write-Host ""; Write-Host "[3E] Conditional Access Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Grace" -Surname "Sutherland" -UPNPrefix "grace.sutherland.caadm" `
    -JobTitle "Conditional Access Administrator" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Conditional Access Administrator" }

# -- 3F. Intune Administrator
Write-Host ""; Write-Host "[3F] Intune / Endpoint Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Peter" -Surname "Laverty" -UPNPrefix "peter.laverty.intuneadm" `
    -JobTitle "Intune / Endpoint Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Intune Administrator" }

# -- 3G. Exchange Administrator
Write-Host ""; Write-Host "[3G] Exchange Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Deborah" -Surname "Langley" -UPNPrefix "deborah.langley.exoadm" `
    -JobTitle "Exchange Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Exchange Administrator" }

# -- 3H. SharePoint Administrator
Write-Host ""; Write-Host "[3H] SharePoint Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Julian" -Surname "Massey" -UPNPrefix "julian.massey.spadm" `
    -JobTitle "SharePoint Administrator" `
    -Department "Digital Platforms" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "SharePoint Administrator" }

# -- 3I. Teams Administrator
Write-Host ""; Write-Host "[3I] Teams Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Monique" -Surname "Arsenault" -UPNPrefix "monique.arsenault.teamsadm" `
    -JobTitle "Teams Administrator" `
    -Department "ICT Operations" -OfficeLocation "Melbourne - Collins St"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Teams Administrator" }

# -- 3J. User Administrator
Write-Host ""; Write-Host "[3J] User Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Craig" -Surname "Moffat" -UPNPrefix "craig.moffat.useradm" `
    -JobTitle "User Administrator (Identity & Access)" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "User Administrator" }

# -- 3K. Privileged Role Administrator
Write-Host ""; Write-Host "[3K] Privileged Role Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Isabella" -Surname "Rafferty" -UPNPrefix "isabella.rafferty.pradm" `
    -JobTitle "Privileged Role Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Privileged Role Administrator" }

# -- 3L. Privileged Authentication Administrator
Write-Host ""; Write-Host "[3L] Privileged Authentication Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Connor" -Surname "Bateman" -UPNPrefix "connor.bateman.authadm" `
    -JobTitle "Privileged Authentication Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Privileged Authentication Administrator" }

# -- 3M. Compliance Administrator
Write-Host ""; Write-Host "[3M] Compliance Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Veronica" -Surname "Alderton" -UPNPrefix "veronica.alderton.compadm" `
    -JobTitle "Compliance Administrator" `
    -Department "Legal & Governance" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Compliance Administrator" }

# -- 3N. Billing Administrator
Write-Host ""; Write-Host "[3N] Billing Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Anthony" -Surname "Dressler" -UPNPrefix "anthony.dressler.billadm" `
    -JobTitle "Billing Administrator" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Billing Administrator" }

# -- 3O. Application Administrator
Write-Host ""; Write-Host "[3O] Application Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Zoe" -Surname "Stanton" -UPNPrefix "zoe.stanton.appadm" `
    -JobTitle "Application Administrator" `
    -Department "Digital Platforms" -OfficeLocation "Sydney - George St"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Application Administrator" }

# -- 3P. Cloud Device Administrator
Write-Host ""; Write-Host "[3P] Cloud Device Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Harrison" -Surname "Vella" -UPNPrefix "harrison.vella.deviceadm" `
    -JobTitle "Cloud Device Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Cloud Device Administrator" }

# -- 3Q. Helpdesk Administrator
Write-Host ""; Write-Host "[3Q] Helpdesk Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Amy" -Surname "Lindqvist" -UPNPrefix "amy.lindqvist.helpdeskadm" `
    -JobTitle "Helpdesk Administrator (Level 2)" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Helpdesk Administrator" }

# -- 3R. Reports Reader
Write-Host ""; Write-Host "[3R] Reports Reader" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Ian" -Surname "Forrester" -UPNPrefix "ian.forrester.reportsr" `
    -JobTitle "Reports Reader (Analytics & Governance)" `
    -Department "Finance & Assurance" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Reports Reader" }

# -- 3S. Attack Simulation Administrator
Write-Host ""; Write-Host "[3S] Attack Simulation Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Stephanie" -Surname "Hawkins" -UPNPrefix "stephanie.hawkins.attacksimadm" `
    -JobTitle "Attack Simulation Administrator" `
    -Department "Cybersecurity Division" -OfficeLocation "Canberra - Main Building"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Attack Simulation Administrator" }

# -- 3T. Azure AD Joined Device Local Administrator
Write-Host ""; Write-Host "[3T] Azure AD Joined Device Local Administrator" -ForegroundColor Magenta
$u = New-TenantUser -GivenName "Fletcher" -Surname "Noonan" -UPNPrefix "fletcher.noonan.localadm" `
    -JobTitle "Device Local Administrator" `
    -Department "ICT Operations" -OfficeLocation "Canberra - Data Centre Annex"
if ($u) { Add-DirectoryRole -UserId $u.Id -RoleDisplayName "Azure AD Joined Device Local Administrator" }

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  PROVISIONING SUMMARY" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow

$created = $Results | Where-Object { $_.Status -eq "Created" }
$failed  = $Results | Where-Object { $_.Status -ne "Created" }

Write-Host "  Total processed : $($Results.Count)" -ForegroundColor White
Write-Host "  Created OK      : $($created.Count)" -ForegroundColor Green

if ($failed.Count -gt 0) {
    Write-Host "  Failed          : $($failed.Count)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Failed accounts:" -ForegroundColor Red
    $failed | ForEach-Object {
        Write-Host "    - $($_.UPN)  => $($_.Status)" -ForegroundColor Red
    }
} else {
    Write-Host "  Failed          : 0" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Full results:"
$Results | Format-Table DisplayName, UPN, Department, Enabled, AdminRole, Status -AutoSize

Write-Host ""
Write-Host "  IMPORTANT: Disconnect your Graph session when done:" -ForegroundColor Red
Write-Host "  Disconnect-MgGraph" -ForegroundColor Red
Write-Host ""

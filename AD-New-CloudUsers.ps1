# ============================================================
# New-CloudUsers.ps1
# Creates the "Cloud Users" OU structure and 20 AD users
# 15 Staff + 5 Administrators under redserver.local
#
# Run this on your Domain Controller as a Domain Admin.
# ============================================================

#Requires -Module ActiveDirectory

# ── Configuration ────────────────────────────────────────────
$DomainDN      = (Get-ADDomain).DistinguishedName   # e.g. DC=redserver,DC=local
$EmailDomain   = "redserver.local"
$StaffPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
$AdminPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

# ── OU Paths ─────────────────────────────────────────────────
$CloudUsersOU = "OU=Cloud Users,$DomainDN"
$StaffOU      = "OU=Staff,$CloudUsersOU"
$AdminOU      = "OU=Administrators,$CloudUsersOU"

# ── User Data ────────────────────────────────────────────────
# 15 Staff users
$StaffUsers = @(
    @{ First = "Alice";   Last = "Barclay"   }
    @{ First = "Brian";   Last = "Chambers"  }
    @{ First = "Claire";  Last = "Davidson"  }
    @{ First = "Daniel";  Last = "Edwards"   }
    @{ First = "Emma";    Last = "Fletcher"  }
    @{ First = "Frank";   Last = "Gibson"    }
    @{ First = "Grace";   Last = "Harris"    }
    @{ First = "Henry";   Last = "Ingram"    }
    @{ First = "Isabel";  Last = "Jenkins"   }
    @{ First = "James";   Last = "Knight"    }
    @{ First = "Karen";   Last = "Lawson"    }
    @{ First = "Liam";    Last = "Morton"    }
    @{ First = "Megan";   Last = "Nash"      }
    @{ First = "Nathan";  Last = "Osbourne"  }
    @{ First = "Olivia";  Last = "Pearce"    }
)

# 5 Administrator users
$AdminUsers = @(
    @{ First = "Peter";   Last = "Quinn"     }
    @{ First = "Rachel";  Last = "Robbins"   }
    @{ First = "Samuel";  Last = "Stone"     }
    @{ First = "Tara";    Last = "Turner"    }
    @{ First = "Victor";  Last = "Walsh"     }
)

# ── Helper: Create OU if it doesn't already exist ────────────
function New-OUIfNotExists {
    param (
        [string]$Name,
        [string]$Path
    )
    $fullDN = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$fullDN'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
        Write-Host "[+] Created OU: $fullDN" -ForegroundColor Green
    } else {
        Write-Host "[~] OU already exists, skipping: $fullDN" -ForegroundColor Yellow
    }
}

# ── Helper: Create AD User ────────────────────────────────────
function New-CloudADUser {
    param (
        [string]$FirstName,
        [string]$LastName,
        [string]$SamAccountName,
        [string]$UPN,
        [string]$Email,
        [string]$OUPath,
        [string]$Description,
        [securestring]$Password
    )

    if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
        Write-Host "[~] User already exists, skipping: $SamAccountName" -ForegroundColor Yellow
        return
    }

    New-ADUser `
        -Name            "$FirstName $LastName" `
        -GivenName       $FirstName `
        -Surname         $LastName `
        -SamAccountName  $SamAccountName `
        -UserPrincipalName $UPN `
        -EmailAddress    $Email `
        -Description     $Description `
        -Path            $OUPath `
        -AccountPassword $Password `
        -Enabled         $true `
        -PasswordNeverExpires $false `
        -ChangePasswordAtLogon $true

    Write-Host "[+] Created user: $SamAccountName ($Email)" -ForegroundColor Cyan
}

# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

Write-Host "`n=== Setting up Cloud Users OU structure ===" -ForegroundColor Magenta

# 1. Create parent and child OUs
New-OUIfNotExists -Name "Cloud Users"     -Path $DomainDN
New-OUIfNotExists -Name "Staff"           -Path $CloudUsersOU
New-OUIfNotExists -Name "Administrators"  -Path $CloudUsersOU

# 2. Create Staff users
Write-Host "`n=== Creating Staff users ===" -ForegroundColor Magenta

foreach ($user in $StaffUsers) {
    $sam   = ($user.First.Substring(0,1) + $user.Last).ToLower()   # e.g. jsmith
    $upn   = "$sam@$EmailDomain"
    $email = "$sam@$EmailDomain"

    New-CloudADUser `
        -FirstName      $user.First `
        -LastName       $user.Last `
        -SamAccountName $sam `
        -UPN            $upn `
        -Email          $email `
        -OUPath         $StaffOU `
        -Description    "Staff Account" `
        -Password       $StaffPassword
}

# 3. Create Administrator users
Write-Host "`n=== Creating Administrator users ===" -ForegroundColor Magenta

foreach ($user in $AdminUsers) {
    $sam   = "a_" + ($user.First.Substring(0,1) + $user.Last).ToLower()   # e.g. a_jsmith
    $upn   = "$sam@$EmailDomain"
    $email = "$sam@$EmailDomain"

    New-CloudADUser `
        -FirstName      $user.First `
        -LastName       $user.Last `
        -SamAccountName $sam `
        -UPN            $upn `
        -Email          $email `
        -OUPath         $AdminOU `
        -Description    "Administrator Account" `
        -Password       $AdminPassword
}

Write-Host "`n=== Done! 20 users created under Cloud Users ===`n" -ForegroundColor Green

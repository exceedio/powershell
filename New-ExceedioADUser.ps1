#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS

    Creates a new Active Directory user

.DESCRIPTION

    Designed to streamline user adds in an ADSync-enabled Active Directory environment. There are
    numerous assumptions that are made, including expectations about license assignment 


    Text banner created at https://manytools.org/hacker-tools/ascii-banner/ using DOS Rebel font.

.PARAMETER Username

    The desired username for the new user account. Will be checked against Active Directory
    to ensure that it is available at the time the script is run.

.PARAMETER UsernameOfManager

    The username of an existing Active Directory user account that corresponds with the
    Manager of the new user.

.PARAMETER UsernameOfSimilar

    The username of an existing Active Directory user account that has a similar job role
    or function as the new user. Group membership and potentially other attributes will be
    copied from this user account.

.PARAMETER Firstname

    The first (given) name of the new user.

.PARAMETER Lastname

    The last name of the new user.

.PARAMETER Department

    The department within the organization that the new user is a part of (optional).

.PARAMETER Title

    The job title of the new user (optional).

.PARAMETER Phone

    The office phone number of the new user (optional).

.PARAMETER Mobile

    The mobile phone number of the new user (optional).

.PARAMETER ConfigurationFile

    The JSON file that contains organization-specific information that is common
    to all users in an organization. Certain Active Directory account properties
    will be populated from this file. Also specifies the OU that the new user
    account should be created in, UPN suffix, domain controller name to operate
    on, and the name of the Azure AD Connect server.

    The file should be in the following format:

    {
        "Company": "Dunder Mifflin",
        "Address": "1725 Slough Avenue, Suite 200",
        "City": "Scranton",
        "State": "PA",
        "Postal": "18501",
        "Country": "US",
        "OUPath": "OU=Users,OU=Business,DC=dundermifflin,DC=com",
        "UPNSuffix": "dundermifflin.com",
        "ADServer": "dc1.dundermifflin.com",
        "AzureADConnectServer": "dc1.dundermifflin.com",
        "UserFolderUNCPath": "\\\\dc1.dundermifflin.com\\Users",
        "DefaultGroups": [
            "Security Group 1",
            "Security Group 2"
        ]
    }

.NOTES

    Filename : New-ExceedioADUser.ps1
    Author   : jreese@exceedio.com
    Modified : Aug, 15, 2023

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory, HelpMessage = 'Desired username all lower case')]
    [string]
    $Username,
    [Parameter(Mandatory, HelpMessage = 'Username of the manager/supervisor of new user')]
    [string]
    $UsernameOfManager,
    [Parameter(Mandatory, HelpMessage = 'Username of an existing user who holds a similar job role/function as the new user')]
    [string]
    $UsernameOfSimilar,
    [Parameter(Mandatory, HelpMessage = 'First name of the new user')]
    [string]
    $Firstname,
    [Parameter(Mandatory, HelpMessage = 'Last name of the new user')]
    [string]
    $Lastname,
    [Parameter(Mandatory, HelpMessage = 'Department of the new user (e.g. Sales, Support)')]
    [string]
    $Department,
    [Parameter(Mandatory, HelpMessage = 'Job title of the new user (e.g. Director of Sales)')]
    [string]
    $Title,
    [Parameter(Mandatory, HelpMessage = 'Office phone number of the new user (e.g. 831-555-1212)')]
    [string]
    $Phone,
    [Parameter(Mandatory, HelpMessage = 'Mobile phone number of the new user (e.g. 831-555-1212) or leave blank')]
    [string]
    $Mobile,
    [Parameter()]
    [string]
    $ConfigurationFile = "$PSScriptRoot\New-ExceedioADUser.json"
)

class Configuration {

    [string]   $Company
    [string]   $Address
    [string]   $City
    [string]   $State
    [string]   $Postal
    [string]   $Country
    [string]   $OUPath
    [string]   $UPNSuffix
    [string]   $ADServer
    [string]   $AzureADConnectServer
    [string]   $UserFolderUNCPath
    [string[]] $DefaultGroups

    static [Configuration] Load([string] $filename) {
        $result = $null
        if (Test-Path $filename) {
            $result = [Configuration](Get-Content $filename | Out-String | ConvertFrom-Json)
            #Write-Host "[*] Configuration successfully loaded" -ForegroundColor Green
            #Write-Host "    Company............. $($configuration.Company)" -ForegroundColor DarkGray
            #Write-Host "    Address............. $($configuration.Address)" -ForegroundColor DarkGray
            #Write-Host "    City................ $($configuration.City)" -ForegroundColor DarkGray
            #Write-Host "    State............... $($configuration.State)" -ForegroundColor DarkGray
            #Write-Host "    Postal.............. $($configuration.Postal)" -ForegroundColor DarkGray
            #Write-Host "    Country............. $($configuration.Country)" -ForegroundColor DarkGray
            #Write-Host "    OUPath.............. $($configuration.OUPath)" -ForegroundColor DarkGray
            #Write-Host "    UPN suffix.......... $($configuration.UPNSuffix)" -ForegroundColor DarkGray
            #Write-Host "    AD server........... $($configuration.ADServer)" -ForegroundColor DarkGray
            #Write-Host "    AD connect server... $($configuration.AzureADConnectServer)" -ForegroundColor DarkGray
            #Write-Host "    User data path...... $($configuration.UserFolderUNCPath)" -ForegroundColor DarkGray
            #Write-Host "    Default groups...... " -ForegroundColor DarkGray
            #foreach ($group in $configuration.DefaultGroups) {
            #    Write-Host "        $group" -ForegroundColor DarkGray
            #}
        }
        return $result
    }
}

class User {

    [string] $Firstname
    [string] $Lastname
    [string] $Department
    [string] $Title
    [string] $Phone
    [string] $Mobile
    [string] $Username
    [Microsoft.ActiveDirectory.Management.ADUser] $Manager
    [Microsoft.ActiveDirectory.Management.ADUser] $Similar
    [securestring] $Password
    [Configuration] $Configuration

    User ([string] $un) {
        $this.Username = $un
    }

    [string] Fullname() {
        return ('{0} {1}' -f $this.Firstname, $this.Lastname)
    }

    [string] EmailAddress() {
        return ('{0}@{1}' -f $this.Username, $this.Configuration.UPNSuffix)
    }

    [string] Initials() {
        return ('{0}{1}' -f $this.Firstname[0], $this.Lastname[0])
    }

    [string] Folder() {
        if ($this.Configuration.UserFolderUNCPath -and $this.Username) {
            return Join-Path $this.Configuration.UserFolderUNCPath $this.Username
        }
        else {
            return $null
        }
    }

    static [Microsoft.ActiveDirectory.Management.ADUser] Get([string] $Identity, [string] $Server) {
        #Write-Host "[*] Retrieving Active Directory account for $($Identity)"
        $user = $null
        try {
            $user = Get-ADUser -Identity $Identity -Server $Server -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # do nothing; null will be returned below
        }
        Write-Host "[*] Successfully retrieved Active Directory account for $($Identity)" -ForegroundColor Green
        return $user
    }

    [bool] Exists([string] $Server) {
        #Write-Host "[*] Checking that $($this.Username) username is available"
        try {
            $aduser = Get-ADUser -Identity $this.Username -Server $Server
            return ($null -ne $aduser)
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "[*] Username $($this.Username) is available" -ForegroundColor Green
            return $false
        }
    }

    [void] CreateFolder() {
        if ($this.Folder()) {
            if (Test-Path $this.Configuration.UserFolderUNCPath) {
                $path = $this.Folder()
                if (-not (Test-Path $path)) {
                    Write-Host "[+] Creating user folder at $path and setting permissions"
                    New-Item -ItemType Directory -Path $path | Out-Null
                    icacls.exe "$path" /setowner $this.Username /T /C
                    icacls.exe "$path" /reset /T /C
                }
                else {
                    Write-Host "[*] Folder $path already exists; skipping folder creation"
                }
            }
            else {
                Write-Host "[!] Folder $($this.Configuration.UserFolderUNCPath) in configuration file does not exist" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "[*] No user folder specified in configuration; skipping folder creation"
        }
    }

    [void] GeneratePassword([int] $Length) {

        Write-Host "[*] Generating strong, random password is $Length characters in length"

        $charset = @{
            Upper   = (97..122) | Get-Random -Count 10 | ForEach-Object { [char]$_ }
            Lower   = (65..90)  | Get-Random -Count 10 | ForEach-Object { [char]$_ }
            Numeric = (48..57)  | Get-Random -Count 10 | ForEach-Object { [char]$_ }
            Special = (33..47) + (58..64) + (91..96) + (123..126) | Get-Random -Count 10 | ForEach-Object { [char]$_ }
        }

        $stringset = $charset.Upper + $charset.Lower + $charset.Numeric + $charset.Special

        $plaintext = -join (Get-Random -Count $Length -InputObject $stringset)

        $this.Password = $plaintext | ConvertTo-SecureString -AsPlainText -Force

        Write-Host "[*] Generated password is $plaintext"

        $plaintext = ''
    }

    [bool] Validate() {

        $passed = $true

        if (-not $this.Firstname) {
            $passed = $false
        }
        if (-not $this.Lastname) {
            $passed = $false
        }
        if (-not $this.Department) {
            $passed = $false
        }
        if (-not $this.Title) {
            $passed = $false
        }
        if (-not $this.Username) {
            $passed = $false
        }
        if ((-not $this.Password) -or (-not $this.Password.Length -eq 12)) {
            $passed = $false
        }
        if (-not $this.Configuration) {
            $passed = $false
        }

        Write-Host "[*] Validating new user properties"
        Write-Host "    First name........ $($this.Firstname)" -ForegroundColor DarkGray
        Write-Host "    Last name......... $($this.Lastname)" -ForegroundColor DarkGray
        Write-Host "    Full name......... $($this.Fullname())" -ForegroundColor DarkGray
        Write-Host "    Initials.......... $($this.Initials())" -ForegroundColor DarkGray
        Write-Host "    Email address..... $($this.EmailAddress())" -ForegroundColor DarkGray
        Write-Host "    Office phone...... $($this.Phone)" -ForegroundColor DarkGray
        Write-Host "    Mobile phone...... $($this.Mobile)" -ForegroundColor DarkGray
        Write-Host "    Password length... $($this.Password.Length)" -ForegroundColor DarkGray
        Write-Host "    Manager........... $($this.Manager.Name)" -ForegroundColor DarkGray
        Write-Host "    Similar to........ $($this.Similar.Name)" -ForegroundColor DarkGray
        Write-Host "    User Folder....... $(@('None',($this.Folder()))[$null -ne $this.Folder()])" -ForegroundColor DarkGray

        return $passed
    }

    [void] Create() {

        Write-Host "[+] Creating Active Directory account for $($this.Username)"

        New-ADUser `
            -AccountPassword $this.Password `
            -AllowReversiblePasswordEncryption $false `
            -CannotChangePassword $false `
            -ChangePasswordAtLogon $false `
            -City $this.Configuration.City `
            -Company $this.Configuration.Company `
            -Country $this.Configuration.Country `
            -Department $this.Department `
            -Description $this.Title `
            -DisplayName $this.Fullname() `
            -EmailAddress $this.EmailAddress() `
            -Enabled $true `
            -GivenName $this.Firstname `
            -Initials $this.Initials() `
            -Manager $this.Manager `
            -MobilePhone $this.Mobile `
            -Name $this.Fullname() `
            -OfficePhone $this.Phone `
            -Organization $this.Configuration.Company `
            -PasswordNeverExpires $true `
            -PasswordNotRequired $false `
            -Path $this.Configuration.OUPath `
            -PostalCode $this.Configuration.Postal `
            -SamAccountName $this.Username `
            -State $this.Configuration.State `
            -StreetAddress $this.Configuration.Address `
            -Surname $this.Lastname `
            -Title $this.Title `
            -UserPrincipalName $this.EmailAddress()
    }

    [void] SyncToAzureAD() {
        if ($this.Configuration.AzureADConnectServer.Length -gt 0) {
            Write-Host "[*] Starting Azure AD Connect synchronization cycle on $($this.Configuration.AzureADConnectServer)"
            try {
                $command = Invoke-Command -ComputerName $($this.Configuration.AzureADConnectServer) -ScriptBlock { Start-ADSyncSyncCycle } -ErrorAction Stop
                Write-Host "[*] Synchronization result: $($command.Result)"
            }
            catch {
                Write-Host "[!] Failed to start synchronization cycle on $($this.Configuration.AzureADConnectServer)" -ForegroundColor Yellow
                Write-Host "    $_" -ForegroundColor DarkYellow
            }
        }
        else {
            Write-Host "[*] No Azure AD Connect server specified in configuration; skipping sync"
        }
    }

    [void] AddGroupMemberships() {
        
        #
        # get the group memberships for the similar user
        #
        $copied = @($this.Similar | Get-ADPrincipalGroupMembership)

        #
        # get the default groups that are specified in the configuration file
        #
        $default = Get-ADGroup -Filter (($this.Configuration.DefaultGroups | ForEach-Object { "Name -eq '$_'" }) -join " -or ")

        #
        # combine copied and default groups into one list
        #
        $groups = $copied + $default | Group-Object Name | ForEach-Object { $_.Group[0] }

        #
        # get our current group memberships
        #
        $current = @(Get-ADPrincipalGroupMembership $this.Username)

        #
        # finally, add our new user the groups list as long as they aren't already a member

        foreach ($group in $groups) {
            if ($current.ObjectGUID -notcontains $group.ObjectGuid) {
                Write-Host "[+] Adding $($this.Username) to group $($group.Name)"
                Add-ADGroupMember -Identity $group -Members $this.Username
            }
        }
    }
}

function Write-Banner {
    Write-Host ''
    Write-Host '    |\__/,|   (`\ '
    Write-Host '  _.|o o  |_   ) )'
    Write-Host '-(((---(((------- '  
    Write-Host ''    
}

Write-Banner

Write-Host "[*] Starting at $(Get-Date)"

$configuration = [Configuration]::Load($ConfigurationFile)

if ($null -eq $configuration) {
    Write-Host "[!] Unable to load configuration file at $ConfigurationFile; exiting" -ForegroundColor Red
    return
}

$user = [User]::new($Username)

if ($user.Exists($configuration.ADServer)) {
    Write-Host "[!] An account with username $Username already exists; exiting" -ForegroundColor Red
    return
}

$manager = [User]::Get($UsernameOfManager, $configuration.ADServer)
if ($null -eq $manager) {
    Write-Host "[!] Manager account $UsernameOfManager was not found; exiting" -ForegroundColor Red
    return
}

$similar = [User]::Get($UsernameOfSimilar, $configuration.ADServer)
if ($null -eq $similar) {
    Write-Host "[!] Similar account $UsernameOfManager was not found; exiting" -ForegroundColor Red
    return
}

$user.Firstname = $Firstname
$user.Lastname = $Lastname
$user.Department = $Department
$user.Title = $Title
$user.Phone = $Phone
$user.Mobile = $Mobile
$user.Manager = $manager
$user.Similar = $similar
$user.Configuration = $configuration
$user.GeneratePassword(12)

if (-not ($user.Validate())) {
    Write-Host "[!] Something about this user isn't right; quitting" -ForegroundColor Red
    return
}

Write-Host "[*] New user properties appear to be good. Press [y] to create user or any other key to quit." -ForegroundColor Green
if ([System.Console]::ReadKey($true).KeyChar -ne 'y') {
    Write-Host "[!] Quiting without creating user" -ForegroundColor Yellow
    return
}

$user.Create()
$user.AddGroupMemberships()
$user.SyncToAzureAD()
$user.CreateFolder()

Write-Host "[!] Important: Note the generated password above before closing this window!" -ForegroundColor Yellow
Write-Host "[*] Finished at $(Get-Date)"
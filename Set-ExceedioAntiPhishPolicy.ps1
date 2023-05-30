#Requires -Version 7.2
#Requires -Modules @{ ModuleName="ExchangeOnlineManagement"; ModuleVersion="3.0.0" }

<#
.SYNOPSIS

    Configures default AntiPhish policy to standard.

.DESCRIPTION

    The anti-spoofing settings that are configured by this script require Microsoft Defender for Office 365 P1
    or higher. This script should be run using PowerShell 7.2 as a user that has delegated partner access to
    the target organization. Do not run as Global Administrator of the target organization - run as yourself
    and authenticate as yourself when prompted.

.PARAMETER PolicyIdentity

    The name of the anti-phishing policy. Defaults to 'Exceedio'.

.PARAMETER DelegatedOrganization

    The domain name of the organization on which to configure the policy. If not provided as a script
    parameter you will be prompted.

.PARAMETER TargetedUsersToProtect

    Array of users to receive additional impersonation protection in the format <full name>;<email address>.
    This is typically a list of high value targets or people in positions of authority who, if their email
    account was successfully impersonated, could cause a lot of damage. If not provided as a script
    parameter you will be prompted. If you're not sure, put the CEO, general manager, or other person in
    charge in this list.

.EXAMPLE

    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Set-ExceedioAntiPhishPolicy.ps1 | iex

.NOTES

    Filename : Set-ExceedioAntiPhishPolicy.ps1
    Author   : jreese@exceedio.com
    Modified : May 30, 2023
#>

[CmdletBinding()]
param (
    [string]
    $PolicyIdentity = 'Exceedio',

    [string]
    $DelegatedOrganization,

    [string[]]
    $TargetedUsersToProtect
)

if (-not $DelegatedOrganization) {
    $DelegatedOrganization = Read-Host 'Delegated organization (e.g. contoso.onmicrosoft.com)'
}

if (-not $ImpersonationProtectedUsers) {

    $TargetedUsersToProtect = @()

    Write-Output ""
    Write-Output "You will now be asked for a list of people that are considered high-value targets for business"
    Write-Output "email compromise (BEC). These are typically people in positions of authority, especially those"
    Write-Output "who would be authorized to make financial requests of others. For example, if the email account"
    Write-Output "for the Director of Finance at an organization was compromised it could be used to make a funds"
    Write-Output "transfer request to an accounting clerk that looks legitimate. In this case the director of"
    Write-Output "finance is the high value target."
    Write-Output ""
    Write-Output "Names should be in the format <name>;<email address> (e.g. John Doe;jdoe@contoso.com). Press"
    Write-Output "[Enter] on a blank line to indicate you are done entering names."
    Write-Output ""

    do {
        $highValueTarget = Read-Host 'User to receive additional impersonation protection'
        if ($highValueTarget -ne '') {
            $TargetedUsersToProtect += $highValueTarget
        }
    } while ($highValueTarget -ne '')
}

$antiPhishSettings = @{
    'Name' = $PolicyIdentity
    'AdminDisplayName' = $PolicyIdentity
    'EnableFirstContactSafetyTips' = $true
    'EnableMailboxIntelligence' = $true
    'EnableMailboxIntelligenceProtection' = $true
    'EnableOrganizationDomainsProtection' = $true
    'EnableSimilarDomainsSafetyTips' = $true
    'EnableSimilarUsersSafetyTips' = $true
    'EnableSpoofIntelligence' = $true
    'EnableTargetedDomainsProtection' = $true
    'EnableTargetedUserProtection' = $true
    'EnableUnauthenticatedSender' = $true
    'EnableUnusualCharactersSafetyTips' = $true
    'EnableViaTag' = $true
    'ExcludedDomains' = @()
    'ExcludedSenders' = @()
    'MailboxIntelligenceProtectionAction' = 'Quarantine'
    'PhishThresholdLevel' = 2
    'TargetedDomainProtectionAction' = 'Quarantine'
    'TargetedDomainsToProtect' = @('exceedio.com')
    'TargetedUserProtectionAction' = 'Quarantine'
    'TargetedUsersToProtect' = $TargetedUsersToProtect
}

Write-Output ""
Write-Output "A browser window will now open and you will now be prompted to authenticate. Use your own"
Write-Output "credentials to authenticate, not the target organization credentials."
Write-Output ""
timeout 10
Write-Output "[*] Connecting to Exchange Online..."
Connect-ExchangeOnline -DelegatedOrganization $DelegatedOrganization -ShowBanner:$false

if (-not (Get-AntiPhishPolicy -Identity $PolicyIdentity)) {

    Write-Output "[*] Creating new anti-phish policy named $PolicyIdentity"
    New-AntiPhishPolicy @antiPhishSettings

    Write-Output "[*] Obtaining list of domains to which the policy applies"
    $acceptedDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName

    Write-Output "[*] Creating rule to apply new policy to $($acceptedDomains -join ', ')"
    New-AntiPhishRule -Name $PolicyIdentity -AntiPhishPolicy $PolicyIdentity -RecipientDomainIs $acceptedDomains
}
else {

    Write-Output "[*] Updating existing anti-phish policy named $PolicyIdentity"
    Set-AntiPhishPolicy @antiPhishSettings
}

Write-Output "[*] Disconnecting from Exchange Online..."
Disconnect-ExchangeOnline -Confirm:$false
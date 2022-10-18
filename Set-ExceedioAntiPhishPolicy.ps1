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
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Set-ExceedioAntiPhishPolicy.ps1 | iex
.NOTES
    Filename : Set-ExceedioAntiPhishPolicy.ps1
    Author   : jreese@exceedio.com
    Modified : Oct 18, 2022
#>

[CmdletBinding()]
param (
    [String]
    $PolicyIdentity = 'Office365 AntiPhish Default'
)

$delegatedOrg = Read-Host 'Delegated organization (e.g. contoso.onmicrosoft.com)'

Write-Output "Connecting to Exchange Online..."
Connect-ExchangeOnline -DelegatedOrganization $delegatedOrg -ShowBanner:$false

if (Get-AntiPhishPolicy -Identity $PolicyIdentity) {
    Write-Output "Updating $PolicyIdentity..."
    Set-AntiPhishPolicy `
        -Identity $PolicyIdentity `
        -EnableMailboxIntelligence $true `
        -EnableMailboxIntelligenceProtection $true `
        -EnableOrganizationDomainsProtection $true `
        -EnableTargetedUserProtection $true `
        -EnableTargetedDomainsProtection $true `
        -MailboxIntelligenceProtectionAction Quarantine `
        -TargetedUserProtectionAction Quarantine `
        -TargetedDomainProtectionAction Quarantine `
        -EnableFirstContactSafetyTips $true `
        -EnableSimilarDomainsSafetyTips $true `
        -EnableSimilarUsersSafetyTips $true `
        -EnableUnusualCharactersSafetyTips $true `
        -PhishThresholdLevel 2
} else {
    Write-Warning "Policy $PolicyIdentity does not exist. No changes made."
}

Write-Output "Disconnecting from Exchange Online..."
Disconnect-ExchangeOnline -Confirm:$false
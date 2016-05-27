<#
.SYNOPSIS
    Sets up environment for managing O365 accounts.
.DESCRIPTION
    Run this script to 
.PARAMETER UserName
    The username portion of the global administrator account (e.g. user@domain.com)
.PARAMETER Exchange
    Value indicating whether you need to load the Exchange Online cmdlets for
    managing mailboxes, distribution groups, etc. Setting this to true will
    cause the script to take longer to load.
.EXAMPLE
    .\Enter-O365.ps1 -UserName user@domain.com -Exchange
.NOTES
    Author: Jeff Reese
    Date:   May 27, 2016
#>

param (
    [Parameter(Mandatory=$True)]
    [string] $UserName,

    [switch] $Exchange = $false
)

#
# get user credential in upn format (e.g. user@domain.com)
#
$UserCredential = Get-Credential -UserName $UserName -Message 'Enter global administrator credentials...'

#
# connect to msonline
# 
Connect-MsolService -Credential $UserCredential

#
# load the Exchange cmdlets only if necessary
#
if ($Exchange) {
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
    Import-PSSession $Session
}

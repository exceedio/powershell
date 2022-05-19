#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Security

<#
.SYNOPSIS
    Gets a list of Azure AD sign ins using legacy authentication.
.DESCRIPTION
    You can use the list generated by this script to track down users that might be
    using legacy authentication protocols such as ActiveSync or SMTP to authenticate
    to Azure AD and get them on to a modern authentication client before disabling
    legacy authentication for the tenant.
.PARAMETER TenantId
    The Azure AD Tenant ID that can be obtained from the Overview blade of the Azure
    AD portal.
.PARAMETER ClientId
    The Application (client) ID of your app registration that is registered in your
    Azure AD instance. The app requires at least User.Read and AuditLog.Read.All
    delegated permissions for Microsoft Graph.
.PARAMETER Scopes
    The Graph API permissions required for this script. You shouldn't need to use this.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/Get-ExceedioLegacyAuthSigninLogs.ps1'))
.EXAMPLE
    .\Get-ExceedioLegacyAuthSigninLogs.ps1
.EXAMPLE
    .\Get-ExceedioLegacyAuthSigninLogs.ps1 -TenantId 430b6c3f-3d7b-45cb-8bc1-f745acf4df74 -ClientId b133e7d1-8a79-49a0-a001-fdf82aee3081
.EXAMPLE
    .\Get-ExceedioLegacyAuthSigninLogs.ps1 -StayConnectedToGraphAPIWhenFinished
.NOTES
    Filename : Get-ExceedioLegacyAuthSigninLogs.ps1
    Author   : jreese@exceedio.com
    Modified : May 18, 2022
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage='Enter the Azure AD Tenent ID from Overview blade in portal')]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $TenantId,
    [Parameter(Mandatory = $true, HelpMessage='Enter application (client) ID of Azure AD registered app with permissions to read multi-tenant logs')]
    [ValidateNotNullOrEmpty()]
    [String]
    $ClientId
)

$results = @()

$profiles = Get-MgSecuritySecureScoreControlProfile

$TenantId | ForEach-Object {
    Connect-MgGraph -TenantId $_ -ClientId $ClientId -ContextScope Process | Out-Null
    "[*] Obtaining secure score information for {0}" -f $_ | Write-Host
    $score = Get-MgSecuritySecureScore | Select-Object -First 1
    foreach ($control in $score.ControlScores) {
        $scoreInPercentage = $control.AdditionalProperties['scoreInPercentage']
        $controlProfile = $profiles | Where-Object {$_.Id -contains $control.ControlName}
        "[!] {0} {1}" -f $scoreInPercentage, $controlProfile.Title | Write-Host -ForegroundColor Yellow
    }
    $results += $score
}

#$results | Format-Table AzureTenantId,@{label='Score';expression={($_.CurrentScore / $_.MaxScore).ToString("P")}}

$results
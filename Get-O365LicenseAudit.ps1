<#
.SYNOPSIS
    Gets Office 365 SKUs and user license assignments.
.DESCRIPTION
    Generates two CSV files that can be used to determine how many licenses and of what
	kind are purchased and assigned within a given organization. The script can be run
	as a one-liner that deposits the CSV file in the current TEMP folder or the script
	can be downloaded and run with arguments to direct the output to a folder of your
	choice. Examples are provided below.

    This script requires the Azure AD V2 PowerShell module.
	
	Install-Module AzureAD

    Resource and background information on the commands used in this script are available
    at the website below.
	
	https://practical365.com/blog/managing-office-365-licenses-with-azure-ad-v2-powershell-module
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Get-O365LicenseAudit.ps1 | iex
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Get-O365LicenseAudit.ps1 -OutFile Get-O365LicenseAudit.ps1
	.\Get-O365LicenseAudit.ps1 -OutPath C:\Temp
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Get-O365LicenseAudit.ps1 -OutFile Get-O365LicenseAudit.ps1
	.\Get-O365LicenseAudit.ps1 -Username someuser@contoso.com -OutPath C:\Temp
.NOTES
    Filename : Get-O365LicenseAudit.ps1
    Author   : jreese@exceedio.com
    Modified : Oct 04, 2017
#>

param (
    [string] $Username,
	[string] $OutPath = $env:temp
)

function Export-SkuAudit
{
    $skusfile  = "$OutPath\O365skus-$date.csv"
    Get-AzureADSubscribedSku | Select -Property Sku*,ConsumedUnits -ExpandProperty PrepaidUnits | Export-Csv -NoTypeInformation $skusfile
	Write-Output "Office 365 SKU audit saved to $skusfile"
}

function Export-UserAudit
{
    $usersfile = "$OutPath\O365users-$date.csv"
    $skulookup = @{}
    Get-AzureADSubscribedSku | % {$skulookup.Add($_.SkuId, $_.SkuPartNumber)}
    $users = Get-AzureADUser -Top 1000 | Where-Object {$_.AssignedLicenses.Length -gt 0} | Sort-Object DisplayName
	$users | Select-Object DisplayName, Department, Mail, AccountEnabled, @{Expression={$skulookup[$_.AssignedLicenses[0].SkuId]};Label="Plan"} | Export-Csv -NoTypeInformation $usersfile
	Write-Output "Office 365 User audit saved to $usersfile"
}

$date = (Get-Date).ToString('yyyyMMdd')
Connect-AzureAD -Credential (Get-Credential $Username) | Out-Null
Export-SkuAudit
Export-UserAudit
Disconnect-AzureAD
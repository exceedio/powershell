<#
.SYNOPSIS
    Configures Windows Server 2012 R2 as the first site server.
.DESCRIPTION
    
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioForest.ps1 | iex
.NOTES
    Filename : New-ExceedioForest.ps1
    Author   : jreese@exceedio.com
    Modified : Nov, 9, 2016
#>

if (!((Get-WindowsFeature -Name AD-Domain-Services).Installed)) {
    Write-Host "Installing ADDS"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
} else {
    Write-Host "ADDS is installed" -ForegroundColor Green
}

if ((Get-WmiObject win32_computersystem).PartOfDomain -eq $false) {
    
} else {
    Write-Host "Computer is already part of domain" -ForegroundColor Green
}
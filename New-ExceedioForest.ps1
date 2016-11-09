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
    Write-Warning "Installing ADDS"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
} else {
    Write-Output "ADDS is installed"
}

if ((Get-WmiObject win32_computersystem).PartOfDomain -eq $false) {
    Write-Warning "Installing new forest"
    $netbios = Read-Host "Domain NETBIOS name?"
    $publicdomain = Read-Host "Primary public domain name?"
    $domainname = "$netbios.$publicdomain"
    $testresult = Test-ADDSForestInstallation -DomainName $domainname -DomainNetbiosName $netbios -ForestMode Win2012R2 -DomainMode Win2012R2 -CreateDnsDelegation $false -InstallDNS
    if ($testresult.Status -eq 'Success') {
        Install-ADDSForest -DomainName $domainname -DomainNetbiosName $netbios -ForestMode Win2012R2 -DomainMode Win2012R2 -InstallDNS
    }
} else {
    Write-Output "Computer is already part of domain"
}

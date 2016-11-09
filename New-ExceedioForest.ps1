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

function Convert-IPAddressToBinary ($dottedDecimal){ 
  $dottedDecimal.split(".") | ForEach-Object {$binary=$binary + $([convert]::toString($_,2).padleft(8,"0"))} 
  return $binary 
} 
 
function Convert-IPAddressToDottedDecimal ($binary){ 
  do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i,8),2)); $i+=8 } while ($i -le 24) 
  return $dottedDecimal.substring(1) 
} 

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
    $testresult = Test-ADDSForestInstallation -DomainName $domainname -DomainNetbiosName $netbios -ForestMode Win2012R2 -DomainMode Win2012R2 -InstallDNS
    if ($testresult.Status -eq 'Success') {
        Install-ADDSForest -DomainName $domainname -DomainNetbiosName $netbios -ForestMode Win2012R2 -DomainMode Win2012R2 -InstallDNS
        exit
    }
} else {
    Write-Output "Computer is part of domain"
}

if (@(Get-DnsServerZone | Where-Object IsReverseLookupZone -eq $true).Length -le 3) {
    Write-Warning "Creating reverse lookup zone"
    $netaddress   = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet
    $ipv4address  = $netaddress.IPAddress
    $prefixlength = $netaddress.PrefixLength
    $network      = Convert-IPAddressToDottedDecimal $((Convert-IPAddressToBinary $ipv4address).substring(0,$prefixlength).padright(32,"0"))
    $networkid    = "$network/$prefixlength"
    Add-DnsServerPrimaryZone -NetworkID $networkid -ReplicationScope "Domain"
} else {
    Write-Output "Reverse lookup zone exists"
}


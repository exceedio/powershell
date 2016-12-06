<#

.SYNOPSIS
    Creates a consistent OU structure.
.DESCRIPTION
    Use this script to create the initial OU structure in an active directory domain.
.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioOUStructure.ps1 -UseBasicParsing | iex
#>

$base = Read-Host "Base OU (e.g. DC=contoso,DC=com)"

New-ADOrganizationalUnit -Name 'Business' -Path "$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Contacts' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Disabled Users' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Distribution Groups' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Security Groups' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Servers' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Users' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name 'Workstations' -Path "OU=Business,$base" -ProtectedFromAccidentalDeletion $true

Write-Output "Completed"
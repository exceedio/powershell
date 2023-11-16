#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a consistent set of Active Directory security groups.
.DESCRIPTION
    Use this script to create a consistent set of Active Directory security groups in an organization.
    Currently this is used to create security groups for group-based licensing in Microsoft Entra ID and
    so the default group description reflects that.
.PARAMETER OUPath
    The distinguished name of the organization unit in which to create the security groups. Typically
    this is going to be OU=Security Groups,OU=Business,DC=contoso,DC=com or something similar.
.PARAMETER Description
    The description to use for each security group that is created. This has a default value that
    typically should not be changed.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioStandardADGroups.ps1 -UseBasicParsing | iex
.NOTES
    Filename : New-ExceedioStandardADGroups.ps1
    Author   : jreese@exceedio.com
    Modified : Nov 16, 2023
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String]
    $OUPath,
    [Parameter()]
    [String]
    $Description = 'Members are assigned license via group-based licensing in Microsoft Entra ID'
)

$names = @(
    'Microsoft 365 Audio Conferencing',
    'Microsoft 365 E3',
    'Microsoft Defender for Office 365 (Plan 1)',
    'Microsoft Defender for Office 365 (Plan 2)',
    'Microsoft Entra ID P2'
)

foreach ($name in $names) {
    New-ADGroup -Name "Licensed for $name" -Description $Description -Path $OUPath -GroupScope Global -GroupCategory Security
}

Write-Output "Finished created $($names.Count) groups"
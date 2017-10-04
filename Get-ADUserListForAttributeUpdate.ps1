<#
.SYNOPSIS
    Gets a list of users and their attributes in a format that will be used to feed update.
.DESCRIPTION
    Run to generate a CSV file that can be handed to HR to be filled out with current,
    accurate information. Ask them to return the file to you so that you can use the file
    as input to an automated AD update.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Get-ADUserListForAttributeUpdate.ps1 | iex
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Get-ADUserListForAttributeUpdate.ps1 -OutFile Get-ADUserListForAttributeUpdate.ps1
    .\Get-ADUserListForAttributeUpdate.ps1 -SearchBase "OU=Users,OU=Business,DC=contoso,DC=com"
.NOTES
    Filename : Get-ADUserListForAttributeUpdate.ps1
    Author   : jreese@exceedio.com
    Modified : Oct 04, 2017
#>

param (
    [string] $SearchBase
)

$date = (Get-Date).ToString('yyyyMMdd')
$filename = "$env:temp\userlistforadupdate-$date.csv"
Get-ADUser -Filter * -Properties * -SearchBase $SearchBase | ? {$_.UserPrincipalName -ne $null} | Sort UserPrincipalName | Select UserPrincipalName, GivenName, Surname, Title, Organization, Department, Office, EmailAddress, OfficePhone, MobilePhone, HomePhone, Fax, StreetAddress, City, State, PostalCode | Export-Csv $env:temp\Get-UsersForADUpdate.csv -NoTypeInformation
Write-Output "File has been generated at $filename"
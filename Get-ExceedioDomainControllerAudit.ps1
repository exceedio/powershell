#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Gathers information about a domain controller and posts the results as
    JSON to a specified URL
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Get-ExceedioDomainControllerAudit.ps1 | iex
.NOTES
    Filename: Invoke-ExceedioDomainControllerAudit.ps1
    Author:   jreese@exceedio.com
    Modified: Sep 28, 2024
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $Uri
)

function Get-Forwarders
{
    Get-DnsServerForwarder | Select-Object @{Name='Addresses';Expression={$_.IPAddress -join ', '}}, UseRootHint
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$results = [PsCustomObject] @{
    'Hostname' = ([System.Net.Dns]::GetHostByName($env:computerName)).HostName.ToLower()
    'DnsServerForwarders' = Get-Forwarders
}

$results | ConvertTo-Json -Depth 10 | Invoke-RestMethod -Uri $Uri -Method Post -ContentType 'application/json'

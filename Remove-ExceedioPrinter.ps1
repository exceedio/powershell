#Requires -Version 5.1
#Requires -RunAsAdministrator 
#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Removes a retired printer
.DESCRIPTION
.EXAMPLE
    PS C:\> Remove-ExceedioPrinter.ps1
.EXAMPLE
    PS C:\> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Remove-ExceedioPrinter.ps1 | iex
.PARAMETER Name
    The name of the printer to remove
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory=$false)]
    [string]
    $Name
)

if (-not ($Name))
{
    Write-Host "[*] Gathering printer list"
    Get-Printer | Sort-Object Name | Format-Table Name,PrinterStatus,PortName,Shared
    $Name = Read-Host "Name of printer to remove"
}

foreach ($gpo in (Get-GPO -All | Sort-Object DisplayName))
{
    Write-Host "[*] Analyzing $($gpo.DisplayName)"
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    if ($report -match $Name)
    {
        Write-Host "[!] Found reference to $Name in $($gpo.DisplayName)"
    }
}

Write-Host "[*] Finished"

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
    PS C:\> irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Remove-ExceedioPrinter.ps1 | iex
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

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
Write-Host "[*] Current active directory domain is $domain"

if (-not ($Name))
{
    Write-Host "[*] Gathering printer list"
    Get-Printer | Sort-Object Name | Format-Table Name,PrinterStatus,PortName,Shared
    $Name = Read-Host "Name of printer to remove"
}

Write-Host "[*] Searching for printer $Name in group policies..."
foreach ($gpo in (Get-GPO -All | Sort-Object DisplayName))
{
    Write-Host "[*] Analyzing $($gpo.DisplayName)"
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml

    if ($report -like "*$Name*")
    {
        Write-Host "[!] Found reference to $Name in $($gpo.DisplayName)"
        $path = "\\$domain\sysvol\$domain\Policies\{$($gpo.Id)}\User\Preferences\Printers\Printers.xml"
        if (Test-Path $path)
        {
            Write-Host "[*] Found user printer preferences at $path"
            [xml] $xml = Get-Content $path
            $printer = $xml.Printers.SharedPrinter | Where-Object { $_.name -eq "$Name" }
            if ($printer)
            {
                $action = $printer.Properties.action
                Write-Host "[*] Printer $Name is current set to $action"
                if ($action -ne 'D')
                {
                    Write-Host "[*] Creating backup of $path"
                    Copy-Item -Path $path -Destination "$env:temp\Printers.xml"
                    Write-Host "[!] Setting printer $Name action to [D]elete"
                    $printer.Properties.action = 'D'
                    $xml.Save($path)
                }
            } else
            {
                Write-Warning "Did not find $Name in $path"
            }
        } else
        {
            Write-Warning "Expected to find user printer preferences at $path"
        }
    }
}

Write-Host "[*] Finished"

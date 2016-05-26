<#
.SYNOPSIS
    Activates Windows
.DESCRIPTION
    Uses WMI to enter the provided product key and activate Windows.
.EXAMPLE
    .\Activate-Windows.ps1 -ProductKey AAAAA-BBBBB-CCCCC-DDDDD-EEEEE
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Activate-Windows.ps1 | iex
#>

param (
    [Parameter(Mandatory=$true)]
    [string] $ProductKey,

    [string] $ComputerName = $env:COMPUTERNAME
)

$service = gwmi -query "select * from SoftwareLicensingService" -ComputerName $ComputerName
$service.InstallProductKey($ProductKey)
$service.RefreshLicenseStatus()

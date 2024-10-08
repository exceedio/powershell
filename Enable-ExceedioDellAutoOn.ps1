#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Dell client computers to automatically power on at a given time
.DESCRIPTION
    This script makes BIOS setting changes that enable automatic power on of
    a Dell client computer every day at given time as well as whenver power is
    restored to a computer that has lost power.
.PARAMETER Frequency
    When do you want automatic power on to occur? Defaults to every day.
.PARAMETER Hour
    The hour to automatically power on. Defaults to 0 (midnight).
.PARAMETER Minute
    The minute to automatically power on. Defaults to 5.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Enable-ExceedioDellAutoOn.ps1 | iex
.NOTES
    Filename: Enable-ExceedioDellAutoOn.ps1
    Author:   jreese@exceedio.com
    Modified: Oct 1, 2024
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]
    $Frequency = 'Everyday',
    [Parameter()]
    [string]
    $Hour = '0',
    [Parameter()]
    [string]
    $Minute = '5'
)

function Set-DellSmbiosValue
{
    param (
        $Path,
        $DesiredValue
    )

    $currentValue = (Get-Item -Path $Path -ErrorAction SilentlyContinue).CurrentValue

    if ($currentValue -ne $DesiredValue)
    {
        Set-Item -Path $Path -Value $DesiredValue -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Set $Path to $DesiredValue" -ForegroundColor Yellow
    } else
    {
        Write-Host "[*] $Path is already set to $DesiredValue"
    }
}

$mfg = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer
if ($mfg -notlike 'Dell*')
{
    Write-Host "[!] This script is not mean for $mfg systems" -ForegroundColor Yellow
    return
}

Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Install-ExceedioDellBIOSProvider.ps1' | Invoke-Expression

Write-Host "[*] Checking for existence of DellSmbios drive"
if (-not (Get-PSDrive -Name DellSmbios -ErrorAction SilentlyContinue))
{
    Write-Host "[*] Importing DellBIOSProvider module"
    Set-ExecutionPolicy RemoteSigned -Scope Process
    Import-Module DellBIOSProvider
}

Write-Host "[*] Configuring BIOS to automatically power on system"
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AcPwrRcvry" -DesiredValue 'On'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOn" -DesiredValue $Frequency
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnHr" -DesiredValue $Hour
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnMn" -DesiredValue $Minute


Write-Host "[*] Finished"

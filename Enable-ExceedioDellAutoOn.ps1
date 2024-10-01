#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Dell client computers to automatically power on at a given time
.DESCRIPTION
    This script makes BIOS setting changes that enable automatic power on of
    a Dell client computer every day at given time as well as whenver power is
    restored to a computer that has lost power.
.PARAMETER AutoOnHr
    The hour to automatically power on. Defaults to midnight.
.PARAMETER AutoOnMn
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

    if ($value = (Get-Item -Path $Path -ErrorAction SilentlyContinue).CurrentValue)
    {
        if ($value -ne $DesiredValue)
        {
            Set-Item -Path $Path -Value $DesiredValue -Force
            Write-Host "Set $Path to $DesiredValue" -ForegroundColor Yellow
        } else
        {
            Write-Host "$Path is already set to $DesiredValue"
        }
    } else
    {
        Write-Host "Problem getting $Path" -ForegroundColor Yellow
    }
}

Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Install-ExceedioDellBIOSProvider.ps1' | Invoke-Expression

Write-Host "Configuring BIOS to automatically power on system"
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AcPwrRcvry" -DesiredValue 'On'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOn" -DesiredValue $Frequency
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnHr" -DesiredValue $Hour
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnMn" -DesiredValue $Minute


Write-Host "Finished"

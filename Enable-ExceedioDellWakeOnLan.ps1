#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Dell clients with Realtek or Intel cards for wake on lan (WOL)
.DESCRIPTION
    Designed to configure Dell Windows client computers with Realteak or Intel
    ethernet cards to ensure they are on or can be turned on for overnight
    maintenance tasks such as patching.

    Configures BIOS and advanced network card properties for Dell client
    computers having Realtek or Intel network cards to support wake on lan
    (WOL) functionality. Also configures Dell BIOS-based automatic power on
    for 12:05 AM (5 minutes after midnight) every day.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Enable-ExceedioDellWakeOnLan.ps1 | iex
.NOTES
    Filename: Enable-ExceedioDellWakeOnLan.ps1
    Author:   jreese@exceedio.com
    Modified: Sep 25, 2024
#>

[CmdletBinding()]
param()

# Older versions of PowerShell default to TLS 1.0, which is incompatible with
# modern repositories like the PowerShell Gallery. Setting the security protocol
# to TLS 1.2 ensures secure connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue))
{
    Write-Host "Installing NuGet package provider"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Confirm:$false
}

if (Get-PSRepository -Name PSGallery -ErrorAction Stop)
{
    Write-Host "Checking status of PSGallery repository"
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted')
    {
        Write-Host "Trusting the PSGallery repository"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
}

if (-not (Get-Module -ListAvailable -Name DellBIOSProvider))
{
    Write-Host "Installing the DellBIOSProvider module"
    Install-Module -Name DellBIOSProvider -MinimumVersion 2.8.0 -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop
}

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
    }
}

function Set-NetAdapterAdvancedPropertyIfExists
{
    param (
        $NetAdapter,
        $Property,
        $DesiredValue = 'Disabled'
    )
    if ($current = ($NetAdapter | Get-NetAdapterAdvancedProperty -DisplayName $Property -ErrorAction SilentlyContinue).DisplayValue)
    {
        if ($current -ne $DesiredValue)
        {
            $NetAdapter | Set-NetAdapterAdvancedProperty -DisplayName $Property -DisplayValue $DesiredValue
            Write-Host "Set net adapter advanced property $Property to $DesiredValue" -ForegroundColor Yellow
        } else
        {
            Write-Host "Net adapter advanced property $Property is already set to $DesiredValue"
        }
    }
}

Write-Host "Configuring BIOS to automatically power on system"
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AcPwrRcvry" -DesiredValue 'On'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOn" -DesiredValue 'Everyday'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnHr" -DesiredValue '0'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnMn" -DesiredValue '5'

Write-Host "Configuring BIOS to support Wake On Lan (WOL)"
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\DeepSleepCtrl" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\WakeOnLan" -DesiredValue 'LanOnly'

if ($nic = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.PhysicalMediaType -eq '802.3'})
{
    Write-Host "Found $($nic.DriverProvider) netadapter with MAC $($nic.MacAddress)"

    #
    # Realtek and Intel cards that are common on Dell client computers have
    # different settings that need to be configured to support WOL so we base
    # our settings on which of those two we found.
    #
    # To get the advanced properties for your adapter run the following:
    #
    # Get-NetAdapter -Name Ethernet | Get-NetAdapterAdvancedProperty | Sort-Object DisplayName | Select-Object DisplayName,DisplayValue
    #
    switch ($nic.DriverProvider)
    {
        'Realtek'
        {
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Advanced EEE'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy-Efficient Ethernet'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy Efficient Ethernet'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Gigabit Lite'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Green Ethernet'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Shutdown Wake-On-Lan' -DesiredValue 'Enabled'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on Magic Packet' -DesiredValue 'Enabled'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on pattern match' -DesiredValue 'Enabled'
        }
        'Intel'
        {
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy-Efficient Ethernet'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy Efficient Ethernet' -DesiredValue 'Off'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Reduce Speed On Power Down'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'System Idle Power Saver'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Ultra Low Power Mode'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on Link Settings' -DesiredValue 'Forced'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on Magic Packet' -DesiredValue 'Enabled'
            Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on pattern match' -DesiredValue 'Enabled'
        }
        default
        {
            Write-Host "Unknown network adapter type '$($nic.DriverProvider)'. No settings changed!" -ForegroundColor Yellow
        }
    }
}

Write-Host "Finished"

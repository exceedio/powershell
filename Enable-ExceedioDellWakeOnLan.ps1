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
    Modified: Oct 9, 2024
#>

[CmdletBinding()]
param()

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

#Write-Host "Configuring BIOS to support Wake On Lan (WOL)"
#Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
#Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\DeepSleepCtrl" -DesiredValue 'Disabled'
#Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
#Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\WakeOnLan" -DesiredValue 'LanOnly'

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

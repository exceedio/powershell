#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Installs the Dell BIOS powershell module
.DESCRIPTION
    Silently installs the Dell BIOS powershell module that is used to configure
    BIOS settings for Dell client computers.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Install-ExceedioDellBIOSProvider.ps1 | iex
.NOTES
    Filename: Install-ExceedioDellBIOSProvider.ps1
    Author:   jreese@exceedio.com
    Modified: Oct 1, 2024
#>

[CmdletBinding()]
param(
)

#
# Older versions of PowerShell default to TLS 1.0, which is incompatible with
# modern repositories like the PowerShell Gallery. Setting the security protocol
# to TLS 1.2 ensures secure connections
#
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#
# We need to ensure that the Nuget package provider is installed on this system
# and we attempt to do so silently. Important that -ListAvailable is used in the
# call to Get-PackageProvider otherwise it prompts you to install on that step
#
$nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
if (-not ($nuget))
{
    Write-Host "Installing NuGet package provider"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Confirm:$false
} else
{
    Write-Host "NuGet package provider version $($nuget.Version) is already installed"
}

#
# The PSGallery repository must be trusted in order to silently install modules
# from the gallery. We may optionally choose to set this back to untrusted after
# the module has been installed.
#
if (Get-PSRepository -Name PSGallery -ErrorAction Stop)
{
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted')
    {
        Write-Host "Configuring PSGallery repository as trusted"
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    } else
    {
        Write-Host "PSGallery repository is already trusted"
    }
} else
{
    Write-Host "PSGallery repository is not installed" -ForegroundColor Yellow
}

#
# Finally, we check to make sure that the DellBIOSProvider is available and
# install it if not. It is installed for all users as we're not sure where this
# script may be called from
#
if (-not (Get-Module -ListAvailable -Name DellBIOSProvider))
{
    Write-Host "Installing the DellBIOSProvider module"
    Install-Module -Name DellBIOSProvider -MinimumVersion 2.8.0 -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop
} else
{
    Write-Host "DellBIOSProvider module is already installed"
}

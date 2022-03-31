<#
.SYNOPSIS
    Installs the modules that we use in our DSC configurations
.DESCRIPTION
    Installs the NuGet package provider and then installs DSC resource
    modules that are used throughout other scripts in this repository.
    This must be run before other scripts.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Install-RequiredModules.ps1'))
.NOTES
    Filename : Install-RequiredModules.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 31, 2022
#>

#
# required to install modules from NuGet
#
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

#
# required for the DSC resources that we utilize
#
Install-Module -Name PSDscResources -Scope AllUsers -Force
Install-Module -Name ComputerManagementDsc -Scope AllUsers -Force
Install-Module -Name NetworkingDsc -Scope AllUsers -Force
Install-Module -Name StorageDsc -Scope AllUsers -Force
Install-Module -Name xHyper-V -Scope AllUsers -Force
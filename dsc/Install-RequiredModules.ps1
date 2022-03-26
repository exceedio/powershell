<#
.SYNOPSIS
    Installs the modules that we use in our DSC configurations.
.DESCRIPTION

.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Install-RequiredModules.ps1'))
.NOTES
    Filename : Install-RequiredModules.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 26, 2022
#>

Install-Module -Name PSDscResources -Scope AllUsers -Force
Install-Module -Name ComputerManagementDsc -Scope AllUsers -Force
Install-Module -Name NetworkingDsc -Scope AllUsers -Force
Install-Module -Name StorageDsc -Scope AllUsers -Force
Install-Module -Name xHyper-V -Scope AllUsers -Force

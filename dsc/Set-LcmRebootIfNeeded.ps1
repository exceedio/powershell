<#
.SYNOPSIS
    Configures DSC local configuration manager to reboot if needed.
.DESCRIPTION
    Running this script configures the Desired State Configuration (DSC) local configuration
    manager (LCM) to automatically reboot on its own while bringing a machine into the desired
    state. This should be run prior to running a DSC configuration for the first time.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Set-LcmRebootIfNeeded.ps1'))
.NOTES
    Filename : Set-LcmRebootIfNeeded.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 26, 2022
#>

[DSCLocalConfigurationManager()]
Configuration LcmRebootIfNeeded {
    Node 'localhost' {
        Settings {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndMonitor'
            RebootNodeIfNeeded = $true
        }
    }
}

LcmRebootIfNeeded -Output "$env:systemdrive\Dsc"
Set-DscLocalConfigurationManager -Path "$env:systemdrive\Dsc" -Verbose
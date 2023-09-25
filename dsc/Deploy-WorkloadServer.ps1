<#
.SYNOPSIS
    Initializes a Windows server.
.DESCRIPTION
    Prepares a fresh installation of Windows Server 2022 on a virtual machine.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Deploy-WorkloadServer.ps1'))
.NOTES
    Filename : Deploy-WorkloadServer.ps1
    Author   : jreese@exceedio.com
    Modified : Sep 25, 2023
#>

if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
}

if (-not (Get-InstalledModule -Name PSDscResourcesa -ErrorAction SilentlyContinue)) {
    Install-Module -Name PSDscResources -Scope AllUsers -Force
}

if (-not (Get-InstalledModule -Name ComputerManagementDsc -ErrorAction SilentlyContinue)) {
    Install-Module -Name ComputerManagementDsc -Scope AllUsers -Force
}

if (-not (Get-InstalledModule -Name NetworkingDsc -ErrorAction SilentlyContinue)) {
    Install-Module -Name NetworkingDsc -Scope AllUsers -Force
}

Configuration WorkloadServer {

    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName
    )

    #
    # make sure to run Install-RequiredModules.ps1 if you're running
    # into an error here
    #

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName NetworkingDsc

    Node 'localhost' {

        Computer SetComputerName {
            Name = $ComputerName
        }
                
        Registry HideFirstRunExperience {
            Key = 'HKLM:\SOFTWARE\Policies\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }

        Registry DisableEdgePasswordManager {
            Key = 'HKLM:\SOFTWARE\Policies\SOFTWARE\Policies\Microsoft\Edge'
            Ensure = 'Present'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force = $true
        }

        Registry DisableOpenServerManagerAtLogon {
            Key = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            Ensure = 'Present'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }

        RemoteDesktopAdmin EnableRdp {
            IsSingleInstance = 'Yes'
            Ensure = 'Present'
            UserAuthentication = 'Secure'
        }

        Firewall EnableRemoteDesktop-In-TCP-WS {
            Name = 'RemoteDesktop-In-TCP-WS'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-In-TCP-WSS {
            Name = 'RemoteDesktop-In-TCP-WSS'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-Shadow-In-TCP {
            Name = 'RemoteDesktop-Shadow-In-TCP'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-UserMode-In-TCP {
            Name = 'RemoteDesktop-UserMode-In-TCP'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-UserMode-In-UDP {
            Name = 'RemoteDesktop-UserMode-In-UDP'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        FirewallProfile EnablePrivateFirewallProfile {
            Name = 'Private'
            Enabled = 'True'
            DefaultInboundAction = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules = 'True'
            NotifyOnListen = 'False'
            LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes = 16384
            LogAllowed = 'False'
            LogBlocked = 'True'
            LogIgnored = 'NotConfigured'
        }

        FirewallProfile EnableDomainFirewallProfile {
            Name = 'Domain'
            Enabled = 'True'
            DefaultInboundAction = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules = 'True'
            NotifyOnListen = 'False'
            LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes = 16384
            LogAllowed = 'False'
            LogBlocked = 'True'
            LogIgnored = 'NotConfigured'
        }

        FirewallProfile EnablePublicFirewallProfile {
            Name = 'Public'
            Enabled = 'True'
            DefaultInboundAction = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules = 'True'
            NotifyOnListen = 'False'
            LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes = 16384
            LogAllowed = 'False'
            LogBlocked = 'True'
            LogIgnored = 'NotConfigured'
        }

        Service DisableDefragService {
            Name = 'defragsvc'
            Ensure = 'Present'
            StartupType = 'Manual'
            State = 'Stopped'
        }

        Service EnableW32TimeService {
            Name = 'W32Time'
            Ensure = 'Present'
            StartupType = 'Automatic'
            State = 'Running'
        }
    }
}

$computerName = Select-ComputerName

#
# generate the configuration
#
WorkloadServer `
    -ComputerName $computerName `
    -OutputPath "$env:systemdrive\Dsc"

#
# implement the configuration
#

Start-DscConfiguration `
    -Path "$env:systemdrive\Dsc" `
    -Force `
    -Wait `
    -Verbose
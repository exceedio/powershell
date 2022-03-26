<#
.SYNOPSIS
    Initializes a Dell server running Windows Server 2022 for Hypervisor role.
.DESCRIPTION
    Prepares a fresh installation of Windows Server 2022 on a Dell PowerEdge Rxxx server.
    This scripts makes a lot of assumptions about how you want your Hyper-V parent to be
    configured. Do not blindly run this script.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Deploy-Hypervisor.ps1'))
.NOTES
    Filename : Deploy-Hypervisor.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 26, 2022
#>

Configuration Hypervisor {

    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $StorageDiskUniqueId

    )

    #
    # make sure to run Install-RequiredModules.ps1 if you're running
    # into an error here
    #

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName xHyper-V

    Node 'localhost' {

        Computer SetComputerName {
            Name = $ComputerName
        }
        
        WindowsOptionalFeature Snmp {
            Name = 'SNMP'
            Ensure = 'Present'
        }
        
        Registry DisableRdpPrinterMapping {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure = 'Present'
            ValueName = 'fDisableCpm'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }

        RemoteDesktopAdmin EnableRdp {
            IsSingleInstance = 'Yes'
            Ensure = 'Present'
            UserAuthentication = 'Secure'
        }

        Firewall RemoteDesktop-In-TCP-WS {
            Name = 'RemoteDesktop-In-TCP-WS'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall RemoteDesktop-In-TCP-WSS {
            Name = 'RemoteDesktop-In-TCP-WSS'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall RemoteDesktop-Shadow-In-TCP {
            Name = 'RemoteDesktop-Shadow-In-TCP'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall RemoteDesktop-UserMode-In-TCP {
            Name = 'RemoteDesktop-UserMode-In-TCP'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall RemoteDesktop-UserMode-In-UDP {
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

        Service EnableW32Time {
            Name = 'W32Time'
            Ensure = 'Present'
            StartupType = 'Automatic'
            State = 'Running'
        }

        Service DisableDefragSvc {
            Name = 'defragsvc'
            Ensure = 'Present'
            StartupType = 'Manual'
            State = 'Stopped'
        }

        Script EnableTimeSyncWithGoogle {
            SetScript = {
                w32tm.exe /config /manualpeerlist:"time.google.com" /syncfromflags:manual /update | Out-Null
            }
            TestScript = {
                return ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1) -match "time.google.com")
            }
            GetScript = {
                return @{
                    Result = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1)
                }                
            }
            DependsOn = '[Service]EnableW32Time'
        }

        if ((Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine') {
            OpticalDiskDriveLetter SetDVDDriveLetter {
                DiskId = 1
                DriveLetter = 'Z'
            }
        }

        WaitForDisk StorageDisk {
            DiskId = $StorageDiskUniqueId
            DiskIdType = 'UniqueId'
            RetryIntervalSec = 60
            RetryCount = 60
            #DependsOn = '[OpticalDiskDriveLetter]SetDVDDriveLetter'
        }

        Disk StorageVolume {
            DiskId = $StorageDiskUniqueId
            DiskIdType = 'UniqueId'
            DriveLetter = 'D'
            FSLabel = 'Data'
            FSFormat = 'ReFS'
            AllocationUnitSize = 64KB
            DependsOn = '[WaitForDisk]StorageDisk'
        }

        WindowsFeature HyperV {
            Name = 'Hyper-V'
            Ensure = 'Present'
            DependsOn = '[Disk]StorageVolume'
        }

        WindowsFeature HyperVTools {
            Name = 'RSAT-Hyper-V-Tools'
            Ensure = 'Present'
            DependsOn = '[WindowsFeature]HyperV'
            IncludeAllSubFeature = $true
        }

        xVMHost HyperVStoragePaths {
            IsSingleInstance = 'Yes'
            VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks'
            VirtualMachinePath = 'D:\Hyper-V\Virtual Machines'
            DependsOn = '[WindowsFeature]HyperVTools'
        }
    }
}

#
# here we list non-boot disks that are candidates for storing virtual machines
#
Get-Disk | Where-Object IsBoot -eq $false | Format-Table Number,FriendlyName,UniqueId,@{label='SizeInGb';expression={$_.Size / 1Gb}}

#
# now we ask the caller to tell us which disk they want to use; we don't ask for
# the number of the disk - we need the unique id because according to MS the disk
# id can change between reboots
#
$storageDiskUniqueId = (Get-Disk -Number (Read-Host "Type the number of the disk that will be used to store virtual machines")).UniqueId

#
# ask the caller for the EID of this computer so that we can create the computer name
#
$computerName = "SV", (Read-Host "Type the EID of this hypervisor") -join ""

#
# generate the configuration
#
Hypervisor `
    -ComputerName $computerName `
    -StorageDiskUniqueId $storageDiskUniqueId `
    -OutputPath "$env:systemdrive\Dsc"

#
# implement the configuration
#
Start-DscConfiguration `
    -Path "$env:systemdrive\Dsc" `
    -Force `
    -Wait `
    -Verbose
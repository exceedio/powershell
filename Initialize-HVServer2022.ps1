<#
.SYNOPSIS
    Initializes a Dell server running Windows Server 2022 for Hypervisor role.
.DESCRIPTION
    Prepares a fresh installation of Windows Server 2022 on a Dell PowerEdge Rxxx server.
    This scripts makes a lot of assumptions about how you want your Hyper-V parent to be
    configured. Do not blindly run this script.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-HVServer2022.ps1 -UseBasicParsing | iex
.NOTES
    Filename : Initialize-HVServer2022.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 25, 2022
#>

Configuration Exceedio-HVServer2022 {

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

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName xHyperV

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

        Registry EnableRdp {
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
            Ensure = 'Present'
            ValueName = 'fDenyTSConnections'
            ValueType = 'DWord'
            ValueData = '0'
            Force = $true
        }

        Registry EnableRdpUserAuthentication {
            Key = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            Ensure = 'Present'
            ValueName = 'UserAuthentication'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }

        Firewall EnableRdpFirewallRule {
            Group = 'Remote Desktop'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private', 'Public')
        }

        Firewall EnableRdpFirewallRule {
            Group = 'Remote Desktop'
            Ensure = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private', 'Public')
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

        OpticalDiskDriverLetter SetDVDDriveLetter {
            DiskId = 1
            DriveLetter = 'Z'
        }

        WaitForDisk StorageDisk {
            DiskId = $StorageDiskUniqueId
            DiskIdType = 'UniqueId'
            RetryIntervalSec = 60
            RetryCount = 60
            DependsOn = '[OpticalDiskDriverLetter]SetDVDDriveLetter'
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

        xVMHost SetVMPaths {
            Name = 'Hyper-V'
            Ensure = 'Present'
            IncludeAllSubFeature = $true
            DependsOn = '[WindowsFeature]HyperV'
        }
    }
}

#
# here we list non-boot disks that are candidates for storing virtual machines
#
Get-Disk | Where-Object IsBoot -eq $false | Select-Object Number,FriendlyName,UniqueId,@{label='SizeInGb';expression={$_.Size / 1Gb}}

#
# now we ask the caller to tell us which disk they want to use; we don't ask for
# the number of the disk - we need the unique id because according to MS the disk
# id can change between reboots
#
$storageDiskUniqueId = Read-Host "Type the UniqueId of the disk that will be used to store virtual machines"

#
# ask the caller for the EID of this computer so that we can create the computer name
#
$computerName = "SV", (Read-Host "Type the EID of this hypervisor") -join ""

#
# generate the configuration
#
Exceedio-HVServer2022 `
    -ComputerName $computerName `
    -StorageDiskUniqueId $storageDiskUniqueId `
    -OutputPath "$env:temp\dsc"

#
# implement the configuration
#
Start-DscConfiguration `
    -Path "$env:temp\dsc" `
    -Force `
    -Wait `
    -Verbose
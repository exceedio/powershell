<#
.SYNOPSIS
    Initializes a Dell server running Hyper-V Server 2016
.DESCRIPTION
    Prepares a fresh installation of Hyper-V Server 2016 on a Dell PowerEdge Rxxx server.
    This scripts makes a lot of assumptions about how you want your Hyper-V parent to be
    configured. Do not blindly run this script.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-HVServer2016.ps1 -UseBasicParsing | iex
#>

#
# disable printer mapping for RDP
#

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCpm' -Value 1 -Type DWord -Force

#
# enable RDP
#

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -Type DWord -Force

#
# disable Windows Firewall
#

Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

#
# disable task offload globally
#
Set-NetOffloadGlobalSetting -TaskOffload Disabled

#
# change cd-rom letter
#

$cdrom = Get-WmiObject Win32_Volume -Filter 'DriveType=5'
if ($cdrom) {
    $cdrom.DriveLetter = 'E:'
    $cdrom.Put() | Out-Null
}

#
# prepare data volume
#

Get-Partition | Sort-Object Size | Select-Object -Last 1 | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport $false
Get-Partition | Sort-Object Size | Select-Object -Last 1 | Set-Partition -NewDriveLetter 'D'

#
# configure hyper-v defaults
#

Set-VMHost -VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks' -VirtualMachinePath 'D:\Hyper-V'

#
# configure networking
#

$nics = @(Get-NetAdapter)
$vmswitchname = 'External Virtual Switch'

if ($nics.Length -eq 4) {
    if (!(Get-NetLbfoTeam -Name MGTeam -ErrorAction SilentlyContinue)) {
        New-NetLbfoTeam -Name MGTeam -TeamMembers NIC1,NIC2 -TeamNicName VIC1 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
    }

    if (!(Get-NetLbfoTeam -Name VMTeam -ErrorAction SilentlyContinue)) {
        New-NetLbfoTeam -Name VMTeam -TeamMembers NIC3,NIC4 -TeamNicName VIC2 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        New-VMSwitch -Name $vmswitchname -NetAdapterName VIC2 -AllowManagementOS 0 | Out-Null
    }
}

#
# set computer name based on asset tag
#


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

$restartneeded = $false

#
# prevent print drivers from being loaded
# on this server when we connect to it via
# RDP
#

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCpm' -Value 1 -Type DWord -Force

#
# enable RDP for all clients
#

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -Type DWord -Force

#
# disable task offload globally - this is
# to prevent known problems with Broadcom
# network cards
#
if ((Get-NetOffloadGlobalSetting).TaskOffload -ne 'Disabled') {
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
}

#
# change cd-rom letter to make room for D:
#

$cdrom = Get-WmiObject Win32_Volume -Filter 'DriveType=5'
if ($cdrom) {
    $cdrom.DriveLetter = 'E:'
    $cdrom.Put() | Out-Null
}

#
# prepare data volume - we find the largest
# partition in the server and format as D: with
# a volume label of 'Data'
#

if (!(Get-Volume -FileSystemLabel Data -ErrorAction SilentlyContinue)) {
    Get-Partition | Sort-Object Size | Select-Object -Last 1 | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport $false
    Get-Partition | Sort-Object Size | Select-Object -Last 1 | Set-Partition -NewDriveLetter 'D'
}

#
# configure hyper-v defaults - this is where virtual
# machine configuration files and virtual hard disks
# will be located
#

if ((Get-VMHost).VirtualHardDiskPath -ne 'D:\Hyper-V\Virtual Hard Disks') {
    Set-VMHost -VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks'
}
if ((Get-VMHost).VirtualMachinePath -ne 'D:\Hyper-V') {
    Set-VMHost -VirtualMachinePath 'D:\Hyper-V'
}

#
# configure networking - we take into account servers with
# two or four NICs. servers with more than that will need
# to be configured manually.
#
#   4: team the first two as 'MGTeam' and use that
#      for management traffic; team the last two as
#      as 'VMTeam' and use that for virtual machine
#      traffic.
#
#   2: no teaming; use second NIC for virtual machine
#      traffic.
#

$nics         = @(Get-NetAdapter)
$vmswitchname = 'External Virtual Switch'
$mgteamname   = 'MGTeam'
$vmteamname   = 'VMTeam'
$vmswitchnic  = ''

if ($nics.Length -eq 4) {
    if ((Get-NetLbfoTeam).Name -notcontains $mgteamname) {
        New-NetLbfoTeam -Name $mgteamname -TeamMembers NIC1,NIC2 -TeamNicName VIC1 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
    }

    if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
        New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4 -TeamNicName VIC2 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
    }
    $vmswitchnic = 'VIC2'
}
elseif ($nics.Length -eq 2) {
    $vmswitchnic = 'NIC2'
}
else {
    Write-Host "Strange number of NICs found; you'll need to configuring teaming and virtual switch manually" -ForegroundColor Yellow
}


if (((Get-VMSwitch).Name -notcontains $vmswitchname) -and ($vmswitchnic -ne '')) {
    New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
}

#
# disabling VMQ on all network adapters prevents known
# problems with Broadcom adapters
#

Get-NetAdapter | Set-NetAdapterVmq -Enabled $false

#
# configure time synchronization
#

sc.exe config W32Time start= auto | Out-Null
sc.exe start W32Time | Out-Null
w32tm.exe /config /manualpeerlist:"0.us.pool.ntp.org,1.us.pool.ntp.org,2.us.pool.ntp.org,3.us.pool.ntp.org" /syncfromflags:manual /update | Out-Null


#
# add a user
#

$username = Read-Host "Type the username of the local admin"
if ((Get-LocalUser).Name -notcontains $username) {
    net.exe user $username * /add
    net.exe localgroup Administrators $username /add | Out-Null
    wmic.exe useraccount where name=`"$username`" set PasswordExpires=False | Out-Null
}

#
# download Dell-specific stuff
#

iwr http://downloads.dell.com/FOLDER03944869M/3/SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE -UseBasicParsing -OutFile SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE
iwr http://downloads.dell.com/FOLDER03940499M/3/SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE -UseBasicParsing -OutFile SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE
iwr http://downloads.dell.com/FOLDER03909716M/1/OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe -UseBasicParsing -OutFile OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe

#
# install OMSA
#

if (!(Test-Path 'C:\Program Files\Dell\SysMgt\omsa')) {
    .\OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe /auto .\OMSA
    msiexec.exe /i .\OMSA\windows\SystemsManagementx64\SysMgmtx64.msi /qb /norestart
}

#
# disable Windows Firewall
#

Get-NetFirewallProfile -All | Where Enabled -eq $true | Set-NetFirewallProfile -Enabled False

#
# create location for ISO files
#

New-Item -Path 'C:\Users\Public\Documents\ISO' -ItemType Directory -Force

#
# set computer name based on asset tag - this is why it
# is important to set asset tag in BIOS during the initial
# provisioning step
#

$newname = -Join('SV', (Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)
if ($env:computername -ne $newname) {
    Write-Host "Computer will now restart; run this script again after restart to continue"
    pause
    Rename-Computer -NewName $newname -Restart
}

#
# finish up
#

Write-Host "Server has been successfully initialized" -ForegroundColor Green

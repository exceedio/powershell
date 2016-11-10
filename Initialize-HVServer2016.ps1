<#
.SYNOPSIS
    Initializes a Dell server running Hyper-V Server 2016
.DESCRIPTION
    Prepares a fresh installation of Hyper-V Server 2016 on a Dell PowerEdge Rxxx server.
    This scripts makes a lot of assumptions about how you want your Hyper-V parent to be
    configured. Do not blindly run this script.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-HVServer2016.ps1 -UseBasicParsing | iex
.NOTES
    Filename : Initialize-HVServer2016.ps1
    Author   : jreese@exceedio.com
    Modified : Nov, 10, 2016
#>

#
# prevent print drivers from being loaded
# on this server when we connect to it via
# RDP
#

if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')) {
    Write-Warning "Creating Terminal Services policy registry key"
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
}

if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableCpm -ne 1) {
    Write-Warning "Disabling printer mapping for RDP connections"
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCpm' -Value 1 -Type DWord -Force
} else {
    Write-Output "Printer mapping for RDP connections has already been disabled"
}

pause

#
# enable RDP for all clients
#

if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -ne 0) {
    Write-Warning "Enabling RDP connections"
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
} else {
    Write-Output "RDP connections are already enabled"
}

pause

if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -ne 0) {
    Write-Warning "Enabling RDP connections for all clients"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -Type DWord -Force
} else {
    Write-Output "RDP connections for all clients are already enabled"
}

pause

if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').SecurityLayer -ne 0) {
    Write-Warning "Changing RDP security layer from 2 to 0"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 0 -Type DWord -Force
} else {
    Write-Output "RDP security layer is already set to 0"
}

pause

#
# disable task offload globally - this is
# to prevent known problems with Broadcom
# network cards
#

if ((Get-NetOffloadGlobalSetting).TaskOffload -ne 'Disabled') {
    Write-Warning "Disabling task offload"
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
} else {
    Write-Output "Task offload is already disabled"
}

pause

#
# change cd-rom letter to make room for D:
#

$cdrom = Get-WmiObject Win32_Volume -Filter 'DriveType=5 and DriveLetter="E:"'
if (!($cdrom)) {
    Write-Warning "Setting CD-ROM drive letter"
    $cdrom.DriveLetter = 'E:'
    $cdrom.Put() | Out-Null
} else {
    Write-Output "CD-ROM drive letter has already been set"
}

pause

#
# prepare data volume - we find the largest
# partition in the server and format as D: with
# a volume label of 'Data'
#

if (!(Get-Volume -FileSystemLabel Data -ErrorAction SilentlyContinue)) {
    #Write-Warning "Preparing data volume"
    #Get-Partition | Sort-Object Size | Select-Object -Last 1 | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport $false -Confirm
    #Get-Partition | Sort-Object Size | Select-Object -Last 1 | Set-Partition -NewDriveLetter 'D'
    Write-Warning "Use Get-Partition | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport `$false to format data volume"
    pause
} else {
    Write-Output "Data volume has already been prepared"
}

pause

#
# configure hyper-v defaults - this is where virtual
# machine configuration files and virtual hard disks
# will be located
#

if ((Get-VMHost).VirtualHardDiskPath -ne 'D:\Hyper-V\Virtual Hard Disks') {
    Write-Warning "Setting default virtual hard disk path"
    Set-VMHost -VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks'
} else {
    Write-Output "Virtual hard disk path has already been set"
}

pause

if ((Get-VMHost).VirtualMachinePath -ne 'D:\Hyper-V') {
    Write-Warning "Setting default virtual machine path"
    Set-VMHost -VirtualMachinePath 'D:\Hyper-V'
} else {
    Write-Output "Virtual machine path has already been set"
}

pause

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


if ((Get-NetLbfoTeam).Name -notcontains $mgteamname) {
    if ($nics.Length -eq 4) {
        Write-Warning "Teaming NIC1 and NIC2 for management traffic"
        New-NetLbfoTeam -Name $mgteamname -TeamMembers NIC1,NIC2 -TeamNicName VIC1 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
    } elseif ($nics.Length -eq 2) {
        Write-Warning "Using NIC1 for management traffic"
    }
    else {
        Write-Warning "You have $($nics.Length) NICs; you'll need to configure teaming for $mgteamname manually"
    }
} else {
    Write-Output "Management team already exists"
}

if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
    if ($nics.Length -eq 4) {
        Write-Warning "Teaming NIC3 and NIC4 for virtual machine traffic"
        New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4 -TeamNicName VIC2 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        $vmswitchnic = 'VIC2'
    } elseif ($nics.Length -eq 2) {
        Write-Warning "Using NIC2 for virtual machine traffic"
        $vmswitchnic = 'NIC2'
    }
    else {
        Write-Warning "You have $($nics.Length) NICs; you'll need to configure teaming for $vmteamname manually"
    }
} else {
    Write-Output "Virtual machine team already exists"
}

if ($vmswitchnic -ne '') {
    if ((Get-VMSwitch).Name -notcontains $vmswitchname) {
        Write-Warning "Creating virtual switch $vmswitchname on $vmswitchnic"
        New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
    }
    else {
        Write-Output "Virtual switch $vmswitchname already exists"
    }
} else {
    Write-Warning "Could not reliability determine if virtual switch exists; you'll need to configure manually"
}

pause

#
# disabling VMQ on all network adapters prevents known
# problems with Broadcom adapters
#

if (Get-NetAdapterVmq | where Enabled -eq $true) {
    Write-Warning "Disabling VMQ on all network adapters"
    Get-NetAdapter | Set-NetAdapterVmq -Enabled $false
} else {
    Write-Output "VMQ has already been disabled on all network adapters"
}

pause

#
# configure time synchronization
#

if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1) -notmatch '0.us.pool.ntp.org') {
    Write-Warning "Configuring time synchronization with pool.ntp.org"
    sc.exe config W32Time start= auto | Out-Null
    sc.exe start W32Time | Out-Null
    w32tm.exe /config /manualpeerlist:"0.us.pool.ntp.org,1.us.pool.ntp.org,2.us.pool.ntp.org,3.us.pool.ntp.org" /syncfromflags:manual /update | Out-Null
} else {
    Write-Output "Time synchronization is already configured for pool.ntp.org"
}

pause

#
# download Dell-specific stuff
#

if ((gwmi Win32_ComputerSystem).Model -eq 'PowerEdge R530') {
    Write-Output "Downloading BIOS, firmware, and drivers for $((gwmi Win32_ComputerSystem).Model)"
    iwr http://downloads.dell.com/FOLDER03919962M/1/BIOS_02H3F_WN64_2.2.5.EXE -UseBasicParsing -OutFile BIOS_02H3F_WN64_2.2.5.EXE
    iwr http://downloads.dell.com/FOLDER03884128M/1/iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE -UseBasicParsing -OutFile iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE
    iwr http://downloads.dell.com/FOLDER03897782M/1/Network_Firmware_FC41D_WN64_20.02.05.04.EXE -UseBasicParsing -OutFile Network_Firmware_FC41D_WN64_20.02.05.04.EXE
    iwr http://downloads.dell.com/FOLDER03944869M/3/SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE -UseBasicParsing -OutFile SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE
    iwr http://downloads.dell.com/FOLDER03940499M/3/SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE -UseBasicParsing -OutFile SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE
} else {
    Write-Warning "Modify this script to download BIOS, firmware, and drivers for model $((gwmi Win32_ComputerSystem).Model)"
}

iwr http://downloads.dell.com/FOLDER03909716M/1/OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe -UseBasicParsing -OutFile OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe
iwr http://downloads.dell.com/FOLDER03906702M/1/OM-iSM-Dell-Web-X64-2.4.0-358_A00.exe -UseBasicParsing -OutFile OM-iSM-Dell-Web-X64-2.4.0-358_A00.exe

pause

#
# install OMSA
#

#if (!(Test-Path 'C:\Program Files\Dell\SysMgt\omsa')) {
#    Write-Warning "Installing Openmanage Server Administrator"
#    .\OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe /auto .\OMSA
#    msiexec.exe /i .\OMSA\windows\SystemsManagementx64\SysMgmtx64.msi /qb /norestart
#} else {
#    Write-Output "Openmanage Server Administrator is already installed"
#}

#
# temporarily disable Windows Firewall
#

if (Get-NetFirewallProfile -All | Where Enabled -eq $true) {
    Write-Warning "Disabling all firewall profiles"
    Get-NetFirewallProfile -All | Set-NetFirewallProfile -Enabled False
} else {
    Write-Output "All firewall profiles are already disabled"
}

pause

#
# create location for ISO files
#

if (!(Test-Path 'C:\Users\Public\Documents\ISO')) {
    Write-Warning "Creating location for ISO files"
    New-Item -Path 'C:\Users\Public\Documents\ISO' -ItemType Directory -Force | Out-Null
} else {
    Write-Output "ISO file location already exists"
}

pause

#
# set computer name based on asset tag - this is why it
# is important to set asset tag in BIOS during the initial
# provisioning step
#

$newname = -Join('SV', (Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)
if ($env:computername -ne $newname) {
    Write-Warning "Computer name will be changed to $newname and will restart; run this script again after restart to continue"
    pause
    Rename-Computer -NewName $newname -Restart
} else {
    Write-Output "Computer name has already been changed"
}

pause

#
# configure idrac address and change default password
#

$racip = Read-Host "What is the desired iDRAC address (e.g. 192.168.0.201)?"
$racnm = Read-Host "What is the desired iDRAC netmask (e.g. 255.255.255.0)?"
$racgw = Read-Host "What is the desired iDRAC gateway (e.g. 192.168.0.1)?"
$racpw = Read-Host "What is the Dell iDRAC ($newname) password?"

Write-Output "Configuring iDRAC address and setting password"
racadm set iDRAC.IPv4.Address $racip | Out-Null
racadm set iDRAC.IPv4.Netmask $racnm | Out-Null
racadm set iDRAC.IPv4.Gateway $racgw | Out-Null
racadm set iDRAC.IPv4.DNS1 8.8.8.8 | Out-Null
racadm set iDRAC.IPv4.DNS2 8.8.4.4 | Out-Null
racadm set iDRAC.Users.2.Password $racpw | Out-Null

#
# add a user
#

$username = Read-Host "Type the username of the local admin"
if ((Get-LocalUser).Name -notcontains $username) {
    Write-Warning "Creating local administrator"
    net.exe user $username * /add
    net.exe localgroup Administrators $username /add | Out-Null
    wmic.exe useraccount where name=`"$username`" set PasswordExpires=False | Out-Null
} else {
    Write-Output "Local administrator already exists"
}

#
# finish up
#

Write-Output "Server has been successfully initialized"

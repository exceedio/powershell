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
# prevent print drivers from being loaded
# on this server when we connect to it via
# RDP
#

if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableCpm -ne 1) {
    Write-Host "Disabling printer mapping for RDP connections"
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCpm' -Value 1 -Type DWord -Force
} else {
    Write-Host "Printer mapping for RDP connections has already been disabled" -ForegroundColor Green
}

#
# enable RDP for all clients
#

if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -ne 0) {
    Write-Host "Enabling RDP connections"
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
} else {
    Write-Host "RDP connections are already enabled" -ForegroundColor Green
}

if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -ne 0) {
    Write-Host "Enabling RDP connections for all clients"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -Type DWord -Force
} else {
    Write-Host "RDP connections for all clients are already enabled" -ForegroundColor Green
}

#
# disable task offload globally - this is
# to prevent known problems with Broadcom
# network cards
#

if ((Get-NetOffloadGlobalSetting).TaskOffload -ne 'Disabled') {
    Write-Progress -Activity $activity -Status 'Disabling task offload' -PercentComplete ((2 / $steps) * 100)
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
} else {
    Write-Host "Task offload is already disabled" -ForegroundColor Green
}

#
# change cd-rom letter to make room for D:
#

$cdrom = Get-WmiObject Win32_Volume -Filter 'DriveType=5 and DriveLetter="E:"'
if ($cdrom) {
    Write-Host "SEtting CD-ROM drive letter"
    $cdrom.DriveLetter = 'E:'
    $cdrom.Put() | Out-Null
} else {
    Write-Host "CD-ROM drive letter has already been set" -ForegroundColor Green
}

#
# prepare data volume - we find the largest
# partition in the server and format as D: with
# a volume label of 'Data'
#

if (!(Get-Volume -FileSystemLabel Data -ErrorAction SilentlyContinue)) {
    Write-Host "Preparing data volume"
    Get-Partition | Sort-Object Size | Select-Object -Last 1 | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport $false
    Get-Partition | Sort-Object Size | Select-Object -Last 1 | Set-Partition -NewDriveLetter 'D'
} else {
    Write-Host "Data volume has already been prepared" -ForegroundColor Green
}

#
# configure hyper-v defaults - this is where virtual
# machine configuration files and virtual hard disks
# will be located
#

if ((Get-VMHost).VirtualHardDiskPath -ne 'D:\Hyper-V\Virtual Hard Disks') {
    Write-Host "Setting default virtual hard disk path"
    Set-VMHost -VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks'
} else {
    Write-Host "Virtual hard disk path has already been set" -ForegroundColor Green
}

if ((Get-VMHost).VirtualMachinePath -ne 'D:\Hyper-V') {
    Write-Host "Setting default virtual machine path"
    Set-VMHost -VirtualMachinePath 'D:\Hyper-V'
} else {
    Write-Host "Virtual machine path has already been set" -ForegroundColor Green
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


if ((Get-NetLbfoTeam).Name -notcontains $mgteamname) {
    if ($nics.Length -eq 4) {
        Write-Host "Teaming NIC1 and NIC2 for management traffic"
        New-NetLbfoTeam -Name $mgteamname -TeamMembers NIC1,NIC2 -TeamNicName VIC1 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
    } elseif ($nics.Length -eq 2) {
        Write-Host "Using NIC1 for management traffic"
    }
} else {
    Write-Host "Management team already exists" -ForegroundColor Green
}

if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
    if ($nics.Length -eq 4) {
        Write-Host "Teaming NIC3 and NIC4 for virtual machine traffic"
        New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4 -TeamNicName VIC2 -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        $vmswitchnic = 'VIC2'
    } elseif ($nics.Length -eq 2) {
        Write-Host "Using NIC2 for virtual machine traffic"
        $vmswitchnic = 'NIC2'
    }
} else {
    Write-Host "Virtual machine team already exists" -ForegroundColor Green
}

if (((Get-VMSwitch).Name -notcontains $vmswitchname) -and ($vmswitchnic -ne '')) {
    Write-Host "Creating virtual switch $vmswitchname on $vmswitchnic"
    New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
} else {
    Write-Host "Virtual switch $vmswitchname already exists" -ForegroundColor Green
}

#
# disabling VMQ on all network adapters prevents known
# problems with Broadcom adapters
#

Write-Host "Disabling VMQ on all network adapters"
Get-NetAdapter | Set-NetAdapterVmq -Enabled $false

#
# configure time synchronization
#

Write-Host "Configuring time synchronization with pool.ntp.org"
sc.exe config W32Time start= auto | Out-Null
sc.exe start W32Time | Out-Null
w32tm.exe /config /manualpeerlist:"0.us.pool.ntp.org,1.us.pool.ntp.org,2.us.pool.ntp.org,3.us.pool.ntp.org" /syncfromflags:manual /update | Out-Null


#
# add a user
#

$username = Read-Host "Type the username of the local admin"
if ((Get-LocalUser).Name -notcontains $username) {
    Write-Host "Creating local administrator"
    net.exe user $username * /add
    net.exe localgroup Administrators $username /add | Out-Null
    wmic.exe useraccount where name=`"$username`" set PasswordExpires=False | Out-Null
} else {
    Write-Host "Local administrator already exists" -ForegroundColor Green
}

#
# download Dell-specific stuff
#

Write-Host "Downloading Dell-specific firmware, drivers, and software"
iwr http://downloads.dell.com/FOLDER03944869M/3/SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE -UseBasicParsing -OutFile SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE
iwr http://downloads.dell.com/FOLDER03940499M/3/SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE -UseBasicParsing -OutFile SAS-RAID_Driver_T244W_WN64_6.604.06.00_A01.EXE
iwr http://downloads.dell.com/FOLDER03909716M/1/OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe -UseBasicParsing -OutFile OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe

#
# install OMSA
#

if (!(Test-Path 'C:\Program Files\Dell\SysMgt\omsa')) {
    Write-Host "Installing Openmanage Server Administrator"
    .\OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe /auto .\OMSA
    msiexec.exe /i .\OMSA\windows\SystemsManagementx64\SysMgmtx64.msi /qb /norestart
} else {
    Write-Host "Openmanage Server Administrator is already installed" -ForegroundColor Green
}

#
# disable Windows Firewall
#

Write-Host "Disabling all firewall profiles"
Get-NetFirewallProfile -All | Where Enabled -eq $true | Set-NetFirewallProfile -Enabled False

#
# create location for ISO files
#

if (!(Test-Path 'C:\Users\Public\Documents\ISO')) {
    Write-Host "Creating location for ISO files"
    New-Item -Path 'C:\Users\Public\Documents\ISO' -ItemType Directory -Force | Out-Null
} else {
    Write-Host "ISO file location already exists" -ForegroundColor Green
}

#
# set computer name based on asset tag - this is why it
# is important to set asset tag in BIOS during the initial
# provisioning step
#

$newname = -Join('SV', (Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)
if ($env:computername -ne $newname) {
    Write-Host "Computer named changed and will now restart; run this script again after restart to continue"
    pause
    Rename-Computer -NewName $newname -Restart
} else {
    Write-Host "Computer name has already been changed" -ForegroundColor Green
}

#
# configure idrac address and change default password
#

$racip = Read-Host "What is the desired iDRAC address (e.g. 192.168.0.201)?"
$racnm = Read-Host "What is the desired iDRAC netmask (e.g. 255.255.255.0)?"
$racgw = Read-Host "What is the desired iDRAC gateway (e.g. 192.168.0.1)?"
$racpw = Read-Host "What is the documented iDRAC root password?"

Write-Host "Configuring iDRAC address and setting password"
racadm set iDRAC.IPv4.Address $racip | Out-Null
racadm set iDRAC.IPv4.Netmask $racnm | Out-Null
racadm set iDRAC.IPv4.Gateway $racgw | Out-Null
racadm set iDRAC.IPv4.DNS1 8.8.8.8 | Out-Null
racadm set iDRAC.IPv4.DNS2 8.8.4.4 | Out-Null
racadm set iDRAC.Users.2.Password $racpw | Out-Null

#
# finish up
#

Write-Host "Server has been successfully initialized" -ForegroundColor Green

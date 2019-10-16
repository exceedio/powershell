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

function Enable-WindowsFirewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

function Enable-SnmpService {
    if ((Get-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0).State -neq Installed) {
        Add-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0
    }
}

function Disable-PrinterMapping {
    if (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')) {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    }
    if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableCpm -ne 1) {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCpm' -Value 1 -Type DWord -Force
    }
}

function Enable-RDP {
    if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -ne 0) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
    }
    if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -ne 1) {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord -Force
    }
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

function Disable-NetOffloadGlobalSettingTaskOffload {
    #
    # prevents known problems with Broadcom network adapters
    #
    if ((Get-NetOffloadGlobalSetting).TaskOffload -ne 'Disabled') {
        Set-NetOffloadGlobalSetting -TaskOffload Disabled
    }
}

function Set-DvdRomDriveLetter {
    $cdrom = Get-WmiObject Win32_Volume -Filter 'DriveType=5'
    if (!($cdrom)) {
        $cdrom.DriveLetter = 'Z:'
        $cdrom.Put() | Out-Null
    }
}

function Set-DataVolume {
    if (!(Get-Volume -FileSystemLabel Data -ErrorAction SilentlyContinue)) {
        #Write-Warning "Preparing data volume"
        #Get-Partition | Sort-Object Size | Select-Object -Last 1 | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport $false -Confirm
        #Get-Partition | Sort-Object Size | Select-Object -Last 1 | Set-Partition -NewDriveLetter 'D'
        Write-Warning "Use Get-Partition | Format-Volume -AllocationUnitSize 65536 -FileSystem NTFS -NewFileSystemLabel 'Data' -ShortFileNameSupport `$false to format data volume"
        pause
    }
    if ((Get-VMHost).VirtualHardDiskPath -ne 'D:\Hyper-V\Virtual Hard Disks') {
        Set-VMHost -VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks'
    }
    if ((Get-VMHost).VirtualMachinePath -ne 'D:\Hyper-V') {
        Set-VMHost -VirtualMachinePath 'D:\Hyper-V'
    }
    if (Test-Path "C:\Users\Public\Documents\Hyper-V") {
        Remove-Item "C:\Users\Public\Documents\Hyper-V" -Recurse -Force
    }
}

function Enable-NICTeaming {
    $nics         = @(Get-NetAdapter)
    $vmswitchname = 'External Virtual Switch'
    $vmteamname   = 'VMTeam'
    $vmswitchnic  = 'VIC1'

    if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
        if ($nics.Length -eq 2) {
            New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC2 -TeamNicName $vmswitchnic -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        }
        if ($nics.Length -eq 4) {
            New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4 -TeamNicName $vmswitchnic -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        }
        if ((Get-VMSwitch).Name -notcontains $vmswitchname) {
            if ($vmswitchnic -ne '') {
                New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
            }
        }
    }
}

function Disable-VirtualMachineQueue {
    #
    # prevents known problems with Broadcom network adapters
    #
    if (Get-NetAdapterVmq | where Enabled -eq $true) {
        Get-NetAdapter | Set-NetAdapterVmq -Enabled $false -ErrorAction SilentlyContinue
    }
}

function Enable-TimeSynchronization {
    if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1) -notmatch 'time.google.com') {
        sc.exe config W32Time start= auto | Out-Null
        sc.exe start W32Time | Out-Null
        w32tm.exe /config /manualpeerlist:"time.google.com" /syncfromflags:manual /update | Out-Null
    }
}

function Install-OMSA {
    if ((gwmi Win32_ComputerSystem).Manufacturer -match 'Dell*') {
        Invoke-WebRequest https://downloads.dell.com/FOLDER05558179M/1/OM-SrvAdmin-Dell-Web-WINX64-9.3.0-3465_A00.exe -OutFile $env:temp\OM-SrvAdmin-Dell-Web-WINX64-9.3.0-3465_A00.exe
        $env:temp\OM-SrvAdmin-Dell-Web-WINX64-9.3.0-3465_A00.exe /auto $env:temp\OMSA
        msiexec.exe /i "$env:temp\OMSA\windows\SystemsManagementx64\SysMgmtx64.msi" /qb /norestart
    }
    if (!(Get-NetFirewallRule -DisplayName "OpenManage" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "OpenManage" -Direction Inbound -LocalPort 1311 -Protocol TCP -Action Allow
    }
    & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=ciphers setting=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=sslprotocol setting=TLSv1.2
	& "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% system webserver action=restart
}

function Install-FiveNineManager {
    Invoke-WebRequest https://exdo.blob.core.windows.net/public/59Manager.msi -OutFile "$env:temp\59Manager.msi"
    & msiexec.exe /i "$env:temp\59Manager.msi" /qb /norestart
}

function Download-InstallMedia {
    if (!(Test-Path 'C:\Users\Public\Documents\ISO')) {
        New-Item -Path 'C:\Users\Public\Documents\ISO' -ItemType Directory -Force | Out-Null
    }
    Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO'
    Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO'
    Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Pro_10_1903_64BIT_English_Pro_Ent_EDU_N_MLF_X22-02890.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Pro_10_1903_64BIT_English_Pro_Ent_EDU_N_MLF_X22-02890.ISO'
}

function Set-ComputerName {
    $newname = (-Join('SV', (Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)).Trim()
    if ($env:computername -ne $newname) {
        Rename-Computer -NewName $newname -Restart
    }
}

function Enable-iDRAC {
    param (
        $Address,
        $Netmask,
        $Gateway,
        $Password
    )
    if (Test-Path "$env:programfiles\Dell\SysMgt\idrac\racadm.exe") {
        racadm set iDRAC.IPv4.Address $Address | Out-Null
        racadm set iDRAC.IPv4.Netmask $Netmask | Out-Null
        racadm set iDRAC.IPv4.Gateway $Gateway | Out-Null
        racadm set iDRAC.IPv4.DNS1 8.8.8.8 | Out-Null
        racadm set iDRAC.IPv4.DNS2 8.8.4.4 | Out-Null
        racadm set iDRAC.Users.2.Password $Password | Out-Null
    }
}

$Address = Read-Host "What is the desired iDRAC address (e.g. 192.168.0.201)?"
$Netmask = Read-Host "What is the desired iDRAC netmask (e.g. 255.255.255.0)?"
$Gateway = Read-Host "What is the desired iDRAC gateway (e.g. 192.168.0.1)?"
$Password = Read-Host "What is the Dell iDRAC password?"


Enable-SnmpService
Disable-PrinterMapping
Enable-RDP
Disable-NetOffloadGlobalSettingTaskOffload
Set-DvdRomDriveLetter
Set-DataVolume
Enable-NICTeaming
Disable-VirtualMachineQueue
Install-OMSA
Enable-iDRAC -Address $Address -Netmask $Netmask -Gateway $Gateway -Password $Password
Install-FiveNineManager
Download-InstallMedia
Enable-WindowsFirewall

#
# this last function restarts the computer
#
Set-ComputerName
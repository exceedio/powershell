<#
.SYNOPSIS
    Initializes a Dell server running Hyper-V Server 2019
.DESCRIPTION
    Prepares a fresh installation of Hyper-V Server 2019 on a Dell PowerEdge Rxxx server.
    This scripts makes a lot of assumptions about how you want your Hyper-V parent to be
    configured. Do not blindly run this script.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-HVServer2019.ps1 -UseBasicParsing | iex
.NOTES
    Filename : Initialize-HVServer2019.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 23, 2021
#>

function Enable-WindowsFirewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

function Enable-SnmpService {
    if ((Get-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0).State -ne 'Installed') {
        Add-WindowsCapability -Online -Name SNMP.Client~~~~0.0.1.0
    }
}

function Disable-PrinterMapping {
    $terminalServicesRegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    if (!(Test-Path $terminalServicesRegKey)) {
        New-Item -Path $terminalServicesRegKey -ErrorAction SilentlyContinue
    }
    if ((Get-ItemProperty -Path $terminalServicesRegKey).fDisableCpm -ne 1) {
        Set-ItemProperty -Path $terminalServicesRegKey -Name 'fDisableCpm' -Value 1 -Type DWord -Force
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
        Get-Disk | Sort-Object 'Total Size' | Select-Object -Last 1 | New-Partition -UseMaximumSize -DriveLetter D | Format-Volume -FileSystem ReFS -NewFileSystemLabel 'Data' -Confirm:$false
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
    $nics         = @(Get-NetAdapter | Sort-Object Name)
    $vmswitchname = 'External Virtual Switch'
    $vmteamname   = 'VMTeam'
    $vmswitchnic  = 'VIC1'
    $nicnumber    = 1

    foreach ($nic in $nics) {
        $name = "NIC$nicnumber"
        if ($nic.Name -ne $name) {
            Rename-NetAdapter -Name $nic.Name -NewName $name   
        }
    }
    if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
        if ($nics.Length -eq 2) {
            New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC2 -TeamNicName $vmswitchnic -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
        }
        if ($nics.Length -eq 4) {
            New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4 -TeamNicName $vmswitchnic -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
            Disable-NetAdapter -Name NIC2 -Confirm:$false
        }
        if ($nics.Length -eq 6) {
            New-NetLbfoTeam -Name $vmteamname -TeamMembers NIC3,NIC4,NIC5,NIC6 -TeamNicName $vmswitchnic -TeamingMode SwitchIndependent -LoadBalancingAlgorithm Dynamic -Confirm:$false | Out-Null
            Disable-NetAdapter -Name NIC2 -Confirm:$false
        }
    }
    if ((Get-VMSwitch).Name -notcontains $vmswitchname) {
        if ($vmswitchnic -ne '') {
            New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
        }
    }
}

function Disable-VirtualMachineQueue {
    #
    # prevents known problems with Broadcom network adapters
    #
    if (Get-NetAdapterVmq | Where-Object Enabled -eq $true) {
        Get-NetAdapter | Set-NetAdapterVmq -Enabled $false -ErrorAction SilentlyContinue
    }
}

function Enable-TimeSynchronization {
    $timeserver = 'time.google.com'
    if ((Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1) -notmatch $timeserver) {
        sc.exe config W32Time start= auto | Out-Null
        sc.exe start W32Time | Out-Null
        w32tm.exe /config /manualpeerlist:"$timeserver" /syncfromflags:manual /update | Out-Null
    }
}

function Install-OMSA {
    if ((gwmi Win32_ComputerSystem).Manufacturer -match 'Dell*') {
        #
        # install omsa
        #
        $dellOmsaExeUrl = "https://dl.dell.com/FOLDER06454068M/1/OM-SrvAdmin-Dell-Web-WINX64-9.5.0-4063_A00.exe"
        $dellOmsaMspUrl = "https://dl.dell.com/FOLDER07057950M/1/SysMgmt_9501_x64_patch_A00.msp"
        $dellOmsaPath   = Join-Path $env:temp "omsa"
        $dellOmsaExe    = Join-Path $dellOmsaPath "OM-SrvAdmin-Dell-Web-WINX64-Latest.exe"
        $dellOmsaMsi    = Join-Path $dellOmsaPath "windows\SystemsManagementx64\SysMgmtx64.msi"
        $dellOmsaMsp    = Join-Path $dellOmsaPath "SysMgmt-Latest.msp"
        Start-BitsTransfer -Source $dellOmsaExeUrl -Destination $dellOmsaExe
        Start-Process -FilePath $dellOmsaExe -ArgumentList @("/auto","$dellOmsaPath") -Wait -NoNewWindow
        Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i","$dellOmsaMsi","/qb","/norestart") -Wait -NoNewWindow

        #
        # install latest patch if there is one
        #
        if ($dellOmsaMspUrl) {
            Start-BitsTransfer -Source $dellOmsaMspUrl -Destination $dellOmsaMsp
            Start-Process -FilePath "msiexec.exe" -ArgumentList @("/update","$dellOmsaMsp","/qb","/norestart") -Wait -NoNewWindow
        }

        #
        # secure the omsa web server
        #
        & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=ciphers setting=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=sslprotocol setting=TLSv1.2
        & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% system webserver action=restart

        #
        # create a windows firewall rule to allow access
        #
        $displayName = "OpenManage"
        if (!(Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $displayName -Direction Inbound -LocalPort 1311 -Protocol TCP -Action Allow
        }
    }
}

function Install-FiveNineManager {
    Invoke-WebRequest https://exdo.blob.core.windows.net/public/59Manager.msi -OutFile "$env:temp\59Manager.msi"
    Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i","$env:temp\59Manager.msi","/qb","/norestart") -Wait -NoNewWindow
}

function Get-InstallMedia {
    if (!(Test-Path 'C:\Users\Public\Documents\ISO')) {
        New-Item -Path 'C:\Users\Public\Documents\ISO' -ItemType Directory -Force | Out-Null
    }
    Start-BitsTransfer -Source 'https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO' -Destination 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO'
    #Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO'
    #Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2019_1809.1_64Bit_English_DC_STD_MLF_X22-02970.ISO'
    #Invoke-WebRequest https://exdo.blob.core.windows.net/public/iso/SW_DVD9_Win_Pro_10_1903_64BIT_English_Pro_Ent_EDU_N_MLF_X22-02890.ISO -OutFile 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Pro_10_1903_64BIT_English_Pro_Ent_EDU_N_MLF_X22-02890.ISO'
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
        $Password,
        $VlanId = 64
    )
    if (Test-Path "$env:programfiles\Dell\SysMgt\idrac\racadm.exe") {
        racadm set iDRAC.IPv4.Address $Address | Out-Null
        racadm set iDRAC.IPv4.Netmask $Netmask | Out-Null
        racadm set iDRAC.IPv4.Gateway $Gateway | Out-Null
        racadm set iDRAC.IPv4.DNS1 8.8.8.8 | Out-Null
        racadm set iDRAC.IPv4.DNS2 8.8.4.4 | Out-Null
        racadm set iDRAC.Nic.VLanID $VlanId | Out-Null
        racadm set iDRAC.Nic.VLanEnable 1 | Out-Null
        racadm set iDRAC.Users.2.Password $Password | Out-Null
    }
}

$Address = Read-Host "What is the desired iDRAC address (e.g. 10.60.64.2)?"
$Netmask = Read-Host "What is the desired iDRAC netmask (e.g. 255.255.255.0)?"
$Gateway = Read-Host "What is the desired iDRAC gateway (e.g. 10.60.64.1)?"
$Password = Read-Host "What is the Dell iDRAC password?"

Enable-SnmpService
pause
Disable-PrinterMapping
pause
Enable-RDP
pause
Disable-NetOffloadGlobalSettingTaskOffload
pause
Set-DvdRomDriveLetter
pause
Set-DataVolume
pause
Enable-NICTeaming
pause
Disable-VirtualMachineQueue
pause
Install-OMSA
pause
Enable-iDRAC -Address $Address -Netmask $Netmask -Gateway $Gateway -Password $Password
pause
Install-FiveNineManager
pause
Enable-TimeSynchronization
pause
Get-InstallMedia
pause
Enable-WindowsFirewall
pause

#
# this last function restarts the computer
#
Set-ComputerName
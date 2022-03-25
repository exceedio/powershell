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

Configuration HVServer2022 {

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
    }
}

function Set-DataVolume {
    Write-Output "Creating Data volume (if needed)..."
    if (!(Get-Volume -FileSystemLabel Data -ErrorAction SilentlyContinue)) {
        Get-Disk | Sort-Object 'Total Size' | Select-Object -Last 1 | New-Partition -UseMaximumSize -DriveLetter D | Format-Volume -FileSystem ReFS -NewFileSystemLabel 'Data' -Confirm:$false | Out-Null
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

    Write-Output "Creating network team for virtual machines (if needed)..."
    if ((Get-NetLbfoTeam).Name -notcontains $vmteamname) {
        Write-Output "Renaming network adapters..."
        foreach ($nic in $nics) {
            $name = "NIC$nicnumber"
            if ($nic.Name -ne $name) {
                Rename-NetAdapter -Name $nic.Name -NewName $name | Out-Null   
            }
            $nicnumber = $nicnumber + 1
        }
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
    Write-Output "Creating virtual switch..."
    if ((Get-VMSwitch).Name -notcontains $vmswitchname) {
        if ($vmswitchnic -ne '') {
            New-VMSwitch -Name $vmswitchname -NetAdapterName $vmswitchnic -AllowManagementOS 0 | Out-Null
        }
    }
}

function Disable-VirtualMachineQueue {
    Write-Output "Disabling VMQ to avoid problems with Broadcom..."
    if (Get-NetAdapterVmq | Where-Object Enabled -eq $true) {
        Get-NetAdapter | Set-NetAdapterVmq -Enabled $false -ErrorAction SilentlyContinue
    }
}

function Install-OMSA {
    Write-Output "Installing Dell OpenManage Server Administrator (if needed)..."
    if ((gwmi Win32_ComputerSystem).Manufacturer -match 'Dell*' -and (-not (Test-Path "$env:ProgramFiles\Dell\SysMgt\omsa"))) {
        #
        # install omsa
        #
        $dellOmsaExeUrl = "https://dl.dell.com/FOLDER06454068M/1/OM-SrvAdmin-Dell-Web-WINX64-9.5.0-4063_A00.exe"
        $dellOmsaMspUrl = "https://dl.dell.com/FOLDER07057950M/1/SysMgmt_9501_x64_patch_A00.msp"
        $dellOmsaPath   = Join-Path $env:temp "omsa"
        $dellOmsaExe    = Join-Path $dellOmsaPath "OM-SrvAdmin-Dell-Web-WINX64-Latest.exe"
        $dellOmsaMsi    = Join-Path "C:\OpenManage" "windows\SystemsManagementx64\SysMgmtx64.msi"
        $dellOmsaMsp    = Join-Path $dellOmsaPath "SysMgmt-Latest.msp"
        if (-not (Test-Path $dellOmsaPath)) {
            New-Item -Path $dellOmsaPath -ItemType Directory -Force | Out-Null
        }
        Start-BitsTransfer -Source $dellOmsaExeUrl -Destination $dellOmsaExe
        Start-Process -FilePath $dellOmsaExe -ArgumentList @("/auto") -Wait -NoNewWindow
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
        $omconfig = "$env:ProgramFiles\Dell\SysMgt\oma\bin\omconfig.exe"
        Start-Process -FilePath $omconfig -ArgumentList @("preferences","webserver","attribute=ciphers","setting=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256") -Wait -NoNewWindow
        Start-Process -FilePath $omconfig -ArgumentList @("preferences", "webserver","attribute=sslprotocol","setting=TLSv1.2") -Wait -NoNewWindow

        # configure bios settings
        Start-Process -FilePath $omconfig -ArgumentList @("chassis","biossetup","attribute=ErrPrompt","setting=Disabled") -Wait -NoNewWindow
        Start-Process -FilePath $omconfig -ArgumentList @("chassis","biossetup","attribute=AcPwrRcvry","setting=On") -Wait -NoNewWindow

        #
        # create a windows firewall rule to allow access
        #
        $displayName = "OpenManage"
        if (!(Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $displayName -Direction Inbound -LocalPort 1311 -Protocol TCP -Action Allow | Out-Null
        }
    }
}

function Install-FiveNineManager {
    Write-Output "Installing 5Nine Manager (if needed)..."
    if (-not (Test-Path "$env:ProgramFiles\5nine\5nine Manager")) {
        $usb = (Get-Volume | Where-Object DriveType -eq 'Removable').DriveLetter
        Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i","${usb}:\init\59Manager.msi","/qb","/norestart") -Wait -NoNewWindow    
    }
}

function Get-InstallMedia {
    Write-Output "Downloading Windows installation media (if needed)..."
    $filenames = @(
        'SW_DVD9_Win_Pro_10_20H2.5_64BIT_English_Pro_Ent_EDU_N_MLF_X22-55724.ISO',
        'SW_DVD9_Win_Server_STD_CORE_2019_1809.13_64Bit_English_DC_STD_MLF_X22-57176.ISO'
    )
    $path = 'C:\Users\Public\Documents\ISO'
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    foreach ($filename in $filenames)
    {
        if (-not (Test-Path (Join-Path $path $filename))) {
            Start-BitsTransfer -Source "https://exdosa.blob.core.windows.net/public/iso/$filename" -Destination (Join-Path $path $filename)
        }
    }
}

function Enable-iDRAC {
    param (
        $Address,
        $Netmask,
        $Gateway,
        [securestring] $Password,
        $VlanId = 64
    )
    Write-Output "Configuring iDRAC (if needed)..."
    if ((Test-Path "$env:programfiles\Dell\SysMgt\idrac\racadm.exe") -and $Address) {
        racadm set iDRAC.IPv4.Address $Address | Out-Null
        racadm set iDRAC.IPv4.Netmask $Netmask | Out-Null
        racadm set iDRAC.IPv4.Gateway $Gateway | Out-Null
        racadm set iDRAC.IPv4.DNS1 8.8.8.8 | Out-Null
        racadm set iDRAC.IPv4.DNS2 8.8.4.4 | Out-Null
        racadm set iDRAC.Nic.VLanID $VlanId | Out-Null
        racadm set iDRAC.Nic.VLanEnable 1 | Out-Null
        racadm set iDRAC.Users.2.Password ((New-Object PSCredential "root",$password).GetNetworkCredential().Password) | Out-Null
    }
}

function Test-StorageSpeed {
    Write-Output "Testing storage speed for 5 minutes..."
    $usb = (Get-Volume | Where-Object DriveType -eq 'Removable').DriveLetter
    Start-Process -FilePath "${usb}:\init\diskspd.exe" -ArgumentList @("-r","-w30","-d300","-W10","-b8k","-t24","-o12","-Sh","-L","-Z1M","-c64G", "D:\diskspd.dat") -RedirectStandardOutput "diskspd.txt" -Wait -NoNewWindow
    Remove-Item -Path "D:\diskspd.dat"
}

function Set-ComputerName {
    Write-Output "Setting computer name and restarting (if needed)..."
    $newname = (-Join('SV', (Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)).Trim()
    if ($env:computername -ne $newname) {
        #Rename-Computer -NewName $newname -Restart -Confirm:$true
        Rename-Computer -NewName $newname -Confirm:$false
    }
}

function Install-Updates {
    Write-Output "Installing updates for Windows..."
    $updates = Start-WUScan -SearchCriteria "Type='Software' AND IsInstalled=0"
    Install-WUUpdates -Updates $updates
}

if ((Read-Host 'Do you need to (re)configure iDRAC? [y/n]' ).ToLowerInvariant() -eq 'y') {
    if (!($Address = Read-Host "iDRAC address [10.60.64.2]")) { $Address = '10.60.64.2' }
    if (!($Netmask = Read-Host "iDRAC netmask [255.255.255.0]")) { $Netmask = '255.255.255.0' }
    if (!($Gateway = Read-Host "iDRAC gateway [10.60.64.1]")) { $Gateway = '10.60.64.1' }
    $Password = Read-Host "iDRAC root password" -AsSecureString
}

Set-ComputerName
Enable-SnmpService
Disable-PrinterMapping
Enable-RDP
Disable-NetOffloadGlobalSettingTaskOffload
Set-DvdRomDriveLetter
Set-DataVolume
Enable-NICTeaming
Disable-VirtualMachineQueue
Install-OMSA
Install-FiveNineManager
Enable-TimeSynchronization
Enable-iDRAC -Address $Address -Netmask $Netmask -Gateway $Gateway -Password $Password
Get-InstallMedia
Enable-WindowsFirewall
Test-StorageSpeed
Install-Kaseya
Install-Updates

#
# this last function restarts the computer
#

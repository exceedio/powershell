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
    Modified : Mar 31, 2022
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
        $StorageDiskUniqueId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ExternalVirtualSwitchNics,
        [Parameter(Mandatory = $false)]
        [String]
        $VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks',
        [Parameter(Mandatory = $false)]
        [String]
        $VirtualMachinePath = 'D:\Hyper-V',
        [Parameter(Mandatory = $false)]
        [String]
        $VirtualMachineISOPath = 'C:\Users\Public\Documents\ISO',
        [Parameter(Mandatory = $false)]
        [String]
        $DellOmsaManagedNodeUri,
        [Parameter(Mandatory = $false)]
        [String]
        $DellRemoteAccessControllerAddr
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
        
        WindowsOptionalFeature EnableSnmpFeature {
            Name   = 'SNMP'
            Ensure = 'Present'
        }
        
        Registry DisableRdpPrinterMapping {
            Key       = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Ensure    = 'Present'
            ValueName = 'fDisableCpm'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry HideFirstRunExperience {
            Key       = 'HKLM:\SOFTWARE\Policies\SOFTWARE\Policies\Microsoft\Edge'
            Ensure    = 'Present'
            ValueName = 'HideFirstRunExperience'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        Registry DisableEdgePasswordManager {
            Key       = 'HKLM:\SOFTWARE\Policies\SOFTWARE\Policies\Microsoft\Edge'
            Ensure    = 'Present'
            ValueName = 'PasswordManagerEnabled'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $true
        }

        Registry DisableOpenServerManagerAtLogon {
            Key       = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
            Ensure    = 'Present'
            ValueName = 'DoNotOpenServerManagerAtLogon'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $true
        }

        RemoteDesktopAdmin EnableRdp {
            IsSingleInstance   = 'Yes'
            Ensure             = 'Present'
            UserAuthentication = 'Secure'
        }

        Firewall EnableRemoteDesktop-In-TCP-WS {
            Name    = 'RemoteDesktop-In-TCP-WS'
            Ensure  = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-In-TCP-WSS {
            Name    = 'RemoteDesktop-In-TCP-WSS'
            Ensure  = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-Shadow-In-TCP {
            Name    = 'RemoteDesktop-Shadow-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-UserMode-In-TCP {
            Name    = 'RemoteDesktop-UserMode-In-TCP'
            Ensure  = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        Firewall EnableRemoteDesktop-UserMode-In-UDP {
            Name    = 'RemoteDesktop-UserMode-In-UDP'
            Ensure  = 'Present'
            Enabled = 'True'
            Profile = ('Domain', 'Private')
        }

        FirewallProfile EnablePrivateFirewallProfile {
            Name                  = 'Private'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules     = 'True'
            NotifyOnListen        = 'False'
            LogFileName           = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes   = 16384
            LogAllowed            = 'False'
            LogBlocked            = 'True'
            LogIgnored            = 'NotConfigured'
        }

        FirewallProfile EnableDomainFirewallProfile {
            Name                  = 'Domain'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules     = 'True'
            NotifyOnListen        = 'False'
            LogFileName           = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes   = 16384
            LogAllowed            = 'False'
            LogBlocked            = 'True'
            LogIgnored            = 'NotConfigured'
        }

        FirewallProfile EnablePublicFirewallProfile {
            Name                  = 'Public'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules     = 'True'
            NotifyOnListen        = 'False'
            LogFileName           = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            LogMaxSizeKilobytes   = 16384
            LogAllowed            = 'False'
            LogBlocked            = 'True'
            LogIgnored            = 'NotConfigured'
        }

        Service DisableDefragService {
            Name        = 'defragsvc'
            Ensure      = 'Present'
            StartupType = 'Manual'
            State       = 'Stopped'
        }

        Service EnableW32TimeService {
            Name        = 'W32Time'
            Ensure      = 'Present'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        Script EnableTimeSyncWithGoogle {
            SetScript  = {
                w32tm.exe /config /manualpeerlist:"time.google.com" /syncfromflags:manual /update | Out-Null
                w32tm.exe /resync
            }
            TestScript = {
                return ((w32tm.exe /query /configuration | Select-String 'NtpServer: time.google.com') -ne $null)
            }
            GetScript  = {
                return @{
                    Result = (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers').GetValue(1)
                }                
            }
            DependsOn  = '[Service]EnableW32TimeService'
        }

        WaitForDisk WaitForStorageDisk {
            DiskId           = $StorageDiskUniqueId
            DiskIdType       = 'UniqueId'
            RetryIntervalSec = 60
            RetryCount       = 60
        }

        Disk FormatStorageVolume {
            DiskId             = $StorageDiskUniqueId
            DiskIdType         = 'UniqueId'
            DriveLetter        = 'D'
            FSLabel            = 'Data'
            FSFormat           = 'ReFS'
            AllocationUnitSize = 64KB
            PartitionStyle     = 'GPT'
            #AllowDestructive = $true
            #ClearDisk = $true
            DependsOn          = '[WaitForDisk]WaitForStorageDisk'
        }

        File CreateVirtualHardDiskPath {
            DestinationPath = $VirtualHardDiskPath
            Ensure          = 'Present'
            Type            = 'Directory'
            DependsOn       = '[Disk]FormatStorageVolume'
        }

        File CreateVirtualMachinePath {
            DestinationPath = $VirtualMachinePath
            Ensure          = 'Present'
            Type            = 'Directory'
            DependsOn       = '[Disk]FormatStorageVolume'
        }

        File CreateVirtualMachineISOPath {
            DestinationPath = $VirtualMachineISOPath
            Ensure          = 'Present'
            Type            = 'Directory'
        }

        File DeleteDefaultVirtualMachinePath {
            DestinationPath = 'C:\Users\Public\Documents\Hyper-V'
            Ensure          = 'Absent'
            Type            = 'Directory'
            Force           = $true
            DependsOn       = '[xVMHost]HyperVStoragePaths'
        }

        WindowsFeature EnableHyperVFeature {
            Name      = 'Hyper-V'
            Ensure    = 'Present'
            DependsOn = '[File]CreateVirtualMachinePath'
        }

        WindowsFeature EnableHyperVToolsFeatures {
            Name                 = 'RSAT-Hyper-V-Tools'
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
            DependsOn            = '[File]CreateVirtualMachinePath'
        }

        xVMHost HyperVStoragePaths {
            IsSingleInstance    = 'Yes'
            VirtualHardDiskPath = $VirtualHardDiskPath
            VirtualMachinePath  = $VirtualMachinePath
            DependsOn           = '[WindowsFeature]EnableHyperVToolsFeatures'
        }

        xVMSwitch ExternalSwitch {
            Name                  = 'External Virtual Switch'
            Ensure                = 'Present'
            Type                  = 'External'
            NetAdapterName        = $ExternalVirtualSwitchNics
            EnableEmbeddedTeaming = $true
            AllowManagementOS     = $false
            DependsOn             = '[WindowsFeature]EnableHyperVToolsFeatures'
        }

        Script DownloadVMInstallMedia {
            SetScript  = {
                $folder = $using:VirtualMachineISOPath
                $filenames = @(
                    'SW_DVD9_Win_Server_STD_CORE_2022_2108.7_64Bit_English_DC_STD_MLF_X23-09508.ISO',
                    'SW_DVD9_Win_Server_STD_CORE_2019_1809.18_64Bit_English_DC_STD_MLF_X22-74330.ISO'
                )
                foreach ($filename in $filenames) {
                    if (-not (Test-Path (Join-Path $folder $filename))) {
                        Start-BitsTransfer `
                            -Source "https://exdoisofiles.blob.core.windows.net/files/$filename" `
                            -Destination $folder    
                    }
                }
            }
            TestScript = {
                return (@(Get-ChildItem $using:VirtualMachineISOPath).Count -eq 2)
            }
            GetScript  = {
                return @{
                    Result = Get-ChildItem $using:VirtualMachineISOPath
                }                
            }
        }

        Script BenchmarkStorageSpeed {
            SetScript  = {
                Start-BitsTransfer `
                    -Source 'https://github.com/microsoft/diskspd/releases/download/v2.1/DiskSpd.ZIP' `
                    -Destination 'C:\Users\Public\Documents\DiskSpd.ZIP'
                Expand-Archive `
                    -Path 'C:\Users\Public\Documents\DiskSpd.ZIP' `
                    -DestinationPath 'C:\Users\Public\Documents\DiskSpd' `
                    -Force
                $cores = (Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors)
                Start-Process `
                    -FilePath 'C:\Users\Public\Documents\DiskSpd\amd64\diskspd.exe' `
                    -ArgumentList @("-t$cores", '-o32', '-b4k', '-r', '-w30', '-d60', '-Sh', '-D', '-L', '-c5G', 'D:\diskspd.dat') `
                    -RedirectStandardOutput 'C:\Users\Public\Documents\DiskSpd.txt' `
                    -Wait `
                    -NoNewWindow
                Remove-Item -Path 'D:\diskspd.dat' -Force
                Remove-Item -Path 'C:\Users\Public\Documents\DiskSpd.ZIP' -Force
                Remove-Item -Path 'C:\Users\Public\Documents\DiskSpd' -Recurse -Force
            }
            TestScript = {
                return Test-Path 'C:\Users\Public\Documents\DiskSpd.txt'
            }
            GetScript  = {
                return @{
                    Result = Get-Content 'C:\Users\Public\Documents\storagespeed.txt'
                }
            }
            DependsOn  = '[Disk]FormatStorageVolume'
        }

        if ($DellOmsaManagedNodeUri) {

            Script InstallDellOmsa {
                SetScript  = {
                    $uri = $using:DellOmsaManagedNodeUri
                    $filename = $uri.Substring($uri.LastIndexOf("/") + 1)
                    $pathAndFilename = Join-Path $env:temp $filename
                    Start-BitsTransfer -Source $uri -Destination $pathAndFilename
                    Start-Process -FilePath "$pathAndFilename" -ArgumentList @("/auto") -Wait -NoNewWindow
                    Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", "C:\OpenManage\windows\SystemsManagementx64\SysMgmtx64.msi", "/qb", "/norestart") -Wait -NoNewWindow
                }
                TestScript = {
                    return (Test-Path -Path 'C:\Program Files\Dell\SysMgt\omsa')
                }
                GetScript  = {
                    return @{
                        Result = (Test-Path -Path 'C:\Program Files\Dell\SysMgt\omsa')
                    }                
                }
                DependsOn  = '[xVMSwitch]ExternalSwitch'
            }

            Script SecureOmsaWebServer {
                SetScript  = {
                    Start-Process -FilePath "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" -ArgumentList @("preferences", "webserver", "attribute=ciphers", "setting=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256") -Wait -NoNewWindow
                    Start-Process -FilePath "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" -ArgumentList @("preferences", "webserver", "attribute=sslprotocol", "setting=TLSv1.2,TLSv1.3") -Wait -NoNewWindow
                    Start-Process -FilePath "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" -ArgumentList @("system", "webserver", "action=restart") -Wait -NoNewWindow
                }
                TestScript = {
                    if (-not (Test-Path 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe')) { return $false }
                    if ((& 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe' preferences webserver attribute=getciphers)[1] -ne 'CIPHERS-Value : TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256') { return $false }
                    if ((& 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe' preferences webserver attribute=getsslprotocol)[1] -ne 'SSLProtocolValue : TLSv1.2,TLSv1.3') { return $false }
                    return $true
                }
                GetScript  = {
                    $result = & 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe' preferences webserver attribute=getciphers
                    $result += & 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe' preferences webserver attribute=getsslprotocol
                    return @{
                        Result = $result
                    }                
                }
                DependsOn  = '[Script]InstallDellOmsa'
            }

            Script SetDellRemoteAccessControllerName {
                SetScript  = {
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.Nic.DNSRacName ($using:ComputerName).Replace('SV', 'OB')
                }
                TestScript = {
                    return (& 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' get iDRAC.Nic.DNSRacName)[1] -match ($using:ComputerName).Replace('SV', 'OB')
                }
                GetScript  = {
                    return @{
                        Result = (& 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' get iDRAC.Nic.DNSRacName)
                    }                
                }
                DependsOn  = '[Script]InstallDellOmsa'
            }

            Script SetDellRemoteAccessControllerNic {
                SetScript  = {
                    $address = ($using:DellRemoteAccessControllerAddr)
                    $gateway = $address.Substring(0, $address.LastIndexOf(".")) + ".1"
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.DHCPEnable 0
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.DNSFromDHCP 0
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.Address $address
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.Netmask 255.255.255.0
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.Gateway $gateway
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.DNS1 8.8.8.8
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.IPv4.DNS2 8.8.4.4
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.Nic.VLanId 64
                    & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' set iDRAC.Nic.VLanEnable 1
                }
                TestScript = {
                    return (& 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' get iDRAC.IPv4.DHCPEnable)[1] -eq 'DHCPEnable=Disabled'
                }
                GetScript  = {
                    $result = & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' get iDRAC.IPv4
                    $result += & 'C:\Program Files\Dell\SysMgt\OM_iDRACTools\racadm\racadm.exe' get iDRAC.Nic
                    return @{
                        Result = $result
                    }                
                }
                DependsOn  = '[Script]InstallDellOmsa'
            }
        }
    }
}

function Show-Warning {
    $phrase = 'I am good with losing data'
    Clear-Host
    Write-Warning ''
    Write-Warning 'THIS SCRIPT CAN FORMAT YOUR DATA DRIVE!'
    Write-Warning ''
    return (Read-Host "Type '$phrase' to continue or anything else to quit") -eq $phrase
}

function Select-StorageDiskUniqueId {
    Get-Disk | Where-Object IsBoot -eq $false | Sort-Object Number | Format-Table Number, FriendlyName, UniqueId, @{label = 'SizeInGb'; expression = { $_.Size / 1Gb } } | Out-Host
    $number = Read-Host "Type the number of the disk that will be used to store virtual machines"
    return (Get-Disk -Number $number).UniqueId
}

function Select-ExternalVirtualSwitchNics {
    Get-NetAdapter | Sort-Object Name | Format-Table Name, MacAddress, Status | Out-Host
    $list = Read-Host "Comma-separated list of NIC name(s) that make up default virtual switch"
    return $list.Split(',')
}

function Select-ComputerName {
    $asset = Read-Host "Type the asset tag of this hypervisor"
    return "SV$asset"
}

function Select-DellRemoteAccessControllerAddr {
    return Read-Host  "Type the IP address of the Dell iDRAC (leave blank if no iDRAC)"
}

function Select-DellOmsaManagedNodeUri {
    Write-Host "Dell EMC OpenManage Server Administrator Managed Node for Windows can be located on Dell support site"
    Write-Host "Latest is https://dl.dell.com/FOLDER07619260M/1/OM-SrvAdmin-Dell-Web-WINX64-10.2.0.0-4631_A00.exe"
    Write-Host "Leave blank if not working with a Dell server"
    Read-Host  "Type or paste URL"
}

if (-not (Show-Warning)) {
    return 0
}

$computerName = Select-ComputerName
$storageDiskUniqueId = Select-StorageDiskUniqueId
$externalVirtualSwitchNics = Select-ExternalVirtualSwitchNics
$dellOmsaManagedNodeUri = Select-DellOmsaManagedNodeUri
$dellRemoteAccessControllerAddr = Select-DellRemoteAccessControllerAddr

#
# generate the configuration
#
Hypervisor `
    -ComputerName $computerName `
    -StorageDiskUniqueId $storageDiskUniqueId `
    -ExternalVirtualSwitchNics $externalVirtualSwitchNics `
    -DellOmsaManagedNodeUri $dellOmsaManagedNodeUri `
    -DellRemoteAccessControllerAddr $dellRemoteAccessControllerAddr `
    -OutputPath "$env:systemdrive\Dsc"

#
# implement the configuration
#
Start-DscConfiguration `
    -Path "$env:systemdrive\Dsc" `
    -Force `
    -Wait `
    -Verbose
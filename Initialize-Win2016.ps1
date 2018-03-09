<#
.SYNOPSIS
    Configures Windows Server 2016 to standard.
.DESCRIPTION
    Installs 7-Zip
    Sets static IPv4 address
    Renames computer according to standard
    Adds firewall rules for RDP
    Enables RDP
    Disables privacy IPv6 addresses
    Disables task offload
    Enables smartscreen
    Disables server manager for all users
    Disables RDP printer redirection
    Installs all current updates
    Activates Windows (optional)

    This script can be run repeatedly until there are no further updates
    to install. This script will cause the system on which it is running
    to restart automatically. 
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-Win2016.ps1 | iex
.NOTES
    Filename : Initialize-Win2016.ps1
    Author   : jreese@exceedio.com
    Modified : Mar, 08, 2018
#>

Function Install-7Zip
{
    if (!(Test-Path 'C:\Program Files\7-Zip'))
    {
        Write-Output "Installing 7-Zip..."
        $url = 'http://7-zip.org/a/7z1801-x64.msi'
        $msi = "$env:windir\temp\7z1801-x64.msi"
        Invoke-WebRequest $url -OutFile $msi
        & msiexec.exe /i $msi /qb /norestart | Out-Host
        Remove-Item $msi
    }
}

Function Set-StaticIP
{
    if ((Get-NetIPInterface -InterfaceAlias Ethernet -AddressFamily IPv4).Dhcp -eq 'Enabled')
    {
        $staticip = Read-Host "Static IP address?"
        $staticnm = Read-Host "Static subnet prefix length (e.g 24)?"
        $staticgw = Read-Host "Static default gateway?"
        $staticns = Read-Host "Static DNS server(s) (comma separated)?"
        Write-Output "Setting static IP..."
        New-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IPAddress $staticip -PrefixLength $staticnm -DefaultGateway $staticgw | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $staticns | Out-Null
    }
}

Function Set-ComputerName
{
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters')
    {
        $vmname = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("VirtualMachineName")
        if ($env:computername -ne $vmname)
        {
            Write-Output "Setting computer name to $vmname..."
            Rename-Computer -NewName $vmname -Force | Out-Null
        }
    }
}

Function Enable-RDP
{
    if (!(Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled)
    {
        Write-Output "Enabling Remote Desktop firewall rule..."
        Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True
    }
    
    if ((Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).AllowTSConnections -ne 1)
    {
        Write-Output "Enabling RDP..."
        (Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
    }

    if ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired -ne 0)
    {
        Write-Output "Disabling the requirement that RDP users must be authenticated at connection time..."
        (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null
    }
    
    if ((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services").fDisableCpm -ne 1)
    {
        Write-Output "Disabling RDP printer redirection..."
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCpm -PropertyType DWORD -Value 1 -Force | Out-Null
    }
}

Function Disable-TaskOffload
{
    if ((Get-NetOffloadGlobalSetting).TaskOffload -eq 'Enabled')
    {
        Write-Output "Disabling global task offload..."
        Set-NetOffloadGlobalSetting -TaskOffload Disabled
    }
}

Function Enable-SmartScreen
{
    if ((Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer).SmartScreenEnabled -ne 'RequireAdmin')
    {
        Write-Output "Enabling SmartScreen..."
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value 'RequireAdmin' -Force
    }
}

Function Install-Updates
{
    if (@(Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue).Count -eq 0)
    {
        Write-Output "Installing Windows Update PowerShell module..."
        Install-Module PSWindowsUpdate -Force

        #Write-Output "Enabling Microsoft Update..."
        #Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
    }

    Write-Output "Installing updates and automatically rebooting if needed..."
    Install-WindowsUpdate -Criteria "IsInstalled = 0 AND BrowseOnly = 0 AND Type = 'Software'" -MicrosoftUpdate -AutoReboot -AcceptAll
}

Function Activate-Windows
{
    $status = cscript.exe "$env:windir\system32\slmgr.vbs" /dli
    if ($status -notcontains 'License Status: Licensed')
    {
        Write-Output "Press [Enter] to skip activation for now..."
        $key = Read-Host "Windows 2016 Product Key (e.g. XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
        if ($key.Length -eq 29)
        {
            Write-Output "Activating Windows using key $key..."
            $service = Get-WmiObject SoftwareLicensingService 
            $service.InstallProductKey($key) | Out-Null
            $service.RefreshLicenseStatus() | Out-Null
        }
        else
        {
            Write-Output "Skipping activation..."
        }
    }
}

Function Disable-ServerManager
{
    if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager).DoNotOpenServerManagerAtLogon -ne 1)
    {
        Write-Output "Disabling server manager for current user..."
        New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force | Out-Null

        #
        # disable server manager from showing for all future users
        #
        REG LOAD HKU\DefaultUser $env:systemdrive\Users\Default\NTUSER.DAT | Out-Null
        REG ADD "HKU\DefaultUser\Software\Microsoft\ServerManager" /v DoNotOpenServerManagerAtLogon /d 1 /t REG_DWORD /f | Out-Null
        REG UNLOAD HKU\DefaultUser | Out-Null
    }
}

Function Disable-IPv6PrivacyAddresses
{
    if ((netsh interface ipv6 show privacy) -match 'enabled')
    {
        Write-Output "Disabling privacy IPv6 addresses..."
        netsh interface ipv6 set privacy state=disabled store=active | Out-Null
        netsh interface ipv6 set privacy state=disabled store=persistent | Out-Null
        netsh interface ipv6 set global randomizeidentifiers=disabled store=active | Out-Null
        netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent | Out-Null
    }
}

Function Download-DattoWindowsAgent
{
    if (!(Test-Path "$env:windir\Temp\DattoWindowsAgent.exe"))
    {
        Write-Output "Downloading Datto Windows Agent to $env:windir\Temp..."
        iwr 'https://www.datto.com/downloads/DattoWindowsAgent.exe' -OutFile "$env:windir\Temp\DattoWindowsAgent.exe"
    }
}

Function Download-KAgent
{
    if (!(Test-Path "$env:windir\Temp\KcsSetup.exe"))
    {
        Write-Output "Downloading K Agent to $env:windir\Temp..."
        iwr 'https://ksy.exceedio.com/install/VSA-default-93643676/KcsSetup.exe' -OutFile "$env:windir\Temp\KcsSetup.exe"
    }
}

Write-Output "Starting standard configuration of Windows Server 2012 R2..."

Disable-ServerManager
Install-7Zip
Set-StaticIP
Enable-RDP
Disable-TaskOffload
Disable-IPv6PrivacyAddresses
Enable-SmartScreen
Set-ComputerName
Install-Updates
Activate-Windows
Download-DattoWindowsAgent
Download-KAgent

Write-Output "Finished"

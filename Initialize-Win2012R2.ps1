<#
.SYNOPSIS
    Configures Windows Server 2012 R2 to standard.
.DESCRIPTION
    Installs .NET Framework 4.7 and WMF 5.1
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
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-Win2012R2.ps1 | iex
.NOTES
    Filename : Initialize-Win2012R2.ps1
    Author   : jreese@exceedio.com
    Modified : Sep, 21, 2017
#>

Function Install-NETFramework47
{
    if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -lt 460805)
    {
        Write-Output "Installing .NET Framework 4.7..."
        $url = 'https://download.microsoft.com/download/D/D/3/DD35CC25-6E9C-484B-A746-C5BE0C923290/NDP47-KB3186497-x86-x64-AllOS-ENU.exe'
        $exe = "$env:windir\temp\NDP47-KB3186497-x86-x64-AllOS-ENU.exe"
        Invoke-WebRequest $url -OutFile $exe
        & $exe /q /norestart | Out-Null
        Remove-Item $exe
    }
}

Function Install-WMF51
{
    if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1))
    {
        Write-Output "Installing WMF 5.1..."
        $url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'
        $msu = "$env:windir\temp\Win8.1AndW2K12R2-KB3191564-x64.msu"
        Invoke-WebRequest $url -OutFile $msu
        & wusa.exe $msu /quiet /forcerestart | Out-Host
        Remove-Item $msu
    }
}

Function Install-7Zip
{
    if (!(Test-Path 'C:\Program Files\7-Zip'))
    {
        Write-Output "Installing 7-Zip..."
        $url = 'http://www.7-zip.org/a/7z1604-x64.msi'
        $msi = "$env:windir\temp\7z1604-x64.exe"
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

        Write-Output "Enabling Microsoft Update..."
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
    }

    Write-Output "Installing updates and automatically rebooting if needed..."
    Get-WUInstall -Criteria "IsInstalled = 0 AND BrowseOnly = 0 AND Type = 'Software'" -AutoReboot -AcceptAll
}

Function Activate-Windows
{
    $status = cscript.exe "$env:windir\system32\slmgr.vbs" /dli
    if ($status -notcontains 'License Status: Licensed')
    {
        Write-Output "Press [Enter] to skip activation for now..."
        $key = Read-Host "Windows 2012 R2 Product Key (e.g. XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
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
Install-NETFramework47
Install-WMF51
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

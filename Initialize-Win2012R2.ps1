<#
.SYNOPSIS
    Configures Windows Server 2012 R2 to standard.
.DESCRIPTION
    Installs .NET Framework 4.6.1 and WMF 5.0
    Renames computer according to standard
    Adds firewall rules for RDP and then disables firewall
    Enables RDP
    Disables privacy IPv6 addresses
    Disables task offload
    Enables smartscreen
    Disables server manager for all users
    Disables RDP printer redirection
    Installs all current updates

    This script can be run repeatedly until there are no further updates
    to install. This script will cause the system on which it is running
    to restart automatically. 
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-Win2012R2.ps1 | iex
.NOTES
    Filename : Initialize-Win2012R2.ps1
    Author   : jreese@exceedio.com
    Modified : Nov, 4, 2016
#>

Function Install-NETFramework461
{
    $url = 'https://download.microsoft.com/download/E/4/1/E4173890-A24A-4936-9FC9-AF930FE3FA40/NDP461-KB3102436-x86-x64-AllOS-ENU.exe'
    $exe = "$env:windir\temp\NDP461-KB3102436-x86-x64-AllOS-ENU.exe"
    Invoke-WebRequest $url -OutFile $exe
    & $exe /q /norestart | Out-Host
    Remove-Item $exe
}

Function Install-NETFramework47
{
    $url = 'https://download.microsoft.com/download/D/D/3/DD35CC25-6E9C-484B-A746-C5BE0C923290/NDP47-KB3186497-x86-x64-AllOS-ENU.exe'
    $exe = "$env:windir\temp\NDP47-KB3186497-x86-x64-AllOS-ENU.exe"
    Invoke-WebRequest $url -OutFile $exe
    & $exe /q /norestart | Out-Host
    Remove-Item $exe
	
}

Function Install-WMF5
{
    $url = 'https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win8.1AndW2K12R2-KB3134758-x64.msu'
    $msu = "$env:windir\temp\Win8.1AndW2K12R2-KB3134758-x64.msu"
    Invoke-WebRequest $url -OutFile $msu
    & wusa.exe $msu /quiet /forcerestart | Out-Host
    Remove-Item $msu
}

Function Install-WMF51
{
    $url = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'
    $msu = "$env:windir\temp\Win8.1AndW2K12R2-KB3191564-x64.msu"
    Invoke-WebRequest $url -OutFile $msu
    & wusa.exe $msu /quiet /forcerestart | Out-Host
    Remove-Item $msu
	
}

Function Install-7Zip
{
    $url = 'http://www.7-zip.org/a/7z1604-x64.msi'
    $msi = "$env:windir\temp\7z1604-x64.exe"
    Invoke-WebRequest $url -OutFile $msi
    & msiexec.exe /i $msi /qb /norestart | Out-Host
    Remove-Item $msi
}

Function Update-Progress
{
    param (
        [string] $Status,
        [int] $Step
    )

    Write-Progress -Activity "Initializing Windows Server 2012 R2" -Status $Status -PercentComplete (($Step / 15) * 100)
}

#
# rename to standard
#
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters') {
    $vmname = (Get-Item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("VirtualMachineName")
    if ($env:computername -ne $vmname) {
        Rename-Computer -NewName $vmname -Force
    }
}

#
#
#
if ((Get-NetIPInterface -InterfaceAlias Ethernet -AddressFamily IPv4).Dhcp -eq 'Enabled') {
    $staticip = Read-Host "Static IP address?"
    $staticnm = Read-Host "Static subnet prefix length (e.g 24)?"
    $staticgw = Read-Host "Static default gateway?"
    $staticns = Read-Host "Static DNS server(s) (comma separated)?"
    New-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4 -IPAddress $staticip -PrefixLength $staticnm -DefaultGateway $staticgw
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $staticns
}

#
# disable server manager from showing for current user
#
Update-Progress -Status "Disabling server manager for current user" -Step 1
New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force | Out-Null

#
# disable server manager from showing for all future users
#
REG LOAD HKU\DefaultUser $env:systemdrive\Users\Default\NTUSER.DAT
REG ADD "HKU\DefaultUser\Software\Policies\Microsoft\Windows NT\Terminal Services" /v DoNotOpenServerManagerAtLogon /d 1 /t REG_DWORD /f
REG UNLOAD HKU\DefaultUser

#
# install .net 4.6.1 if needed
#
#if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -lt 394271) {
#    Update-Progress -Status "Installing .NET Framework 4.6.1" -Step 2
#    Install-NETFramework461
#}

#
# install .net 4.7 if needed
#
# see https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
#
if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -lt 460805) {
    Update-Progress -Status "Installing .NET Framework 4.7" -Step 2
    Install-NETFramework47
}

#
# install WMF 5 if needed
#
if ($PSVersionTable.PSVersion.Major -ne 5) {
    Update-Progress -Status "Installing Windows Management Framework 5.1" -Step 3
    Install-WMF51
} else if ($PSVersionTable.PSVersion.Minor -ne 1) {
    Update-Progress -Status "Installing Windows Management Framework 5.1" -Step 3
    Install-WMF51
}

#
# install 7-Zip if needed
#
if (!(Test-Path 'C:\Program Files\7-Zip')) {
    Update-Progress -Status "Installing 7-Zip" -Step 4
    Install-7Zip
}

#
# enable remote desktop in firewall rules in case firewall is turned back on
#
if (!(Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled) {
    Update-Progress -Status "Enabling Remote Desktop firewall rule" -Step 5
    Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True
}

#
# enable remote desktop
#
Update-Progress -Status "Enabling Remote Desktop" -Step 6
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null

#
# disable firewall
#
Update-Progress -Status "Disabling Windows Firewall" -Step 7
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

#
# disable privacy IPv6 addresses
#
Update-Progress -Status "Disabling privacy IPv6 addresses" -Step 8
netsh interface ipv6 set privacy state=disabled store=active | Out-Null
netsh interface ipv6 set privacy state=disabled store=persistent | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=active | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent | Out-Null

#
# disable task offloading
#
if ((Get-NetOffloadGlobalSetting).TaskOffload -eq 'Enabled') {
    Update-Progress -Status "Disabling global task offload" -Step 9
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
}

#
# enable smartscreen
#
if ((Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer).SmartScreenEnabled -ne 'RequireAdmin') {
    Update-Progress -Status "Enabling SmartScreen" -Step 10
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value 'RequireAdmin' -Force
}

#
# disable printer direction on the server side to keep event log clean
#
Update-Progress -Status "Disabling printer redirection for remote connections" -Step 11
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCpm -PropertyType DWORD -Value 1 -Force | Out-Null

#
# enable nuget
#
if (@(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue).Count -eq 0) {
    Update-Progress -Status "Enabling NuGet" -Step 12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#
# install modules
#
if (@(Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue).Count -eq 0) {
    Update-Progress -Status "Installing Windows Update PowerShell module" -Step 13
    Install-Module PSWindowsUpdate -Force
}

#
# enable Microsoft Update
#
if (@(Get-WUServiceManager | ? {$_.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d'}).Count -eq 0) {
    Update-Progress -Status "Enabling Microsoft Update" -Step 14
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
}

#
# install updates
#
Update-Progress -Status "Installing updates and automatically rebooting if needed" -Step 15
Get-WUInstall -Criteria "IsInstalled = 0 AND BrowseOnly = 0 AND Type = 'Software'" -AutoReboot -AcceptAll

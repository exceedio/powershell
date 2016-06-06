<#
.SYNOPSIS
    Configures Windows Server 2012 R2 to standard.
.DESCRIPTION
    Use this script to configure any physical or virtual machine that is running Windows Server 2012 R2.

    Call with iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-Win2012R2.ps1 | iex

.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    .\Initialize-Win2012R2.ps1 -Name VM1234 -Purpose 'Domain Controller'
#>

param(
    [Parameter(Mandatory=$true)]
    [string] $Name,

    [Parameter(Mandatory=$true)]
    [string] $Purpose
)

Function Install-NETFramework461
{
    Write-Host "Installing .NET Framework 4.6.1..."
    $url = 'https://download.microsoft.com/download/E/4/1/E4173890-A24A-4936-9FC9-AF930FE3FA40/NDP461-KB3102436-x86-x64-AllOS-ENU.exe'
    $exe = "$env:windir\temp\NDP461-KB3102436-x86-x64-AllOS-ENU.exe"
    Invoke-WebRequest $url -OutFile $exe
    & $exe /q /norestart | Out-Host
    Remove-Item $exe
}

Function Install-WMF5
{
    Write-Host "Installing Windows Management Framework 5.0..."
    $url = 'https://download.microsoft.com/download/2/C/6/2C6E1B4A-EBE5-48A6-B225-2D2058A9CEFB/Win8.1AndW2K12R2-KB3134758-x64.msu'
    $msu = "$env:windir\temp\Win8.1AndW2K12R2-KB3134758-x64.msu"
    Invoke-WebRequest $url -OutFile $msu
    & wusa.exe $msu /quiet /forcerestart | Out-Host
    Remove-Item $msu
}

if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -lt 394271) {
    Install-NETFramework461
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Install-WMF5
}

#
# enable remote desktop in firewall rules in case firewall is turned back on
#
if (!(Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled) {
    Write-Host "Enabling Remote Desktop firewall rule..."
    Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True
}

#
# enable remote desktop
#
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null

#
# disable firewall
#
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

#
# disable privacy IPv6 addresses
#
Write-Host "Disabling privacy IPv6 addresses..."
netsh interface ipv6 set privacy state=disabled store=active | Out-Null
netsh interface ipv6 set privacy state=disabled store=persistent | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=active | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent | Out-Null

#
# disable task offloading
#
if ((Get-NetOffloadGlobalSetting).TaskOffload -eq 'Enabled') {
    Write-Host "Disabling global task offload..."
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
}

#
# enable smartscreen
#
if ((Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer).SmartScreenEnabled -ne 'RequireAdmin') {
    Write-Host "Enabling SmartScreen..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value 'RequireAdmin' -Force
}

#
# disable server manager from showing for current user
#
New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force | Out-Null

#
# disable printer direction on the server side to keep event log clean
#
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCpm -PropertyType DWORD -Value 1 -Force | Out-Null

#
# enable nuget
#
if (@(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue).Count -eq 0) {
    Write-Host "Enabling Nuget..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#
# install modules
#
if (@(Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue).Count -eq 0) {
    Write-Host "Installing Windows Update PowerShell module..."
    Install-Module PSWindowsUpdate -Force
}

#
# enable Microsoft Update
#
if (@(Get-WUServiceManager | ? {$_.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d'}).Count -eq 0) {
    Write-Host "Enabling Microsoft Update..."
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
}

#
# install updates
#
Write-Host "Installing updates and automatically rebooting if needed..."
Get-WUInstall -Criteria "IsInstalled = 0 AND BrowseOnly = 0 AND Type = 'Software'" -AutoReboot -AcceptAll

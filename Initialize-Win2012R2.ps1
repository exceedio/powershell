<#
.SYNOPSIS
    Configures Windows Server 2012 R2 to standard.
.DESCRIPTION
    Use this script to configure any physical or virtual machine that is running Windows Server 2012 R2.
    
    Call from elevated PowerShell prompt using:

    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Initialize-Win2012R2.ps1 | iex

.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    .\Initialize-Win2012R2.ps1 -Name VM1234 -Purpose 'Domain Controller'
#>

Function Install-NETFramework461
{
    $url = 'https://download.microsoft.com/download/E/4/1/E4173890-A24A-4936-9FC9-AF930FE3FA40/NDP461-KB3102436-x86-x64-AllOS-ENU.exe'
    $exe = "$env:windir\temp\NDP461-KB3102436-x86-x64-AllOS-ENU.exe"
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

Function Update-Progress
{
    param (
        [string] $Status,
        [int] $Step
    )

    Write-Progress -Activity "Initializing Windows Server 2012 R2" -Status $Status -PercentComplete (($Step / 14) * 100)
}

if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -lt 394271) {
    Update-Progress -Status "Installing .NET Framework 4.6.1" -Step 1
    Install-NETFramework461
}



if ($PSVersionTable.PSVersion.Major -lt 5) {
    Update-Progress -Status "Installing Windows Management Framework 5.0" -Step 2
    Install-WMF5
}

#
# enable remote desktop in firewall rules in case firewall is turned back on
#
if (!(Get-NetFirewallRule -DisplayGroup "Remote Desktop").Enabled) {
    Update-Progress -Status "Enabling Remote Desktop firewall rule" -Step 3
    Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True
}

#
# enable remote desktop
#
Update-Progress -Status "Enabling Remote Desktop" -Step 4
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null

#
# disable firewall
#
Update-Progress -Status "Disabling Windows Firewall" -Step 5
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

#
# disable privacy IPv6 addresses
#
Update-Progress -Status "Disabling privacy IPv6 addresses" -Step 6
netsh interface ipv6 set privacy state=disabled store=active | Out-Null
netsh interface ipv6 set privacy state=disabled store=persistent | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=active | Out-Null
netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent | Out-Null

#
# disable task offloading
#
if ((Get-NetOffloadGlobalSetting).TaskOffload -eq 'Enabled') {
    Update-Progress -Status "Disabling global task offload" -Step 7
    Set-NetOffloadGlobalSetting -TaskOffload Disabled
}

#
# enable smartscreen
#
if ((Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer).SmartScreenEnabled -ne 'RequireAdmin') {
    Update-Progress -Status "Enabling SmartScreen" -Step 8
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value 'RequireAdmin' -Force
}

#
# disable server manager from showing for current user
#
Update-Progress -Status "Disabling server manager for current user" -Step 9
New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value 1 -Force | Out-Null

#
# disable printer direction on the server side to keep event log clean
#
Update-Progress -Status "Disabling printer redirection for remote connections" -Step 10
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCpm -PropertyType DWORD -Value 1 -Force | Out-Null

#
# enable nuget
#
if (@(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue).Count -eq 0) {
    Update-Progress -Status "Enabling NuGet" -Step 11
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#
# install modules
#
if (@(Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue).Count -eq 0) {
    Update-Progress -Status "Installing Windows Update PowerShell module" -Step 12
    Install-Module PSWindowsUpdate -Force
}

#
# enable Microsoft Update
#
if (@(Get-WUServiceManager | ? {$_.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d'}).Count -eq 0) {
    Update-Progress -Status "Enabling Microsoft Update" -Step 13
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
}

#
# install updates
#
Update-Progress -Status "Installing updates and automatically rebooting if needed" -Step 14
Get-WUInstall -Criteria "IsInstalled = 0 AND BrowseOnly = 0 AND Type = 'Software'" -AutoReboot -AcceptAll

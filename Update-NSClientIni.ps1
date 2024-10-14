#Requires -Version 5.1
#Requires -RunAsAdministrator 

<#
.SYNOPSIS
    Updates nsclient.ini on the local system based on the current system
    attributes and configuration
.DESCRIPTION
    This script will dynamically determine which monitors need to be active
    on a system and configure the nsclient.ini on the local system thusly.
.EXAMPLE
    PS C:\> Update-ExceedioNSClientIni.ps1
.EXAMPLE
    PS C:\> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Update-NSClientIni.ps1 | iex
.PARAMETER NSClientIni
    The path to write to and/or the path of the existing nsclient.ini file.
    Defaults to C:\Program Files\NSClient\nsclient.ini if omitted.
.PARAMETER Hostname
    The hostname of the local system to be used in the nsclient.ini file.
    Does not necessarily need to correspond to the actual hostname of the
    system. If omitted it will default to the hostname in the existing
    nsclient.ini at the location specified by the NSClientIni parameter.
.PARAMETER EncryptionKey
    The password to use when AES encrypting data to be sent to the server
    specified by the Address parameter. If omitted it will default to the
    password in the existing nsclient.ini at the location specified by the
    NSClientIni parameter.
.PARAMETER Address
    The network address (name or IP) of the Icinga server. If omitted it
    will default to the address in the existing nsclient.ini at the location
    specified by the NSClientIni parameter.
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory=$false)]
    [string]
    $NSClientIni = "C:\Program Files\NSClient++\nsclient.ini",

    [Parameter(Mandatory=$false)]
    [string]
    $CustomServiceIgnorePath = "C:\Program Files\NSClient++\ignore_services.txt",

    [Parameter(Mandatory=$false)]
    [string]
    $CustomIcmpCheckPath = "C:\Program Files\NSClient++\check_icmp.txt",

    [Parameter(Mandatory=$false)]
    [string]
    $Hostname,

    [Parameter(Mandatory=$false)]
    [string]
    $EncryptionKey,

    [Parameter(Mandatory=$false)]
    [string]
    $Address
)

function Find-Value
{
    param (
        [string[]] $Content,
        [string] $Pattern
    )

    (($Content | Select-String -Pattern $Pattern) -replace $Pattern, '').Trim()
}

function Get-ServiceFilter
{
    $servicesToIgnoreLike = @(
        'GoogleUpdaterService',
        'GoogleUpdaterInternalService',
        'cbdhsvc_',
        'CDPUserSvc_',
        'clr_optimization_v',
        'OneSyncSvc_',
        'WpnUserService_'
    )

    $servicesToIgnoreExact = @(
        'BITS',
        'CDPSvc',
        'dbupdate',
        'DoSvc',
        'edgeupdate',
        'GISvc',
        'gpsvc',
        'gupdate',
        'IaasVmProvider',
        'iDRAC Service Module',
        'IntelAudioService',
        'Intel(R) TPM Provisioning Service',
        'MapsBroker',
        'MMCSS',
        'Net Driver HPZ12',
        'Pml Driver HPZ12',
        'RemoteRegistry',
        'ShellHWDetection',
        'sppsvc',
        'StateRepository',
        'SysmonLog',
        'TabletInputService',
        'tiledatamodelsvc',
        'TrustedInstaller',
        'VSS',
        'WbioSrvc',
        'wuauserv',
        'ZeroConfigService'
    )

    if (Test-Path $CustomServiceIgnorePath)
    {
        Write-Host "[+] Adding custom service ignores from $CustomServiceIgnorePath"
        $custom = Get-Content -Path $CustomServiceIgnorePath
        $servicesToIgnoreExact += $custom
    }

    $serviceFilter = @(
        "start_type='auto'"
    )

    $servicesToIgnoreLike | ForEach-Object {
        $serviceFilter += "and name not like '$_'"
    }

    $serviceFilter += "and name not in ($(($servicesToIgnoreExact | ForEach-Object {"'$_'"}) -join ','))"

    $serviceFilter
}

if (-not (Test-Path $NSClientIni))
{
    Write-Warning "$NSClientIni does not exist!"
    return
}

if (@($Hostname, $EncryptionKey, $Address) | ForEach-Object {$_ -eq $null -or [string]::IsNullOrWhiteSpace($_)})
{
    $currentIni = Get-Content $NSClientIni

    if (-not $Hostname)
    {
        $Hostname = Find-Value -Content $currentIni -Pattern 'hostname='
    }
    if (-not $EncryptionKey)
    {
        $EncryptionKey = Find-Value -Content $currentIni -Pattern 'password='
    }
    if (-not $Address)
    {
        $Address = Find-Value -Content $currentIni -Pattern 'address='
    }
}

Write-Host "[+] Generating common configuration and checks"
#
# here's where we start building the content of the new nsclient.ini
# file including comments at the top about the fact that the file was
# generated and it includes some information about when it was updated
#
$updatedIni = @()
$updatedIni += "; "
$updatedIni += "; NSClient++ passive host configuration file"
$updatedIni += "; "
$updatedIni += "; This file was automatically generated by a PowerShell script"
$updatedIni += "; named Update-NSClientIni.ps1 that is located in the Github"
$updatedIni += "; repository at https://github.com/exceedio/powershell."
$updatedIni += "; "
$updatedIni += "; Do not manually edit this file. Re-run the PowerShell script"
$updatedIni += "; to regenerate the file when needed."
$updatedIni += "; "
$updatedIni += "; Updated: $(Get-Date)"
$updatedIni += "; "
$updatedIni += ""
$updatedIni += "[/modules]"
$updatedIni += ""
$updatedIni += "CheckSystem=enabled"
$updatedIni += "CheckDisk=enabled"
$updatedIni += "CheckTaskSched=enabled"
$updatedIni += "CheckHelpers=enabled"
$updatedIni += "CheckEventLog=enabled"
$updatedIni += "CheckExternalScripts=enabled"
$updatedIni += "Scheduler=enabled"
$updatedIni += "NSCAClient=enabled"
$updatedIni += ""
$updatedIni += "[/settings/NSCA/client]"
$updatedIni += ""
$updatedIni += "delay=0"
$updatedIni += "hostname=$Hostname"
$updatedIni += "channel=NSCA"
$updatedIni += ""
$updatedIni += "[/settings/external scripts]"
$updatedIni += ""
$updatedIni += "allow arguments = true"
$updatedIni += "allow nasty characters = true"
$updatedIni += "timeout = 90"
$updatedIni += ""
$updatedIni += "[/settings/external scripts/wrappings]"
$updatedIni += ""
$updatedIni += "bat = scripts\\%SCRIPT% %ARGS%"
$updatedIni += 'ps1 = cmd /c echo scripts\\%SCRIPT% %ARGS%; exit($lastexitcode) | @powershell -noprofile -executionpolicy unrestricted -command -'
$updatedIni += "vbs = cscript.exe //t:90 //nologo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%"
$updatedIni += "exe = cmd /c %SCRIPT% %ARGS%"
$updatedIni += ""
$updatedIni += "[/settings/external scripts/scripts]"
$updatedIni += ""
$updatedIni += "check_omsa=scripts/check_openmanage.exe --timeout 120"
$updatedIni += ""
$updatedIni += "[/settings/external scripts/wrapped scripts]"
$updatedIni += ""
$updatedIni += "check_printers=check_printers.vbs"
$updatedIni += "check_time=check_windows_time.bat time.google.com 120 300"
$updatedIni += "check_wsb=check_wsb.ps1"
$updatedIni += 'check_icmp=check_icmp.ps1 -Targets $ARG1$'
$updatedIni += ""
$updatedIni += "[/settings/NSCA/client/targets/default]"
$updatedIni += ""
$updatedIni += "encryption=aes"
$updatedIni += "password=$EncryptionKey"
$updatedIni += "address=$Address"
$updatedIni += "port=5667"
$updatedIni += "timeout=180"
$updatedIni += ""
$updatedIni += "[/settings/log]"
$updatedIni += ""
$updatedIni += ";debug=1"
$updatedIni += ""
$updatedIni += "[/settings/log/file]"
$updatedIni += ""
$updatedIni += "file=C:\Program Files\NSClient++\nsclient.log"
$updatedIni += "max size=10485760"
$updatedIni += ""
$updatedIni += "[/settings/scheduler/schedules/default]"
$updatedIni += ""
$updatedIni += "channel=NSCA"
$updatedIni += "interval=15m"
$updatedIni += "report=all"
$updatedIni += ""
$updatedIni += "[/settings/scheduler/schedules]"
$updatedIni += ""
$updatedIni += ";"
$updatedIni += "; average cpu time over 15 minutes should not be greater than"
$updatedIni += "; 95% or we may have a problem"
$updatedIni += ";"
$updatedIni += "cpu = check_cpu ""warn=load>85"" ""crit=load>95"" time=15m"
$updatedIni += ""
$updatedIni += ";"
$updatedIni += "; all volumes should have more than 2% free space"
$updatedIni += ";"
$updatedIni += "disk = check_drivesize ""warn=free<10%"" ""crit=free<2%"" drive=* ""filter=type in ('fixed')"""
$updatedIni += ""
$updatedIni += ";"
$updatedIni += "; warn if memory usage gets above 95% but do not every show this"
$updatedIni += "; as critical - due to how memory utilization is calculated it"
$updatedIni += "; is possible to be above 100% utilization and still be within"
$updatedIni += "; 'normal' conditions"
$updatedIni += ";"
$updatedIni += "mem = check_memory ""warn=used>95%"" ""crit=none"""
$updatedIni += ""
$updatedIni += ";"
$updatedIni += "; all automatic start services should be running but Windows has"
$updatedIni += "; many services that are stopped under normal conditions and"
$updatedIni += "; should be ignored for the purposes of monitoring"
$updatedIni += ";"
$updatedIni += "service = check_service ""filter=$(Get-ServiceFilter)"""
$updatedIni += ""
$updatedIni += ";"
$updatedIni += "; servers should not generally be restarting during the day so we"
$updatedIni += "; want restarts to pop on the board for 30 minutes but then go"
$updatedIni += "; away - will stay in warning state for 2 hours"
$updatedIni += ";"
$updatedIni += "uptime = check_uptime ""warn=uptime<2h"" ""crit=uptime<30m"""
$updatedIni += ""
$updatedIni += "[/settings/scheduler/schedules/checkin]"
$updatedIni += ""
$updatedIni += "interval=1m"
$updatedIni += "alias=checkin"
$updatedIni += "command=check_ok"

if ((Get-Module -ListAvailable -Name 'PrintManagement') -and (Get-Printer | Where-Object Shared -eq $true))
{
    Write-Host "[+] Adding printer checks"
    #
    # local system is sharing at least one printer so we're going
    # to assume that we're a print server and check printer status
    # every one hour
    #
    $updatedIni += ""
    $updatedIni += "[/settings/scheduler/schedules/printers]"
    $updatedIni += ""
    $updatedIni += "interval=1h"
    $updatedIni += "alias=printers"
    $updatedIni += "command=check_printers"
}

if (Test-Path -Path 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe')
{
    Write-Host "[+] Adding Dell OMSA checks"
    #
    # local system has Dell management components installed so we're
    # going to check status of Dell hardware components every three
    # hours
    #
    $updatedIni += ""
    $updatedIni += "[/settings/scheduler/schedules/omsa]"
    $updatedIni += ""
    $updatedIni += "interval=3h"
    $updatedIni += "alias=omsa"
    $updatedIni += "command=check_omsa"
}

if (@(4,5) -contains (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole)
{
    Write-Host "[+] Adding domain controller checks"
    #
    # local system is a domain controller so we're going to check that
    # the clock is in sync with a known good source of time every 24
    # hours. If you get too aggressive with checking this information
    # you will be blocked by the time source due to throttling
    #
    $updatedIni += ""
    $updatedIni += "[/settings/scheduler/schedules/time]"
    $updatedIni += ""
    $updatedIni += "interval=24h"
    $updatedIni += "alias=time"
    $updatedIni += "command=check_time"
}

if (Test-Path $CustomIcmpCheckPath)
{
    Write-Host "[+] Adding custom ICMP checks from $CustomIcmpCheckPath"
    $targets = @(Get-Content -Path $CustomIcmpCheckPath)
    $updatedIni += ""
    $updatedIni += "[/settings/scheduler/schedules/icmp]"
    $updatedIni += ""
    $updatedIni += "interval=2m"
    $updatedIni += "alias=icmp"
    $updatedIni += "command=check_icmp ""$($targets -join ',')"""
}

#
# create a backup of the existing nsclient.ini file
#
Write-Host "[+] Creating backup of $NSClientIni"
Copy-Item `
    -Path $NSClientIni `
    -Destination "$NSClientIni.backup-$(Get-Date -Format "yyyyMMdd")" `
    -Force

#
# save the new nsclient.ini file using utf8 encoding
#
Write-Host "[+] Saving new configuration at $NSClientIni"
$updatedIni -join "`n" | Out-File `
    -FilePath $NSClientIni `
    -Encoding utf8 `
    -Force

#
# if the nscp service exists and it is running then restart it
# to pick up the changes in the new nsclient.ini file. it would
# be nice to check to see if anything has changed in the file
#
if ($service = Get-Service nscp)
{
    if ($service.Status -eq 'Running')
    {
        Write-Host "[*] Restarting nscp service"
        $service | Restart-Service
    }
}

Write-Host "[*] Finished"

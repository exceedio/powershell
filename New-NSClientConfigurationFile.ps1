#Requires -Version 5.1

<#
.SYNOPSIS

    Generates a standard configuration file for NSClient++

.DESCRIPTION

    This script should be run on a system that already has NSClient++ installed with an existing,
    working nsclient.ini. The hostname, address, and password values will be gathered from the existing
    nsclient.ini and then a new configuration file will be written in its place using the standardized
    values in this script. The original nsclient.ini will be saved as nsclient.ini.orig.

    Text banner created at https://manytools.org/hacker-tools/ascii-banner/ using DOS Rebel font.

.PARAMETER Filename

    Full path to the existing nsclient.ini configuration file. Defaults to the standard location
    of a typical NSClient++ installation (C:\Program Files\NSClient++\nsclient.ini).

.EXAMPLE

    iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/New-NSClientConfigurationFile.ps1'))

.EXAMPLE

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/New-NSClientConfigurationFile.ps1'))

.NOTES

    Filename : New-NSClientConfigurationFile.ps1
    Author   : jreese@exceedio.com
    Modified : Aug, 8, 2023

#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Filename = 'C:\Program Files\NSClient++\nsclient.ini',
    [Parameter()]
    [switch]
    $NoBanner
)

#
# list of exact service names to ignore or are considered OK to be stopped
# despite being configured for auto start; please keep list in alphabetical
# order when updating
#

$serviceNamesToIgnoreExact = @(
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
    'wuauserv'
)

#
# list of partial service names to ignore or are considered OK to be stopped
# despite being configured for auto start; these are services that have random
# strings appended to the end making it impossible to get an exact match from
# the list above; please keep list in alphabetical order when updating
#

$serviceNamesToIgnoreLike = @(
    'cbdhsvc_',
    'CDPUserSvc_',
    'clr_optimization_v',
    'OneSyncSvc_',
    'WpnUserService_'
)

function Get-ServiceCheckCommand {
    $command = 'service=check_service "filter=start_type = ''auto'' '
    $serviceNamesToIgnoreLike | ForEach-Object { $command += "and name not like '$_' " }
    $command += 'and name not in ('
    $command += ($serviceNamesToIgnoreExact | ForEach-Object { "'$_'"}) -join ','
    $command += ')"'
    $command
}

function Write-Banner {
    Write-Output ''
    Write-Output '                              ███                       █████        ███              ███ '
    Write-Output '                             ░░░                       ░░███        ░░░              ░░░  '
    Write-Output ' ████████    █████   ██████  ████   ██████  ████████   ███████      ████  ████████   ████ '
    Write-Output '░░███░░███  ███░░   ███░░███░░███  ███░░███░░███░░███ ░░░███░      ░░███ ░░███░░███ ░░███ '
    Write-Output ' ░███ ░███ ░░█████ ░███ ░░░  ░███ ░███████  ░███ ░███   ░███        ░███  ░███ ░███  ░███ '
    Write-Output ' ░███ ░███  ░░░░███░███  ███ ░███ ░███░░░   ░███ ░███   ░███ ███    ░███  ░███ ░███  ░███ '
    Write-Output ' ████ █████ ██████ ░░██████  █████░░██████  ████ █████  ░░█████  ██ █████ ████ █████ █████'
    Write-Output '░░░░ ░░░░░ ░░░░░░   ░░░░░░  ░░░░░  ░░░░░░  ░░░░ ░░░░░    ░░░░░  ░░ ░░░░░ ░░░░ ░░░░░ ░░░░░ '
    Write-Output ''
}

if (-not $NoBanner) {
    Write-Banner
}

if (-not (Test-Path $Filename)) {
    Write-Output "[!] $Filename does not exist; exiting"
    return 1
}

$existingConfig = Get-Content $Filename

if ($existingConfig) {
    Write-Output "[*] Found existing configuration file at $Filename"
}

#
# attempt to pull a hostname out of the existing configuration file;
# this regex takes into account that our hostname= line may or may not
# have spaces surrounding the equal sign
#
$hostname = ($existingConfig | Select-String 'hostname\s?=\s?(\S+)').Matches.Groups[1].Value

if ($hostname) {
    Write-Output "[*] Found hostname $hostname in existing configuration file"
} else {
    Write-Output "[!] Hostname not found in existing configuration file; quitting"
    return 1
}

#
# attempt to pull a server address out of the existing configuration file;
# this regex takes into account that our address= line may or may not
# have spaces surrounding the equal sign
#
$address  = ($existingConfig | Select-String 'address\s?=\s?(\S+)').Matches.Groups[1].Value

if ($address) {
    Write-Output "[*] Found server address $address in existing configuration file"
} else {
    Write-Output "[!] Server address not found in existing configuration file; quitting"
    return 1
}

#
# attempt to pull the encryption password out of the existing configuration file;
# this regex takes into account that our password= line may or may not
# have spaces surrounding the equal sign
#
$password = ($existingConfig | Select-String 'password\s?=\s?(\S+)').Matches.Groups[1].Value

if ($password) {
    Write-Output "[*] Found password [hidden] in existing configuration file"
} else {
    Write-Output "[!] Password not found in existing configuration file; quitting"
    return 1
}

Write-Output "[*] Saving existng configuration file as $Filename.orig"
Copy-Item -Path $Filename -Destination "$Filename.orig"

Write-Output "[*] Generating new configuration file"

$content = @()

$content += ";"
$content += "; NSClient++ passive host configuration file"
$content += ";"
$content += "; This configuration file was automatically generated using New-NSClientConfigurationFile"
$content += "; at https://github.com/exceedio/powershell. Re-run the script if you need to update or"
$content += "; change this file."
$content += ";"
$content += "; Created $(Get-Date)"
$content += ";"
$content += ""
$content += "[/modules]"
$content += ""
$content += "CheckSystem=enabled"
$content += "CheckDisk=enabled"
$content += "CheckEventLog=enabled"
$content += "CheckExternalScripts=enabled"
$content += "CheckHelpers=enabled"
$content += "Scheduler=enabled"
$content += "NSCAClient=enabled"
$content += ""
$content += "[/settings/NSCA/client]"
$content += ""
$content += "delay=0"
$content += "hostname=$hostname"
$content += "channel=NSCA"
$content += ""
$content += "[/settings/external scripts]"
$content += ""
$content += "allow arguments = true"
$content += "allow nasty characters = true"
$content += "timeout = 90"
$content += ""
$content += "[/settings/external scripts/wrappings]"
$content += ""
$content += "bat = scripts\\%SCRIPT% %ARGS%"
$content += 'ps1 = cmd /c echo scripts\\%SCRIPT% %ARGS%; exit($lastexitcode) | @powershell -noprofile -executionpolicy unrestricted -command -'
$content += 'vbs = cscript.exe //t:90 //nologo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%'
$content += 'exe = cmd /c %SCRIPT% %ARGS%'
$content += ""
$content += "[/settings/external scripts/scripts]"
$content += ""
$content += "check_omsa=scripts/check_openmanage.exe --timeout 60"
$content += ""
$content += "[/settings/external scripts/wrapped scripts]"
$content += ""
$content += "check_printers=check_printers.vbs"
$content += "check_time=check_windows_time.bat time.google.com 120 300"
$content += "check_wsb=check_wsb.ps1"
$content += ""
$content += "[/settings/NSCA/client/targets/default]"
$content += ""
$content += "encryption=aes"
$content += "password=$password"
$content += "address=$address"
$content += "port=5667"
$content += "timeout=180"
$content += ""
$content += "[/settings/log/file]"
$content += ""
$content += "file=C:\Program Files\NSClient++\nsclient.log"
$content += ""
$content += "[/settings/scheduler/schedules/default]"
$content += ""
$content += "channel=NSCA"
$content += "interval=15m"
$content += "report=all"
$content += ""
$content += "[/settings/scheduler/schedules]"
$content += ""
$content += 'cpu=check_cpu "warn=load>80" "crit=load>90" time=30m'
$content += 'disk=check_drivesize "crit=free<5%" "warn=free<10%" drive=* "filter=type in (''fixed'')"'
$content += 'mem=check_memory "warn=used>95%" "crit=used>99%"'
$content += Get-ServiceCheckCommand
$content += 'uptime=check_uptime "crit=uptime < 15m" "warn=uptime < 8h"'
$content += ''
$content += '[/settings/scheduler/schedules/checkin]'
$content += ''
$content += 'interval=1m'
$content += 'alias=checkin'
$content += 'command=check_ok'
$content += ''
$content += '[/settings/scheduler/schedules/network]'
$content += ''
$content += 'interval=5m'
$content += 'alias=network'
$content += 'command=check_network warn=0.3G crit=0.6G'
$content += ''

if ((Get-WmiObject -Class Win32_ComputerSystem).Manufacturer -match 'Dell') {
    $content += '[/settings/scheduler/schedules/omsa]'
    $content += ''
    $content += 'interval=2h'
    $content += 'alias=omsa'
    $content += 'command=check_omsa'
}

if (Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Shared=True") {
    $content += '[/settings/scheduler/schedules/printers]'
    $content += ''
    $content += 'interval=1h'
    $content += 'alias=printers'
    $content += 'command=check_printers'
}

if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -eq 5) {
    $content += '[/settings/scheduler/schedules/time]'
    $content += ''
    $content += 'interval=24h'
    $content += 'alias=time'
    $content += 'command=check_time'
}

$content | Set-Content -Path $Filename -Encoding utf8

if (Get-Service -Name 'nscp' -ErrorAction SilentlyContinue) {
    Write-Output "[*] Restarting NSClient++ service"
    Restart-Service -Name 'nscp'
}

Write-Output "[*] Finished"
Write-Output ""
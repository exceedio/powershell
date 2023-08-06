[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Filename = 'C:\Program Files\NSClient++\nsclient.ini'
)

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
    Write-Output ""
}

Write-Banner

$existingConfig = Get-Content $Filename

if ($existingConfig) {
    Write-Output "[*] Found existing configuration file at $Filename"
}

$hostname = ($existingConfig | Select-String 'hostname=(\S+)').Matches.Groups[1].Value

if ($hostname) {
    Write-Output "[*] Found hostname $hostname in existing configuration file"
} else {
    Write-Output "[!] Hostname not found in existing configuration file; quitting"
    return 1
}

$address  = ($existingConfig | Select-String 'address=(\S+)').Matches.Groups[1].Value

if ($address) {
    Write-Output "[*] Found server address $address in existing configuration file"
} else {
    Write-Output "[!] Server address not found in existing configuration file; quitting"
    return 1
}

$password = ($existingConfig | Select-String 'password=(\S+)').Matches.Groups[1].Value

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
$content += 'ps1 = cmd /c echo scripts\\%SCRIPT% %ARGS%; exit($lastexitcode) | @powershell -noprofile -executionpolicy unrestricted -'
$content += 'vbs = cscript.exe //t:90 //nologo scripts\\lib\\wrapper.vbs %SCRIPT% %ARGS%'
$content += 'exe = cmd /c %SCRIPT% %ARGS%'
$content += 'command -'
$content += ""
$content += "[/settings/external scripts/scripts]"
$content += ""
$content += "check_omsa=scripts/check_openmanage.exe"
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
$content += 'command=check_network'
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
#Requires -Version 5.1

<#
    .SYNOPSIS
        Installs NSClient++ on the local computer
    .DESCRIPTION
        Downloads and installs NSClient++ on the local computer, prompting for
        hostname, monitoring server address, and encryption key during the
        installation. As the final step this script calls Update-NSClientIni.ps1
        to generate the final nsclient.ini file.
    .EXAMPLE
        PS C:\> Install-NSClient.ps1
    .EXAMPLE
        PS C:\> irm https://raw.githubusercontent.com/exceedio/powershell/master/Install-NSClient.ps1 | iex
    .PARAMETER Source
        The source for the NSClient++ installer in MSI format. An appropriate
        default is provided and you should not need to provide a value here.
    .PARAMETER Installer
        The local temporary location of the MSI installer. An appropriate
        default is provided and you should not need to provide a value here.
    .PARAMETER NSClientIniUpdater
        The URL of the Update-NSClientIni.ps1 script that is run as the final
        step of this script to generate the final nsclient.ini. An appropriate
        default is provided and you should not need to provide a value here.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]
    $Source = 'https://github.com/mickem/nscp/releases/download/0.5.2.41/NSCP-0.5.2.41-x64.msi',

    [Parameter(Mandatory=$false)]
    [string]
    $Installer = (Join-Path $env:TEMP 'NSCP-0.5.2.41-x64.msi'),

    [Parameter(Mandatory=$false)]
    [string]
    $NSClientIniUpdater = 'https://raw.githubusercontent.com/exceedio/powershell/master/Update-NSClientIni.ps1'
)

Write-Host "Downloading $Source"
Start-BitsTransfer `
    -Source $Source `
    -Destination $Installer

Write-Host "Silently installing NSClient++"
Start-Process `
    -FilePath "$env:SYSTEMROOT\System32\msiexec.exe" `
    -ArgumentList "/i $Installer /qn /norestart ADDLOCAL=ALL REMOVE=FirewallConfig,OP5Montoring,PythonScript,SampleConfig,Shortcuts" `
    -Wait

Write-Host "Copying custom scripts to scripts folder"
$customscripts = @(
    'check_adreplicationhealth.ps1',
    'check_printers.vbs',
    'check_time.vbs',
    'check_windows_time.bat',
    'check_openmanage.exe'
)
$customscripts | ForEach-Object {
    Start-BitsTransfer `
        -Source "https://exdosa.blob.core.windows.net/public/nscp/scripts/$_" `
        -Destination "C:\Program Files\NSClient++\scripts"
}

Write-Host "Stopping nscp service"
Stop-Service nscp

$ini = @()
$ini += "hostname=$(Read-Host 'Hostname of this machine')"
$ini += "address=$(Read-Host 'Address of monitoring server')"
$ini += "password=$(Read-Host 'Encryption key')"

#
# save the new nsclient.ini file using utf8 encoding
#
Write-Host "Saving values to temporary nsclient.ini file"
$ini -join "`n" | Out-File `
    -FilePath 'C:\Program Files\NSClient++\nsclient.ini' `
    -Encoding utf8 `
    -Force

#
# call out to the script that updates the local nsclient.ini file
#
Write-Host "Updating nsclient.ini with final values"
Invoke-RestMethod -Uri $NSClientIniUpdater | Invoke-Expression

Write-Host "Finished"

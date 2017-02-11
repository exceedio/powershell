<#
.SYNOPSIS
    Configures standard group policy settings
.DESCRIPTION
    This script configures policies that apply to all workstations, servers, or users.
    Some of these policies disable application update functions for third party apps
    (Adobe, Java, etc.). These applications need to be kept up to date using out of
    band tools.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Set-StandardGPOSettings.ps1 | iex
.NOTES
    Author   : jreese@exceedio.com
    Modified : Feb, 10, 2017
#>

param (
    [string] $ClientGPO = 'EXDO-Client',
    [string] $ServerGPO = 'EXDO-Server',
    [string] $UserGPO   = 'EXDO-User'
)

function Disable-AdobeUpdate {
    param (
        [string] $Name
    )
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\11.0\FeatureLockDown" -ValueName bUpdater -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -ValueName bUpdater -Type DWord -Value 0
}

function Disable-AdobeFeatures {
    param (
        [string] $Name
    )
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -ValueName bUsageMeasurement -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleAdobeDocumentServices -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleAdobeSign -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleFillSign -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleSendAndTrack -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bTogglePrefsSync -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleWebConnectors -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bAdobeSendPluginToggle -Type DWord -Value 1
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -ValueName bShowWelcomeScreen -Type DWord -Value 0
}

function Disable-JavaUpdate {
    param (
        [string] $Name
    )
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\JavaSoft\Java Update\Policy" -ValueName NotifyDownload -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\JavaSoft\Java Update\Policy" -ValueName EnableJavaUpdate -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -ValueName NotifyDownload -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Update -Context Computer -Key "HKLM\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -ValueName EnableJavaUpdate -Type DWord -Value 0
    Set-GPPrefRegistryValue -Name $Name -Action Delete -Context Computer -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName SunJavaUpdateSched -Type String -Value ""
    Set-GPPrefRegistryValue -Name $Name -Action Delete -Context Computer -Key "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -ValueName SunJavaUpdateSched -Type String -Value ""
}

Import-Module GroupPolicy

#
# validate inputs
#

$ErrorActionPreference = 'SilentlyContinue'
$Error.PSBase.Clear()

$gpo = Get-GPO -Name $ClientGPO

if ($Error.Count -eq 0) {
    Write-Error "GPO $ClientGPO does not exist. Either create it or specify a different name using the -ClientGPO parameter."
    return
}

$gpo = Get-GPO -Name $ServerGPO

if ($Error.Count -eq 0) {
    Write-Error "GPO $ServerGPO does not exist. Either create it or specify a different name using the -ServerGPO parameter."
    return
}

$gpo = Get-GPO -Name $UserGPO

if ($Error.Count -eq 0) {
    Write-Error "GPO $UserGPO does not exist. Either create it or specify a different name using the -UserGPO parameter."
    return
}


Disable-AdobeUpdate -Name $ClientGPO
Disable-AdobeFeatures -Name $ClientGPO
Disable-JavaUpdate -Name $ClientGPO
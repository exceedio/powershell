<#
.SYNOPSIS
    Configures standard group policy settings
.DESCRIPTION
    This script configures policies that apply to all workstations, servers, or users.
    Some of these policies disable application update functions for third party apps
    (Adobe, Java, etc.). These applications need to be kept up to date using out of
    band tools.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Create-StandardGPOSettings.ps1 -UseBasicParsing | iex
.NOTES
    Author   : jreese@exceedio.com
    Modified : Feb, 10, 2017
#>

param (
    [string] $ClientGPO = 'EXDO-Client',
    [string] $ServerGPO = 'EXDO-Server',
    [string] $UserGPO   = 'EXDO-User'
)

function Update-GPPrefRegistryValue {

    param (
        [string] $Name,
        [PreferenceAction] $Action = 'Update',
        [GpoConfiguration] $Context = 'Computer',
        [string] $Key,
        [string] $ValueName,
        [psobject] $Value,
        [RegistryValueKind] $Type = 'DWord'
    )

    $pref = Get-GPPrefRegistryValue -Name $Name -Context $Context -Key $Key -ValueName $ValueName
    
    if ($pref -ne $null -and $pref.Value -ne $Value) {
        Remove-GPPrefRegistryValue -Name $Name -Context $Context -Key $Key -ValueName $ValueName
    }
    
    if ($pref -eq $null -or $pref.Value -ne $Value) {
        Set-GPPrefRegistryValue -Name $Name -Action $Action -Context Context -Key $Key -ValueName $ValueName -Type $Type -Value $Value
    }
    
    Write-Output "Updated pref $ValueName for $Key"
}

function Configure-AdobeAcrobat11 {

    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\11.0\FeatureLockDown" -ValueName bUpdater -Value 0
}

function Configure-AdobeReaderDC {
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -ValueName bUpdater -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -ValueName bUsageMeasurement -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleAdobeDocumentServices -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleAdobeSign -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleFillSign -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleSendAndTrack -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bTogglePrefsSync -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bToggleWebConnectors -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -ValueName bAdobeSendPluginToggle -Value 1
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -ValueName bShowWelcomeScreen -Value 0
}

function Disable-JavaUpdate {
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\JavaSoft\Java Update\Policy" -ValueName NotifyDownload -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\JavaSoft\Java Update\Policy" -ValueName EnableJavaUpdate -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -ValueName NotifyDownload -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -ValueName EnableJavaUpdate -Value 0
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ValueName SunJavaUpdateSched -Type String -Value "" -Action Delete
    Update-GPPrefRegistryValue -Name $ClientGPO -Key "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -ValueName SunJavaUpdateSched -Type String -Value "" -Action Delete
}

function Test-Inputs() {

    $ErrorActionPreference = 'SilentlyContinue'
    $Error.PSBase.Clear()

    $gpo = Get-GPO -Name $ClientGPO

    if ($Error.Count -ne 0) {
        Write-Warning "GPO $ClientGPO does not exist. Either create it or specify a different name using the -ClientGPO parameter."
        return $false
    }

    $gpo = Get-GPO -Name $ServerGPO

    if ($Error.Count -ne 0) {
        Write-Warning "GPO $ServerGPO does not exist. Either create it or specify a different name using the -ServerGPO parameter."
        return $false
    }

    $gpo = Get-GPO -Name $UserGPO

    if ($Error.Count -ne 0) {
        Write-Warning "GPO $UserGPO does not exist. Either create it or specify a different name using the -UserGPO parameter."
        return $false
    }
    Write-Output "Inputs are valid"
    return $true
}

if ((Get-Module -ListAvailable GroupPolicy) -eq $null) {
    Write-Warning "Missing GroupPolicy module. Run from 2008 R2 or later DC or PC with RSAT."
    return  
}

Import-Module GroupPolicy

if (!(Test-Inputs)) {
    return
}

#Disable-AdobeUpdate -Name $ClientGPO
#Disable-AdobeFeatures -Name $ClientGPO
#Disable-JavaUpdate -Name $ClientGPO
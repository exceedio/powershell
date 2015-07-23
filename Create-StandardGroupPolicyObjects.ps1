Import-Module GroupPolicy

function Disable-GPOUserSettings
{
    param (
        $gpo
    )

    $gpm = New-Object -ComObject GPMgmt.GPM
    $gpmdomain = $gpm.GetDomain($gpo.DomainName, "", $gpm.GetConstants().UseAnyDC)
    $gpoguid = "{$(($gpo.Id).ToString())}"
    $gpmgpo = $gpmdomain.GetGPO($gpoguid)
    $gpmgpo.SetUserEnabled($false)
}

function Disable-GPOComputerSettings
{
    param (
        $GPO
    )

    $gpm = New-Object -ComObject GPMgmt.GPM
    $gpmdomain = $gpm.GetDomain($GPO.DomainName, "", $gpm.GetConstants().UseAnyDC)
    $gpoguid = "{$(($GPO.Id).ToString())}"
    $gpmgpo = $gpmdomain.GetGPO($gpoguid)
    $gpmgpo.SetComputerEnabled($false)
}

function CreateOrGet-GPO
{
    param (
        [string] $Name
    )

    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue

    if ($gpo -eq $null)
    {
        $gpo = New-GPO -Name $Name
    }

    return $gpo
}

function Configure-WindowsUpdatePolicy
{
    $gpo = CreateOrGet-GPO -Name "Windows Update Policy"
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate' -ValueName 'ElevateNonAdmins' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AUPowerManagement' -Value 1 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAutoRebootWithLoggedOnUsers' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AlwaysAutoRebootAtScheduledTime' -Value 1 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAUShutdownOption' -Value 1 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAUAsDefaultShutdownOption' -Value 1 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'NoAutoUpdate' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AUOptions' -Value 4 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'ScheduledInstallDay' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'ScheduledInstallTime' -Value 3 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'UseWUServer' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'IncludeRecommendedUpdates' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'EnableFeaturedSoftware' -Value 0 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AlwaysAutoRebootAtScheduledTime' -Value 1 -Type DWord
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AlwaysAutoRebootAtScheduledTimeMinutes' -Value 5 -Type DWord
    Disable-GPOUserSettings -GPO $gpo
}

function Configure-WindowsUpdatePolicyExclusions
{
    $gpo = CreateOrGet-GPO -Name "Windows Update Policy Exclusions"
    $gpo | Set-GPRegistryValue -Key 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ValueName 'AUOptions' -Value 2 -Type DWord
    Disable-GPOUserSettings -GPO $gpo
}

Configure-WindowsUpdatePolicy
Configure-WindowsUpdatePolicyExclusions
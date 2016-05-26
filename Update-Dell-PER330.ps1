<#
.SYNOPSIS
    Update Dell PowerEdge R330 firmware and drivers (May 26, 2016)
.DESCRIPTION
    This script downloads and installs the current BIOS, chipset, network,
    and other updates that are applicable to a Dell PowerEdge R330 server.
    The installers run in attended mode. Choose not to restart when prompted
    by the various installers. The server will be automatically restarted
    at the end of the script.
.EXAMPLE
    .\Update-Dell-PER330.ps1
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Update-Dell-PER330.ps1 | iex
#>

function Invoke-InstallerFromWeb {
    param (
        [string] $uri,
        [string] $args
    )

    $filename = $uri.Substring($uri.LastIndexOf("/") + 1)
    $fullpath = "$env:windir\temp\$filename"
    Invoke-WebRequest $uri -OutFile $fullpath
    & $fullpath $args | Out-Host
    Remove-Item $fullpath
}

#
# bios
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03639965M/1/BIOS_FP966_WN64_1.3.2.EXE'

#
# chipset
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03611972M/2/Chipset_Driver_8H5MF_WN64_10.1.2.19_A05.EXE'

#
# broadcom firmware
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03658126M/1/Network_Firmware_21DWR_WN64_20.2.17.EXE'

#
# enable snmp service
#
Add-WindowsFeature SNMP-Service

#
# broadcom drivers
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03650537M/1/Network_Driver_TD70Y_WN64_20.2.0_20.02.04.01.EXE'

#
# perc h730 drivers
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03688531M/1/SAS-RAID_Driver_T7F02_WN64_6.603.07.00_A04.EXE'

#
# perc h730 firmware
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03669858M/1/SAS-RAID_Firmware_VH28K_WN64_25.4.0.0017_A06.EXE'
#
# omsa 8.3 (full install)
#
$folder = "$env:windir\temp\omsa"
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03574476M/1/OM-SrvAdmin-Dell-Web-WINX64-8.3.0-1908_A00.exe' "/auto $folder"
& msiexec.exe /i $folder\windows\SystemsManagementx64\SysMgmtx64.msi | Out-Host
Remove-Item $folder -Recurse

#
# restart machine (will prompt first)
#
Restart-Computer -Confirm:$true
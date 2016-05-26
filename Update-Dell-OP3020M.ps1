<#
.SYNOPSIS
    Update Dell OptiPlex 3020M firmware and drivers (May 26, 2016)
.DESCRIPTION
    This script downloads and installs the current BIOS, chipset, network,
    and other updates that are applicable to a particular Dell model.
    The installers run in attended mode. Choose not to restart when prompted
    by the various installers. The server will be automatically restarted
    at the end of the script.
.EXAMPLE
    .\Update-Dell-OP3020M.ps1
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Update-Dell-OP3020M.ps1 | iex
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
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03620445M/1/OptiPlex_3020M_A08.exe'

#
# chipset
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03404628M/1/Chipset_Driver_4HP0D_WN32_11.0.0.1163_A01.EXE'
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03120768M/1/Chipset_Driver_C1XJ9_WN32_10.1.1.7_A00.EXE'

#
# seagate
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03464640M/16/Kahuna_ZPE.exe'

#
# graphics
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03622939M/1/Video_Driver_CKC2D_WN32_20.19.15.4390_A03.EXE'

#
# network
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03125011M/1/Network_Driver_531KT_WN64_2.43.2015.609_A00.EXE'

#
# audio
#
Invoke-InstallerFromWeb 'http://downloads.dell.com/FOLDER03515425M/5/Audio_Driver_DFR6K_WN32_6.0.1.6098_A12.EXE'

#
# restart machine (will prompt first)
#
Restart-Computer -Confirm:$true
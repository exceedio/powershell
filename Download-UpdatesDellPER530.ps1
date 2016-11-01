<#
.SYNOPSIS
    Downloads updates (BIOS, network, storage, etc.)
.DESCRIPTION
    Downloads updates (BIOS, network, storage, etc.) for a Dell PowerEdge R530 server
    to the current folder.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Download-UpdatesDellPER530.ps1 -UseBasicParsing | iex
#>

$files = @(
    @{Title = 'BIOS'; Uri = 'http://downloads.dell.com/FOLDER03919962M/1/BIOS_02H3F_WN64_2.2.5.EXE'},
    @{Title = 'iDRAC Firmware'; Uri = 'http://downloads.dell.com/FOLDER03884128M/1/iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE'},
    @{Title = 'Broadcom Firmware'; Uri = 'iwr http://downloads.dell.com/FOLDER03658126M/1/Network_Firmware_21DWR_WN64_20.2.17.EXE'},
    @{Title = 'Broadcom Driver'; Uri = 'http://downloads.dell.com/FOLDER03650537M/1/Network_Driver_TD70Y_WN64_20.2.0_20.02.04.01.EXE'},
    @{Title = 'PERC H730/H730P/H830 Firmware'; Uri = 'http://downloads.dell.com/FOLDER03944869M/3/SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE'},
    @{Title = 'PERC H730/H730P/H830 Driver'; Uri = 'http://downloads.dell.com/FOLDER03940130M/4/SAS-RAID_Driver_6V4WY_WN64_6.604.06.00_A05.EXE'},
    @{Title = 'OpenManage Server Administrator'; Uri = 'http://downloads.dell.com/FOLDER03909716M/1/OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe'}
)

$total = $files.Length

for ($i=0; $i -lt $total; $i++) {
    $item = $files[$i]
    $title = $item.Title
    $uri = $item.Uri
    $filename = $uri.Substring($uri.LastIndexOf("/") + 1)
    if (!(Test-Path $filename)) {
        Write-Progress -Activity 'Downloading' -Status "Downloaded $i of $total" -CurrentOperation $title -PercentComplete (($i+1 / $total) * 100)
        iwr $uri -UseBasicParsing | Out-File $filename
    }
}

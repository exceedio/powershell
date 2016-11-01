<#
.SYNOPSIS
    Downloads updates (BIOS, network, storage, etc.)
.DESCRIPTION
    Downloads updates (BIOS, network, storage, etc.) for a Dell PowerEdge R530 server
    to the current folder.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Download-UpdatesDellPER530.ps1 | iex
#>

if (Test-Path BIOS_02H3F_WN64_2.2.5.EXE) {
    iwr http://downloads.dell.com/FOLDER03919962M/1/BIOS_02H3F_WN64_2.2.5.EXE -OutFile BIOS_02H3F_WN64_2.2.5.EXE
}

if (Test-Path iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE) {
    iwr http://downloads.dell.com/FOLDER03884128M/1/iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE -OutFile iDRAC-with-Lifecycle-Controller_Firmware_2091K_WN64_2.40.40.40_A00.EXE
}

if (Test-Path Network_Firmware_21DWR_WN64_20.2.17.EXE) {
    iwr http://downloads.dell.com/FOLDER03658126M/1/Network_Firmware_21DWR_WN64_20.2.17.EXE -OutFile Network_Firmware_21DWR_WN64_20.2.17.EXE
}

if (Test-Path Network_Driver_TD70Y_WN64_20.2.0_20.02.04.01.EXE) {
    iwr http://downloads.dell.com/FOLDER03650537M/1/Network_Driver_TD70Y_WN64_20.2.0_20.02.04.01.EXE -OutFile Network_Driver_TD70Y_WN64_20.2.0_20.02.04.01.EXE
}

if (Test-Path SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE) {
    iwr http://downloads.dell.com/FOLDER03944869M/3/SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE -OutFile SAS-RAID_Firmware_2H45F_WN64_25.5.0.0018_A08.EXE
}

if (Test-Path SAS-RAID_Driver_6V4WY_WN64_6.604.06.00_A05.EXE) {
    iwr http://downloads.dell.com/FOLDER03940130M/4/SAS-RAID_Driver_6V4WY_WN64_6.604.06.00_A05.EXE -OutFile SAS-RAID_Driver_6V4WY_WN64_6.604.06.00_A05.EXE
}

if (Test-Path OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe) {
    iwr http://downloads.dell.com/FOLDER03909716M/1/OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe -OutFile OM-SrvAdmin-Dell-Web-WINX64-8.4.0-2193_A00.exe
}
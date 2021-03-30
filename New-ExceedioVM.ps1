<#
.SYNOPSIS
    Creates a consistent virtual machine.
.DESCRIPTION
    Use this script to create any virtual machine that is created on Hyper-V Server 2016 or later.
.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioVM.ps1 -UseBasicParsing | iex
.NOTES
    Filename : New-ExceedioVM.ps1
    Author   : jreese@exceedio.com
    Modified : Mar 29, 2021
#>

$Name                = $null
$Purpose             = $null
$VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks'
$InstallMedia        = 'SW_DVD9_Win_Server_STD_CORE_2019_1809.13_64Bit_English_DC_STD_MLF_X22-57176.ISO'
$InstallMediaPath    = 'C:\Users\Public\Documents\ISO'
$Memory              = 4GB
$ProcessorCount      = 4
$VirtualSwitchName   = 'External Virtual Switch'
$StartDelayInSeconds = 120

#
# gather input
#

if (!$Name) {
    $Name = Read-Host "Name of virtual machine (e.g. VMnnnn)?"
}

if (!$Purpose) {
    $Purpose = Read-Host "Purpose of virtual machine (e.g. Azure AD Connect)?"
}

$Path = Join-Path $VirtualHardDiskPath "$Name.vhdx"

if (!(Test-Path $Path)) {
    Write-Host "Creating fixed size virtual hard disk..."
    New-VHD -Path $Path -Fixed -SizeBytes 120GB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
}

Write-Host "Creating virtual machine..."
$vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $Memory -VHDPath $Path
$vm | Set-VM -ProcessorCount $ProcessorCount -Notes $Purpose
$vm | Set-VM -AutomaticStartAction Start -AutomaticStartDelay $StartDelayInSeconds -AutomaticStopAction Shutdown
$vm | Add-VMDvdDrive -ControllerNumber 0 -Path (Join-Path $InstallMediaPath $InstallMedia)
$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VirtualSwitchName
$vm | Get-VMNetworkAdapter | Set-VMNetworkAdapter -VMQWeight 0
$vm | Get-VMIntegrationService -Name "Time Synchronization" | Disable-VMIntegrationService

Write-Host "Setting boot order to enable DVD boot..."
Set-VMFirmware -VMName $Name -BootOrder ((Get-VMHardDiskDrive -VMName $Name -ControllerNumber 0 -ControllerLocation 0), (Get-VMDvdDrive -VMName $Name))
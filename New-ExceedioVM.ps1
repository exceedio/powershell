<#
.SYNOPSIS
    Creates a consistent virtual machine.
.DESCRIPTION
    Use this script to create any virtual machine that is created on Hyper-V Server 2012 R2 or later.
.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioVM.ps1 -UseBasicParsing | iex
#>

$Name                = $null
$Purpose             = $null
$VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks'
$InstallMedia        = 'SW_DVD9_Win_Server_STD_CORE_2016_64Bit_English_-4_DC_STD_MLF_X21-70526.ISO'
$InstallMediaPath    = 'C:\Users\Public\Documents\ISO'
$Memory              = 4GB
$ProcessorCount      = 2
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
    Optimize-Volume -DriveLetter D -Defrag -Verbose
    Write-Host "Creating fixed size virtual hard disk..."
    New-VHD -Path $Path -Fixed -SizeBytes 60GB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
}

Write-Host "Creating virtual machine..."
$vm = New-VM -Name $Name -Generation 1 -MemoryStartupBytes $Memory -VHDPath $Path
$vm | Set-VM -ProcessorCount $ProcessorCount -Notes $Purpose
$vm | Set-VM -AutomaticStartAction Start -AutomaticStartDelay $StartDelayInSeconds -AutomaticStopAction Shutdown
$vm | Get-VMDvdDrive | Set-VMDvdDrive -Path (Join-Path $InstallMediaPath $InstallMedia)
$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VirtualSwitchName
$vm | Get-VMNetworkAdapter | Set-VMNetworkAdapter -VMQWeight 0
$vm | Get-VMIntegrationService -Name "Time Synchronization" | Disable-VMIntegrationService

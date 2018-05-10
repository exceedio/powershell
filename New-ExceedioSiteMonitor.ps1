<#
.SYNOPSIS
    Creates a consistent site monitoring virtual machine.
.DESCRIPTION
    Use this script to create a site monitor on Hyper-V Server 2012 R2 or later.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioSiteMonitor.ps1 -UseBasicParsing | iex
#>

$Name                = 'SITEMONITOR'
$Purpose             = 'Prometheus Site Monitor'
$VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks'
$InstallMedia        = 'C:\Users\Public\Documents\ISO\ubuntu-18.04-live-server-amd64.iso'
$Memory              = 2GB
$ProcessorCount      = 1
$VirtualSwitchName   = 'External Virtual Switch'
$StartDelayInSeconds = 120
$Path                = Join-Path $VirtualHardDiskPath "$Name-OS.vhdx"

if (!(Test-Path $InstallMedia)) {
    Write-Output "Downloading installation media..."
    iwr http://releases.ubuntu.com/18.04/ubuntu-18.04-live-server-amd64.iso -UseBasicParsing -OutFile $InstallMedia
}

if (!(Test-Path $Path)) {
    Write-Host "Creating fixed size virtual hard disk..."
    Optimize-Volume -DriveLetter D -Defrag -Verbose
    New-VHD -Path $Path -Fixed -SizeBytes 20GB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
}

$vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $Memory -VHDPath $Path
$vm | Set-VM -ProcessorCount $ProcessorCount -Notes $Purpose
$vm | Set-VM -AutomaticStartAction Start -AutomaticStartDelay $StartDelayInSeconds -AutomaticStopAction Shutdown
$vm | Add-VMDvdDrive | Set-VMDvdDrive -Path $InstallMedia
$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VirtualSwitchName
$vm | Get-VMNetworkAdapter | Set-VMNetworkAdapter -VMQWeight 0
$vm | Get-VMIntegrationService -Name "Time Synchronization" | Disable-VMIntegrationService
$vm | Set-VMFirmware -BootOrder ((Get-VMHardDiskDrive -VMName $Name -ControllerNumber 0 -ControllerLocation 0), (Get-VMDvdDrive -VMName $Name))

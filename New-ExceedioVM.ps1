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

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $Name,
    [Parameter()]
    [String]
    $Purpose,
    [Parameter()]
    [String]
    $VirtualSwitchName = 'External Virtual Switch',
    [Parameter()]
    [String]
    $InstallationMedia = 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2022_2108.7_64Bit_English_DC_STD_MLF_X23-09508.ISO',
    [Parameter()]
    [Int64]
    $MemoryStartupBytes = 2GB,
    [Parameter()]
    [Int64]
    $ProcessorCount = 2,
    [Parameter()]
    [Int32]
    $AutomaticStartDelaySeconds = 120,
    [Parameter()]
    [UInt64]
    $OperatingSystemVhdSizeBytes = 120GB,
    [Parameter()]
    [Switch]
    $StartWhenFinished = $false,
    [Parameter()]
    [Switch]
    $OverwriteExistingVhd = $false,
    [Parameter()]
    [String]
    $ExistingVirtualHardDiskPath
)

if (!$Name) {
    $Name = Read-Host "Name of virtual machine (e.g. VMnnnn)?"
}

if (!$Purpose) {
    $Purpose = Read-Host "Purpose of virtual machine (e.g. Azure AD Connect)?"
}

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Warning "A virtual machine named $Name already exists; quitting..."
    exit
}

if (Test-Path $ExistingVirtualHardDiskPath) {
    Write-Output "Using existing virtual hard disk at $ExistingVirtualHardDiskPath..."
    $VhdPath = $ExistingVirtualHardDiskPath
}
else {
    $VhdPath = Join-Path (Get-VMHost).VirtualHardDiskPath "$Name.vhdx"
    if (-not (Test-Path $VhdPath) -or ($OverwriteExistingVhd)) {
        Write-Output "Creating fixed size virtual hard disk..."
        if (Test-Path $VhdPath) {
            Remove-Item $VhdPath -Force
        }
        New-VHD -Path $VhdPath -Fixed -SizeBytes $OperatingSystemVhdSizeBytes -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
    }
}

Write-Output "Creating virtual machine..."
$vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryStartupBytes -VHDPath $VhdPath
Write-Output "Setting processor count to $ProcessorCount..."
$vm | Set-VM -ProcessorCount $ProcessorCount -Notes $Purpose
Write-Output "Configuring automatic shutdown and automatic start delay of $AutomaticStartDelaySeconds seconds..."
$vm | Set-VM -AutomaticStartDelay $AutomaticStartDelaySeconds -AutomaticStartAction Start -AutomaticStopAction Shutdown
Write-Output "Disabling automatic checkpoints..."
$vm | Set-VM -CheckpointType Disabled
Write-Output "Adding a DVD drive to hold installation media..."
$vm | Add-VMDvdDrive -ControllerNumber 0 -Path $InstallationMedia
Write-Output "Connecting network adapter to $VirtualSwitchName..."
$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VirtualSwitchName
Write-Output "Disabling VMQ to avoid Broadcom bugs..."
$vm | Get-VMNetworkAdapter | Set-VMNetworkAdapter -VMQWeight 0
Write-Output "Disabling time synchronization with hypervisor..."
$vm | Get-VMIntegrationService -Name "Time Synchronization" | Disable-VMIntegrationService
Write-Output "Configuring boot order to enable DVD boot..."
Set-VMFirmware -VMName $Name -BootOrder ((Get-VMHardDiskDrive -VMName $Name -ControllerNumber 0 -ControllerLocation 0), (Get-VMDvdDrive -VMName $Name))

if ($StartWhenFinished) {
    Write-Output "Starting virtual machine..."
    $vm | Start-VM
    Write-Output "Waiting 10 seconds for MAC address to be populated..."
    Start-Sleep -Seconds 10
}

Write-Output "Create a new server asset with the following properties:"
Write-Output "  Name:             $Name"
Write-Output "  Manufacturer:     Microsoft"
Write-Output "  Model:            Virtual Machine"
Write-Output "  Location:         <same as hypervisor>"
Write-Output "  Tag Number:       $($Name.Substring(2))"
Write-Output "  Serial Number:    $($vm.Id)"
Write-Output "  Purchase Date:    $(Get-Date -DisplayHint Date)"
Write-Output "  IP Address:       <ip>"
Write-Output "  MAC Address:      $(($vm | Get-VMNetworkAdapter).MacAddress -replace '..(?!$)', '$&:')"
Write-Output "  Purpose:          $Purpose"
Write-Output "  Out of Band Mgmt: None"
Write-Output "  Physical/Virtual: Virtual"
Write-Output "  Physical EID:     $((Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)"
Write-Output "  Backup Type(s):   Datto"
Write-Output "  Operating System: Windows Server 2019"
Write-Output "  OS Purchase Type: <select>"
Write-Output "  OS License Key:   <select>"
Write-Output "  OS CPU Count:     $ProcessorCount"

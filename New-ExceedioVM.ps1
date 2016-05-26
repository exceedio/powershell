<#
.SYNOPSIS
    Creates a consistent virtual machine.
.DESCRIPTION
    Use this script to create any virtual machine that is created on Hyper-V Server 2012 R2 or later.
.PARAMETER Name
    The name of the virtual machine
.EXAMPLE
    .\New-ExceedioVM.ps1 -Name VM9560 -Purpose 'Azure AD Connect' -Start
.EXAMPLE
    .\New-ExceedioVM.ps1 -Name VM9560 -Purpose 'Linux Machine' -Memory 24GB -InstallMedia 'ubuntu-server.iso'
#>

param(
    [Parameter(Mandatory=$true)]
    [string] $Name,

    [Parameter(Mandatory=$true)]
    [string] $Purpose,

    [Parameter()]
    [string] $VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks',

    [Parameter()]
    [string] $InstallMedia = 'SW_DVD9_Windows_Svr_Std_and_DataCtr_2012_R2_64Bit_English_-4_MLF_X19-82891.ISO',

    [Parameter()]
    [string] $InstallMediaPath = 'C:\Users\Public\Documents\ISO',

    [Parameter()]
    [long] $Memory = 8GB,

    [Parameter()]
    [int] $ProcessorCount = 2,

    [Parameter()]
    [string] $VirtualSwitchName = 'External Virtual Switch',

    [Parameter()]
    [int] $StartDelayInSeconds = 120,

    [Parameter()]
    [switch] $Start,

    [Parameter()]
    [switch] $SkipDefrag
)


if (!$SkipDefrag) {
    Write-Host "Please wait while defrag completes..."
    defrag.exe d: /h /u /v /x | Out-File 'defrag.log'
    Write-Host "Defrag completed; see defrag.log for details..."
}

$Path = Join-Path $VirtualHardDiskPath "$Name.vhdx"

if (!(Test-Path $Path)) {
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

#
# attach unattended setup ISO
#
$vm | Add-VMDvdDrive -ControllerNumber 1 -Path .\autounattend.iso

#
# start
#
if ($Start) { Start-VM $Name }

#
# wait for windows to install
#
Write-Host "Continue script AFTER Windows has completed installing..."
pause
$vm | Stop-VM -Force
$vm | Get-VMDvdDrive -ControllerNumber 1 -ControllerLocation 0 | Set-VMDvdDrive -Path $null
$vm | Get-VMDvdDrive -ControllerNumber 1 -ControllerLocation 1 | Remove-VMDvdDrive
$vm | Start-VM

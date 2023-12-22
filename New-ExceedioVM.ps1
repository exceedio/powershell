#Requires -Version 5.1
#Requires -Modules Hyper-V
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a consistent virtual machine.
.DESCRIPTION
    Use this script to create any virtual machine that is created on Hyper-V Server 2016 or later. All parameters
    are optional and you will be prompted for necessary parameters if you do not provide them as arguments to this
    script.
.PARAMETER Name
    The name of the virtual machine
.PARAMETER Purpose
    The purpose or role of the virtual machine
.PARAMETER VirtualSwitchName
    The name of the virtual switch to which the primary NIC will be attached
.PARAMETER ProcessorCount
    The number of virtual CPUs to assign to this virtual machine
.PARAMETER MemoryStartupBytes
    The amount of memory in bytes to assign to this virtual machine (e.g. 4GB)
.PARAMETER OperatingSystemVhdSizeBytes
    The size of the C: volume in bytes (e.g. 60GB)
.PARAMETER OperatingSystemVhdPath
    The folder in which to create the virtual hard disk that corresponds with the C: volume
.PARAMETER DataVhdSizeBytes
    The size of the optional D: volume in bytes (e.g. 500GB)
.PARAMETER DataVhdPath
    The folder in which to create the virtual hard disk that corresponds with the D: volume
.PARAMETER InstallationMedia
    Path to an ISO file that will be attached to the virtual machine for operating system installation
.PARAMETER AutomaticStopAction
    The action to take when the host is shutting down or restarting
.PARAMETER AutomaticStartDelaySeconds
    The number of seconds to delay startup when the host is starting
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioVM.ps1 -UseBasicParsing | iex
.NOTES
    Filename : New-ExceedioVM.ps1
    Author   : jreese@exceedio.com
    Modified : Nov 10, 2023
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Name,
    [Parameter()]
    [string]
    $Purpose,
    [Parameter()]
    [string]
    $VirtualSwitchName,
    [Parameter()]
    [Int64]
    $VlanId,
    [Parameter()]
    [Int64]
    $ProcessorCount,
    [Parameter()]
    [Int64]
    $MemoryStartupBytes,
    [Parameter()]
    [UInt64]
    $OperatingSystemVhdSizeBytes,
    [Parameter()]
    [string]
    $OperatingSystemVhdPath,
    [Parameter()]
    [UInt64]
    $DataVhdSizeBytes,
    [Parameter()]
    [string]
    $DataVhdPath,
    [Parameter()]
    [string]
    $InstallationMedia,
    [Parameter()]
    [Microsoft.HyperV.PowerShell.OnOffState]
    $SecureBoot = 'On',
    [Parameter()]
    [Microsoft.HyperV.PowerShell.StopAction]
    $AutomaticStopAction = 'Save',
    [Parameter()]
    [Int32]
    $AutomaticStartDelaySeconds = 180
)

if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Import-Module Hyper-V
}

if (!$Name) {
    $Name = Read-Host "Name of virtual machine (e.g. VMnnnn)?"
}

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Warning "A virtual machine named $Name already exists; quitting..."
    return
}

if (!$Purpose) {
    $Purpose = Read-Host "Purpose of virtual machine (e.g. Azure AD Connect)?"
}

if (!$VirtualSwitchName) {

    $virtualSwitches = @(Get-VMSwitch)

    if (-not $virtualSwitches) {
        Write-Warning "There are no virtual switches on this Hyper-V parent; quitting..."
        return
    }

    Write-Output "Virtual switch selection:"
    for ($i = 0; $i -lt $virtualSwitches.Count; $i++) {
        Write-Output "  $($i + 1): $($virtualSwitches[$i].Name)"
    }

    while ($true) {
        $selection = Read-Host "Enter the number of the virtual switch"
        if ($selection -match "^\d+$" -and $selection -ge 1 -and $selection -le $($virtualSwitches.Count)) {
            break
        }
        else {
            Write-Host "Invalid selection, please enter a number between 1 and $($virtualSwitches.Count)"
        }
    }

    $VirtualSwitchName = $virtualSwitches[$selection - 1].Name
}

if (-not $VlanId) {
    $selection = Read-Host "Enter the VLAN ID for this virtual machine or leave blank for none"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        $VlanId = $selection
    }
}

if (-not $ProcessorCount) {

    $selection = Read-Host "Enter the processor cores (default is 2)"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        $ProcessorCount = [Int64] $selection
    }
    else {
        $ProcessorCount = 2
    }
}

if (-not $MemoryStartupBytes) {

    $selection = Read-Host "Enter the startup memory in gigabytes (default is 4)"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        $MemoryStartupBytes = ([int] $selection * 1GB)
    }
    else {
        $MemoryStartupBytes = 4GB
    }
}

if (-not $OperatingSystemVhdSizeBytes) {

    $selection = Read-Host "Enter the operating system disk size in gigabytes (default is 80)"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        $OperatingSystemVhdSizeBytes = ([int] $selection * 1GB)
    }
    else {
        $OperatingSystemVhdSizeBytes = 80GB
    }
}

if (-not $OperatingSystemVhdPath) {

    $selection = Read-Host "Enter the operating system disk path (default is $((Get-VMHost).VirtualHardDiskPath))"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        $OperatingSystemVhdPath = $selection
    }
    else {
        $OperatingSystemVhdPath = (Get-VMHost).VirtualHardDiskPath
    }

    $driveInfo = Get-PSDrive -PSProvider FileSystem | Where-Object { $OperatingSystemVhdPath -like "$($_.Root)*" } | Select-Object -First 1
    $threshold = ($driveInfo.Used + $driveInfo.Free) * 0.2
    $freeSpaceAfter = $driveInfo.Free - $OperatingSystemVhdSizeBytes
    if ($freeSpaceAfter -lt $threshold) {
        Write-Warning "Creating a $($OperatingSystemVhdSizeBytes / 1GB)GB file on $($driveInfo.Root) will put us below 20% free space"
    }
}

if (-not $DataVhdSizeBytes) {

    $selection = Read-Host "Enter the data disk size in gigabytes or leave blank for none"

    if (-not [string]::IsNullOrWhiteSpace($selection)) {
        
        $DataVhdSizeBytes = ([int] $selection * 1GB)
      
        $selection = Read-Host "Enter the data disk path (default is $((Get-VMHost).VirtualHardDiskPath))"

        if (-not [string]::IsNullOrWhiteSpace($selection)) {
            $DataVhdPath = $selection
        }
        else {
            $DataVhdPath = (Get-VMHost).VirtualHardDiskPath
        }
    
        $driveInfo = Get-PSDrive -PSProvider FileSystem | Where-Object { $DataVhdPath -like "$($_.Root)*" } | Select-Object -First 1
        $threshold = ($driveInfo.Used + $driveInfo.Free) * 0.2
        $freeSpaceAfter = $driveInfo.Free - $DataVhdSizeBytes
        if ($freeSpaceAfter -lt $threshold) {
            Write-Warning "Creating a $($DataVhdSizeBytes / 1GB)GB file on $($driveInfo.Root) will put us below 20% free space"
        }
    }
}

if (-not $InstallationMedia) {

    $isoFiles = @(Get-ChildItem -Path 'C:\Users\Public\Documents\ISO')

    if (-not $isoFiles) {
        Write-Warning "There are no ISO files at C:\Users\Public\Documents\ISO; quitting..."
        break
    }

    Write-Output "Installation media selection:"
    for ($i = 0; $i -lt $isoFiles.Count; $i++) {
        Write-Output "  $($i + 1): $($isoFiles[$i].Name)"
    }

    while ($true) {
        $selection = Read-Host "Enter the number of the installation media"
        if ($selection -match "^\d+$" -and $selection -ge 1 -and $selection -le $($isoFiles.Count)) {
            break
        }
        else {
            Write-Host "Invalid selection, please enter a number between 1 and $($isoFiles.Count)"
        }
    }

    $InstallationMedia = $isoFiles[$selection - 1].FullName
}

if ((Read-Host "Are you creating a domain controller? (y/n)") -eq 'y') {
    $AutomaticStopAction = 'Shutdown'
    $AutomaticStartDelaySeconds = 0
}

if ((Read-Host "Are you creating a non-Windows VM? (y/n)" -eq 'y')) {
    $SecureBoot = 'Off'
}

Write-Output ""
Write-Output "==================================================================="
Write-Output "PREFLIGHT CHECK"
Write-Output "==================================================================="
Write-Output ""
Write-Output "Generation.................. 2"
Write-Output "Name........................ $Name"
Write-Output "Purpose..................... $Purpose"
Write-Output "Virtual cores............... $ProcessorCount"
Write-Output "Memory...................... $($MemoryStartupBytes / 1GB)GB"
Write-Output "Connect to virtual switch... $VirtualSwitchName"
Write-Output "Configure VLAN tag ......... $VlanId"
Write-Output "Automatic start action...... Start"
Write-Output "Automatic start delay....... $AutomaticStartDelaySeconds seconds"
Write-Output "Automatic stop action....... $AutomaticStopAction"
Write-Output "OS disk size................ $($OperatingSystemVhdSizeBytes / 1GB)GB"
Write-Output "OS disk location............ $OperatingSystemVhdPath"
Write-Output "Data disk size.............. $($DataVhdSizeBytes / 1GB)GB"
Write-Output "Data disk location.......... $DataVhdPath"
Write-Output "Installation media.......... $InstallationMedia"
Write-Output "Secure boot ................ $SecureBoot"
Write-Output ""
Write-Output "Press 'y' to proceed, or any other key to quit..."

if ([System.Console]::ReadKey($true).Key -ne 'y') {
    Write-Output "Quitting"
    return
}

$OSDiskPath = Join-Path $OperatingSystemVhdPath "$Name-OS.vhdx"

if (-not (Test-Path $OSDiskPath)) {
    Write-Output "Creating fixed size VHD at $OSDiskPath..."
    New-VHD -Path $OSDiskPath -Fixed -SizeBytes $OperatingSystemVhdSizeBytes -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
}

if ($DataVhdPath) {

    $DataDiskPath = Join-Path $DataVhdPath "$Name-Data.vhdx"

    if (-not (Test-Path $DataDiskPath)) {
        Write-Output "Creating fixed size VHD at $DataDiskPath..."
        New-VHD -Path $DataDiskPath -Fixed -SizeBytes $DataVhdSizeBytes -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096 -BlockSizeBytes 2MB | Out-Null
    }   
}

Write-Output "Creating virtual machine..."
$vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryStartupBytes -VHDPath $OSDiskPath
Write-Output "Setting processor count to $ProcessorCount..."
$vm | Set-VM -ProcessorCount $ProcessorCount -Notes $Purpose
Write-Output "Configuring automatic start and stop actions with start delay of $AutomaticStartDelaySeconds seconds..."
$vm | Set-VM -AutomaticStartDelay $AutomaticStartDelaySeconds -AutomaticStartAction Start -AutomaticStopAction $AutomaticStopAction
Write-Output "Disabling automatic checkpoints..."
$vm | Set-VM -CheckpointType Disabled
if ($DataVhdSizeBytes) {
    Write-Output "Adding data disk..."
    $vm | Add-VMHardDiskDrive -ControllerNumber 0 -ControllerLocation 1 -Path (Join-Path $DataVhdPath "$Name-Data.vhdx")
}
Write-Output "Adding a DVD drive to hold installation media..."
$vm | Add-VMDvdDrive -ControllerNumber 0 -Path $InstallationMedia
Write-Output "Connecting network adapter to $VirtualSwitchName..."
$vm | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $VirtualSwitchName
if ($VlanId) {
    Write-Output "Configuring VLAN id of $VlanId"
    $vm | Get-VMNetworkAdapter | Set-VMNetworkAdapterVlan -VMName $Name -Access -VlanId $VlanId
}
Write-Output "Disabling VMQ to avoid Broadcom bugs..."
$vm | Get-VMNetworkAdapter | Set-VMNetworkAdapter -VMQWeight 0
Write-Output "Disabling time synchronization with hypervisor..."
$vm | Get-VMIntegrationService -Name "Time Synchronization" | Disable-VMIntegrationService
Write-Output "Configuring boot order to enable DVD boot..."
Set-VMFirmware -VMName $Name -BootOrder ((Get-VMHardDiskDrive -VMName $Name -ControllerNumber 0 -ControllerLocation 0), (Get-VMDvdDrive -VMName $Name)) EnableSecureBoot $SecureBoot
Write-Output "Starting virtual machine..."
$vm | Start-VM
Write-Output "Waiting 10 seconds for MAC address to be populated..."
Start-Sleep -Seconds 10

Write-Output "Create a new server asset with the following properties:"
Write-Output "  Name:             $Name"
Write-Output "  Manufacturer:     Microsoft"
Write-Output "  Model:            Virtual Machine"
Write-Output "  Location:         <same as $((Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)>"
Write-Output "  Tag Number:       $($Name.Substring(2))"
Write-Output "  Serial Number:    $($vm.Id)"
Write-Output "  Purchase Date:    $(Get-Date -DisplayHint Date)"
Write-Output "  IP Address:       <ip>"
Write-Output "  MAC Address:      $(($vm | Get-VMNetworkAdapter).MacAddress -replace '..(?!$)', '$&:')"
Write-Output "  Purpose:          $Purpose"
Write-Output "  Out of Band Mgmt: None"
Write-Output "  Physical/Virtual: Virtual"
Write-Output "  Physical EID:     $((Get-WmiObject Win32_SystemEnclosure).SMBIOSAssetTag)"
Write-Output "  Backup Type(s):   <select>"
Write-Output "  Operating System: <select>"
Write-Output "  OS Purchase Type: <select>"
Write-Output "  OS License Key:   <select>"
Write-Output "  OS CPU Count:     $ProcessorCount"
Write-Output "  Start action:     $($vm.AutomaticStartAction)"
Write-Output "  Start delay:      $($vm.AutomaticStartDelay) seconds"
Write-Output "  Stop action:      $($vm.AutomaticStopAction)"
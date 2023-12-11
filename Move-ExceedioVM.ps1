<#
.SYNOPSIS
    Moves a virtual machine from one host to another.
.DESCRIPTION
    Performs an offline (not live) migration of a virtual machine from one Hyper-V host to
    another Hyper-V host by simply copying and importing the appropriate files. This works
    whether machines are part of a domain or not and between hosts that are on different
    versions of Windows (e.g. moving from Windows Server 2012 R2 to Windows Server 2022).

    This script should be run from the SOURCE Hyper-V host, not the destination. It assumes
    that the VM has a single virtual network adapter.

    This script assumes that we are working with VMCX files, not human-readable XML files
    for virtual machine definition files.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Move-ExceedioVM.ps1 | iex
.NOTES
    Filename : Move-ExceedioVM.ps1
    Author   : jreese@exceedio.com
    Modified : Dec, 11, 2023
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [String]
    $VMName,
    [Parameter(Mandatory = $true)]
    [String]
    $DestinationHost,
    [Parameter()]
    [String]
    $DestinationVirtualMachinePath = 'D:\Hyper-V\Virtual Machines',
    [Parameter()]
    [String]
    $DestinationVirtualStoragePath = 'D:\Hyper-V\Virtual Hard Disks'
)

Write-Output "[*] Starting at $(Get-Date)"

if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) {
    Write-Warning "Virtual machine $VMName does not exist on this host"
    return 1
}

Write-Output "[*] Found virtual machine named $VMName"
$vm = Get-VM -Name $VMName

Write-Output "[*] Attempting to connect to destination; enter credentials for destination if prompted"
net.exe use \\$DestinationHost\ipc$ | Out-Null

$DestinationVirtualMachinePathUnc = "\\$DestinationHost\$($DestinationVirtualMachinePath -replace ':','$')"
$DestinationVirtualStoragePathUnc = "\\$DestinationHost\$($DestinationVirtualStoragePath -replace ':','$')"

if (-not (Test-Path $DestinationVirtualMachinePathUnc)) {
    Write-Warning "$DestinationVirtualMachinePath does not exist on $DestinationHost"
    return 1
}

if (-not (Test-Path $DestinationVirtualStoragePathUnc)) {
    Write-Warning "$DestinationVirtualStoragePath does not exist on $DestinationHost"
    return 1
}

$VMGuid = $vm.VMId.Guid
$VMHardwareAddress = $vm.NetworkAdapters.MacAddress

if ($vm.State -eq 'Running') {
    Write-Output ""
    Write-Output "    Virtual machine $VMName with ID $VMGuid needs to be"
    Write-Output "    shut down before moving. After shutting down it will be configured with a static MAC address"
    Write-Output "    of $VMHardwareAddress and any CD/DVD will be ejected before the virtual machine configuration"
    Write-Output "    and disk(s) will be copied to the destination host. You can press Ctrl-C to quit here now."
    Write-Output ""
    pause
    Write-Output ""
    Write-Output "[*] Gracefully shutting down $VMName"
    $vm | Stop-VM -Confirm:$false
}
else {
    Write-Output "[*] Virtual machine $VMName is already stopped"
}

Write-Output "[*] Configuring static MAC address"
Set-VMNetworkAdapter -VMName $VMName -StaticMacAddress $VMHardwareAddress

Write-Output "[*] Ejecting CD/DVD (if any)"
if (Get-VMDvdDrive -VMName $VMName) {
    Get-VMDvdDrive -VMName $VMName | Set-VMDvdDrive -Path $null
}

Write-Output "[*] Copying $($vm.HardDrives.Count) virtual hard disk(s)"
foreach ($vhd in $vm.HardDrives.Path) {
    Start-BitsTransfer -Source $vhd -Destination "$DestinationVirtualStoragePathUnc" -Description "Copying $vhd" -ErrorAction Stop
}

Write-Output "[*] Removing $($vm.HardDrives.Count) virtual hard disk(s) from virtual machine"
$vm | Get-VMHardDiskDrive | Remove-VMHardDiskDrive

Write-Output "[*] Removing all CD/DVDROM drives from virtual machine"
$vm | Get-VMDvdDrive | Remove-VMDvdDrive

Write-Output "[*] Copying $VMName configuration files"
Copy-Item -Path $(Join-Path $vm.ConfigurationLocation "Virtual Machines\$VMGuid") -Destination "$DestinationVirtualMachinePathUnc\$VMGuid" -Recurse
Copy-Item -Path $(Join-Path $vm.ConfigurationLocation "Virtual Machines\$VMGuid.*") -Destination "$DestinationVirtualMachinePathUnc"

Write-Output "[*] Finished at $(Get-Date)"

Write-Output ""
Write-Output "*************************************************************************************"
Write-Output "Run the following PowerShell commands on the TARGET machine to complete the import..."
Write-Output "*************************************************************************************"
Write-Output ""
Write-Output "(Compare-VM -Path '$DestinationVirtualMachinePath\$VMGuid.vmcx').Incompatibilities | fl *"
Write-Output "Import-VM -Path '$DestinationVirtualMachinePath\$VMGuid.vmcx'"
Write-Output "Update-VMVersion -Name $VMName"
Write-Output "Start-VM -Name $VMName"
Write-Output ""

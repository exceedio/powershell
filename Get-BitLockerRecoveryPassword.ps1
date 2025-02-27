#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Outputs the BitLocker recovery password for the C: volume
.DESCRIPTION
    This script outputs the BitLocker recovery password for the C: volume if one
    exists. If attempts to provide a meaningful message if the BitLocker
    PowerShell command(s) are not available, if BitLocker is not enabled, or if
    there is no recovery password for the BitLocker-enabled C: volume.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Get-BitLockerRecoveryPassword.ps1 | iex
.NOTES
    Filename: Get-BitLockerRecoveryPassword.ps1
    Author:   jreese@exceedio.com
    Modified: Feb 27, 2025
#>

try {
    # Verify that the Get-BitLockerVolume cmdlet is available
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-Output "Bitlocker command not available"
        return
    }

    # Retrieve BitLocker information for the C: volume
    $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue

    # If no information was returned, BitLocker might not be enabled or installed
    if (-not $bitlocker) {
        Write-Output "Bitlocker volume not available; Bitlocker probably not enabled"
        return
    }

    # Check if BitLocker protection is enabled
    # ProtectionStatus can be 'On' or the numeric value 1 when enabled
    if (($bitlocker.ProtectionStatus -ne "On") -and ($bitlocker.ProtectionStatus -ne 1)) {
        Write-Output "Bitlocker not enabled"
        return
    }

    # Look for a key protector of type "RecoveryPassword"
    $recoveryKey = $bitlocker.KeyProtector |
        Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
        Select-Object -ExpandProperty RecoveryPassword -First 1

    # If a recovery password was found, output it; otherwise output the default message
    if ($recoveryKey) {
        Write-Output $recoveryKey
    }
    else {
        Write-Output "Bitlocker enabled but no recovery password found"
    }
}
catch {
    Write-Output "Error while checking for Bitlocker password"
}

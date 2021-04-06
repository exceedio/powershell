<#
.SYNOPSIS
    Creates a consistent workstation.
.DESCRIPTION
    Use this script to get a newly installed Windows 10 workstation up to baseline.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/New-ExceedioWS.ps1 -UseBasicParsing | iex
.NOTES
    Filename : New-ExceedioWS.ps1
    Author   : jreese@exceedio.com
    Modified : Apr 6, 2021
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $Name = 'DESKTOP-UQ8F5KL'
)

Write-Output "Installing RSAT tools..."
Get-WindowsCapability -Name Rsat* -Online | Where-Object State -ne Installed | Add-WindowsCapability -Online | Out-Null
Write-Output "Installing 7-Zip..."
Start-BitsTransfer -Source "https://www.7-zip.org/a/7z1900-x64.msi" -Destination "$env:TEMP\7z1900-x64.msi"
Start-Process "msiexec.exe" -ArgumentList @("/i", "$env:TEMP\7z1900-x64.msi", "/qb", "/norestart") -NoNewWindow -Wait
Write-Output "Installing PuTTY..."
Start-BitsTransfer -Source "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.74-installer.msi" -Destination "$env:TEMP\putty-64bit-0.74-installer.msi"
Start-Process "msiexec.exe" -ArgumentList @("/i", "$env:TEMP\putty-64bit-0.74-installer.msi", "/qb", "/norestart") -NoNewWindow -Wait
Write-Output "Installing git for Windows..."
Start-BitsTransfer -Source "https://github.com/git-for-windows/git/releases/download/v2.31.1.windows.1/Git-2.31.1-64-bit.exe" -Destination "$env:TEMP\Git-2.31.1-64-bit.exe"
Start-Process "$env:TEMP\Git-2.31.1-64-bit.exe" -ArgumentList @("/VERYSILENT") -Wait -NoNewWindow

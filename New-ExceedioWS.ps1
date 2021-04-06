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
    $Office365ConfigurationXml = "Configuration-ExceedioWS.xml",
    [Parameter()]
    [String]
    $DownloadPath = "$env:public\Downloads"
)

Write-Output "Installing RSAT tools..."
Get-WindowsCapability -Name Rsat* -Online | Where-Object State -ne Installed | Add-WindowsCapability -Online | Out-Null

Write-Output "Installing 7-Zip..."
Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z1900-x64.msi" -OutFile "$DownloadPath\7z1900-x64.msi"
Start-Process "msiexec.exe" -ArgumentList @("/i", "$DownloadPath\7z1900-x64.msi", "/qb", "/norestart") -NoNewWindow -Wait

Write-Output "Installing PuTTY..."
Invoke-WebRequest -Uri "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.74-installer.msi" -OutFile "$DownloadPath\putty-64bit-0.74-installer.msi"
Start-Process "msiexec.exe" -ArgumentList @("/i", "$DownloadPath\putty-64bit-0.74-installer.msi", "/qb", "/norestart") -NoNewWindow -Wait

Write-Output "Installing git for Windows..."
Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.31.1.windows.1/Git-2.31.1-64-bit.exe" -OutFile "$DownloadPath\Git-2.31.1-64-bit.exe"
Start-Process "$DownloadPath\Git-2.31.1-64-bit.exe" -ArgumentList @("/VERYSILENT") -Wait -NoNewWindow

Write-Output "Installing Microsoft Edge group policy templates..."
Invoke-WebRequest -Uri "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/24215d5a-0288-4036-aaf5-80ce0418e34c/MicrosoftEdgePolicyTemplates.zip" -OutFile "$DownloadPath\MicrosoftEdgePolicyTemplates.zip"
Expand-Archive -Path "$DownloadPath\MicrosoftEdgePolicyTemplates.zip" -DestinationPath "$DownloadPath\MicrosoftEdgePolicyTemplates"
Copy-Item -Path "$DownloadPath\MicrosoftEdgePolicyTemplates\windows\admx\*.admx" -Destination "$env:windir\PolicyDefinitions"
Copy-Item -Path "$DownloadPath\MicrosoftEdgePolicyTemplates\windows\admx\en-US\*.adml" -Destination "$env:windir\PolicyDefinitions\en-US"


Write-Output "Downloading GCM Core user install..."
Invoke-WebRequest -Uri "https://github.com/microsoft/Git-Credential-Manager-Core/releases/download/v2.0.394-beta/gcmcoreuser-win-x86-2.0.394.50751.exe" -OutFile "$DownloadPath\gcmcoreuser-win-x86-2.0.394.50751.exe"
Write-Output "Run $DownloadPath\gcmcoreuser-win-x86-2.0.394.50751.exe as your regular user account"

Write-Output "Downloading Visual Studio Code user install..."
Invoke-WebRequest -Uri "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user" -OutFile "$DownloadPath\VSCodeUserSetup-x64.exe"
Write-Output "Run $DownloadPath\VSCodeUserSetup-x64.exe /SILENT /NORESTART /MERGETASKS=!runcode as your regular user account"

Write-Output "Installing Office 365..."
Invoke-WebRequest -Uri "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_13801-20360.exe" -OutFile "$DownloadPath\officedeploymenttool_13801-20360.exe"
Start-Process "$DownloadPath\officedeploymenttool_13801-20360.exe" -ArgumentList @("/extract:$DownloadPath\odt", "/quiet") -Wait -NoNewWindow
Start-Process "$DownloadPath\odt\setup.exe" -ArgumentList @("/download", "$Office365ConfigurationXml") -Wait -NoNewWindow
Start-Process "$DownloadPath\odt\setup.exe" -ArgumentList @("/configure", "$Office365ConfigurationXml") -Wait -NoNewWindow

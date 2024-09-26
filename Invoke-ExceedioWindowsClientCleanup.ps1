#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Safely cleans up disk space on a Windows client computer
.DESCRIPTION
    Removes temporary files and crash dumps, cleans up unused user profiles,
    and resets base using the DISM tool which removes the ability to uninstall
    updates and service packs.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Invoke-ExceedioWindowsClientCleanup.ps1 | iex
.NOTES
    Filename: Invoke-ExceedioWindowsClientCleanup.ps1
    Author:   jreese@exceedio.com
    Modified: Sep 25, 2024
#>

[CmdletBinding()]
param(
    [Parameter()]
    [datetime]
    $UserProfileThreshold = (Get-Date).AddDays(-90),
    [Parameter()]
    [switch]
    $PerformComponentCleanup
)

function Get-StaleUserProfiles
{
    [OutputType([CimInstance[]])]
    param()

    $results = @()

    foreach ($profile in Get-CimInstance -ClassName Win32_UserProfile)
    {
        $localPath = $profile.LocalPath

        if ($profile.Special)
        {
            Write-Host "Skipping special profile $localPath"
            continue
        }

        if ($profile.Loaded)
        {
            Write-Host "Skipping loaded profile $localPath"
            continue
        }

        if ($reginfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object { $_.ProfileImagePath -eq $localPath })
        {
            #
            # calculates last time profile was loaded and unloaded in a more
            # accurate way than checking the ciminstance or checking file date
            # of folder or ntuser.dat file, all of which are unreliable
            #
            $lastLoadTime = [datetime]::FromFileTime([Int64]($reginfo.LocalProfileLoadTimeHigh) -shl 32 -bor [Int64]($reginfo.LocalProfileLoadTimeLow))
            $lastUnloadTime = [datetime]::FromFileTime([Int64]($reginfo.LocalProfileUnloadTimeHigh) -shl 32 -bor [Int64]($reginfo.LocalProfileUnloadTimeLow))
            
            if ($lastLoadTime -lt $UserProfileThreshold -and $lastUnloadTime -lt $UserProfileThreshold)
            {
                Write-Host "User profile $localPath is stale ($lastUnloadTime)"
                $results += $profile
            } else
            {
                Write-Host "User profile $localPath is not stale ($lastUnloadTime)"
            }
        } else
        {
            Write-Host "Profile $localPath missing from registry" -ForegroundColor Yellow
        }
    }

    $results
}

# dumps
Remove-Item 'C:\Windows\LiveKernelReports\*.dmp' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\memory.dmp' -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\ProgramData\Kaseya\Data\crashdumps\*.dmp' -Force -ErrorAction SilentlyContinue

# temporary files
Get-ChildItem C:\Windows\Temp\* -Include *.tmp, *.log, *.txt -File | Remove-Item -Force

# temporary directories
Get-ChildItem 'C:\Windows\Temp\*.tmp' -Directory | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# stale user profiles
Get-StaleUserProfiles #| Remove-CimInstance

if ($PerformComponentCleanup)
{
    # windows component cleanup
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
}

Write-Host "Finished"
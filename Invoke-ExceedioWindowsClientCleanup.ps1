#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Safely cleans up disk space on a Windows client computer
.DESCRIPTION
    Removes temporary files and crash dumps, cleans up unused user profiles,
    and optionally resets base using the DISM tool which removes the ability to
    uninstall updates and service packs.

    The default user profile freshness check uses 90 days. Profiles older than
    90 days are removed without prompting. Profiles that are considered special
    such as LocalService are never removed.

    The component cleanup is optional and not enabled by default if you run
    using the example below. You will need to download the script and run it
    using the -PerformComponentCleanup switch to enable component cleanup.

    Example output:

    Starting
    Free space on C: 13.95 GB, Percent Free: 11.88%
    Removing memory dumps
    Removing temporary files from C:\Windows\Temp
    Removing temporary folders from C:\Windows\Temp
    Removing stale user profiles
    User profile C:\Users\Administrator is stale (02/23/2023 08:23:40)
    User profile C:\Users\alice is not stale (07/22/2024 10:23:33)
    User profile C:\Users\bob is stale (03/08/2023 16:48:14)
    Skipping special profile C:\windows\ServiceProfiles\LocalService
    Skipping special profile C:\windows\ServiceProfiles\NetworkService
    Skipping special profile C:\windows\system32\config\systemprofile
    Removing stale profile C:\Users\Administrator
    Removing stale profile C:\Users\bob
    Free space on C: 15.75 GB, Percent Free: 13.41%
    Finished
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

function Set-CleanManagerStateFlags
{
    #
    # this number can be anything you want; it's simply a label that
    # is used to identify a set of state flags that you use when calling
    # cleanmgr.exe from the command line for silent operation
    #
    $stateFlagsId = '5900'

    #
    # these items are generally considered safe to clean on any system
    # without causing harm to the system
    #
    $itemsToClean = @(
        'Active Setup Temp Folders',
        'BranchCache',
        'Content Indexer Cleaner',
        'Delivery Optimization Files',
        'D3D Shader Cache',
        'Device Driver Packages',
        'Downloaded Program Files',
        'GameNewsFiles',
        'GameStatisticsFiles',
        'GameUpdateFiles',
        'Internet Cache Files',
        'Memory Dump Files',
        'Offline Pages Files',
        'Old ChkDsk Files',
        'Previous Installations',
        'RetailDemo Offline Content',
        'Service Pack Cleanup',
        'Setup Log Files',
        'System error memory dump files',
        'System error minidump files',
        'Temporary Files',
        'Temporary Setup Files',
        'Temporary Sync Files',
        'Thumbnail Cache',
        'Update Cleanup',
        'Upgrade Discarded Files',
        'Windows Defender',
        'Windows Error Reporting Archive Files',
        'Windows Error Reporting Files',
        'Windows Error Reporting Queue Files',
        'Windows Error Reporting System Archive Files',
        'Windows Error Reporting System Queue Files',
        'Windows Error Reporting Temp Files',
        'Windows ESD installation files',
        'Windows Upgrade Log Files'
    )

    $pathToVolumeCaches = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'

    foreach ($item in $itemsToClean)
    {
        $fullPath = "$pathToVolumeCaches\$item"

        if (Test-Path -Path $fullPath)
        {
            Write-Host "Enabling automatic clean for '$item'"
            Set-ItemProperty -Path $fullPath -Name "StateFlags$stateFlagsId" -Type DWord -Value 2
        }
    }
}

function Get-StaleUserProfiles
{
    [OutputType([CimInstance[]])]
    param()

    $results = @()

    foreach ($profile in Get-CimInstance -ClassName Win32_UserProfile | Sort-Object LocalPath)
    {
        $localPath = $profile.LocalPath

        if ($localPath.Trim().Length -eq 0)
        {
            Write-Host "Skipping blank profile"
            continue
        }

        if ($localPath -like 'C:\Users\.NET*')
        {
            Write-Host "Skipping .NET profile $localPath"
            continue
        }

        if ($localPath -like 'C:\Windows\ServiceProfiles\*')
        {
            Write-Host "Skipping service profile $localPath"
            continue
        }

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
                Write-Host "User profile $localPath is stale ($lastUnloadTime)" -ForegroundColor Yellow
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

function Clear-Folder
{
    param(
        [Parameter()]
        [string]
        $Path
    )

    Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
}

function Write-FreeSpace
{
    Write-Host (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | ForEach-Object { "Free space on C: $([math]::Round($_.FreeSpace / 1GB, 2)) GB, Percent Free: $([math]::Round(($_.FreeSpace / $_.Size) * 100, 2))%" })
}

Write-Host "Starting"
Write-FreeSpace

Write-Host "Removing memory dumps"
Remove-Item 'C:\Windows\LiveKernelReports\*.dmp' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Windows\memory.dmp' -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\ProgramData\Kaseya\Data\crashdumps\*.dmp' -Force -ErrorAction SilentlyContinue

Write-Host "Removing Windows Error Reports"
Remove-Item 'C:\ProgramData\Microsoft\Windows\WER' -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing temporary files from C:\Windows\Temp"
Get-ChildItem C:\Windows\Temp\* -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing Adobe ARM files"
Clear-Folder -Path 'C:\ProgramData\Adobe\ARM'

Write-Host "Removing stale user profiles"
Get-StaleUserProfiles | ForEach-Object {
    Write-Host "Removing stale profile $($_.LocalPath)" -ForegroundColor  Yellow
    $_ | Remove-CimInstance
}

$subfolders = (
    'AppData\Local\CrashDumps',
    'AppData\Local\Temp',
    'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams',
    'AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data',
    'AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage',
    'AppData\Local\Microsoft\Windows\WebCache',
    'AppData\Local\Microsoft\Windows\WER',
    'AppData\Local\Microsoft\Terminal Server Client\Cache',
    'AppData\LocalLow\Google\GoogleEarth\Cache',
    'AppData\Roaming\Default\Cache',
    'AppData\Roaming\Default\Code Cache',
    'AppData\Roaming\Default\Service Worker',
    'AppData\Roaming\Microsoft\Teams\Cache',
    'AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage'
)

Write-Host "Removing user-specific temporary folders and cache"
foreach ($subfolder in $subfolders)
{
    Clear-Folder -Path "C:\Users\*\$subfolder"
}

Write-Host "Removing recycle bins"
Clear-Folder -Path 'C:\$Recycle.Bin'

if ($PerformComponentCleanup)
{
    # windows component cleanup
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
}

Write-FreeSpace
Write-Host "Finished"

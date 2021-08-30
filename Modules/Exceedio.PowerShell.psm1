function Invoke-ExceedioWindowsUpdate {
    <#
    .SYNOPSIS
    Searches, downloads, and installs Windows updates.
    .PARAMETER Criteria
    Search criteria used to determine if an update is applicable. By default we look
    for updates that are not hidden, not installed, should be installed, and are not
    restricted to being discoverable by browsing through available updates.
    .PARAMETER Download
    Value indicating whether to download applicable updates. Defaults to $false.
    .PARAMETER Install
    Value indicating whether to install applicable updates. The -Download switch is
    implied if -Install is used. Defaults to $false.
    .PARAMETER Reboot
    Value indicating whether to automatically reboot the computer if needed after
    installation is complete. Defaults to $false.
    .NOTES
    See https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
    for details about search criteria.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Criteria = "(IsInstalled=0 and IsHidden=0 and BrowseOnly=0 and IsAssigned=1)",
        [Parameter()]
        [Switch]
        $Download = $false,
        [Parameter()]
        [Switch]
        $Install = $false,
        [Parameter()]
        [Switch]
        $Reboot = $false
    )
    Write-Output "Critera: $Criteria"
    $Session = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher = $Session.CreateupdateSearcher()
    Write-Output "Searching for updates..."
    $SearchResult = $Searcher.Search($Criteria)
    if ($SearchResult.Updates -and $SearchResult.Updates.Count -gt 0) {
        foreach ($Update in $SearchResult.Updates) {
            Write-Output ("[+] {0}" -f $Update.Title)
        }
        if ($Download -or $Install) {
            $Downloader = $Session.CreateUpdateDownloader()
            $Downloader.Updates = $SearchResult.Updates
            Write-Output "Downloading updates..."
            $Downloader.Download()
        }
        if ($Download -and $Install) {
            foreach ($Update in $SearchResult.Updates) {
                if (-not $Update.EulaAccepted) {
                    $Update.AcceptEula()
                }
            }
            $Installer = $Session.CreateUpdateInstaller()
            if ($Installer.IsBusy) {
                Write-Error "Windows update installer is busy; try again later"
                return
            }
            if ($Installer.RebootRequiredBeforeInstallation) {
                Write-Error "Windows installer requires a reboot before installing updates; reboot and try again"
                return
            }
            $Installer.AllowSourcePrompts = $false
            $Installer.IsForced = $true
            $Installer.Updates = $SearchResult.Updates
            Write-Output "Installing updates..."
            $Result = $Installer.Install()
            if ($Result.RebootRequired) {
                if ($Reboot) {
                    Restart-Computer -Force
                } else {
                    Write-Output "Installation completed; reboot required but not initiated"
                }
            } else {
                Write-Output "Installation completed; no reboot required"
            }
        }
    } else {
        Write-Output "No updates found"
    }
}

function Install-ExceedioDellCommandUpdate {
    <#
    .SYNOPSIS
    Installs the latest Universal Windows Platform version of Dell Command Update for
    Windows 10 32 and 64 bit. Dell Command Update is used to update BIOS, firmware, and
    drivers for Dell desktop and laptop computers.
    .PARAMETER ConfigurationUri
    Location of the configuration file that is used to get the latest version of the
    Dell Command Update installer. Defaults to the one we include and maintain in the
    Exceedio GitHub repostiory.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ConfigurationUri = 'https://raw.githubusercontent.com/exceedio/powershell/master/Modules/Configuration.xml'
    )
    [xml] $xml = (Invoke-WebRequest -Uri $ConfigurationUri).Content
    $installerUri = $xml.Configuration.Dell.CommandUpdate.Latest
    $installer = $installerUri.Substring($installerUri.LastIndexOf("/") + 1)
    Set-Location $env:TEMP
    Write-Output "Downloading installer..."
    Start-BitsTransfer -Source "$installerUri" -Destination .\$installer
    Write-Output "Installing Dell Command Update for Windows 10; please wait..."
    & .\$installer /S
    Start-Sleep -Seconds 60
    Remove-Item .\$installer
    & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure -silent -autoSuspendBitLocker=enable -userConsent=disable
    Write-Output "Installation completed"
}

function Invoke-ExceedioDellCommandUpdate {
    <#
    .SYNOPSIS
    Scans for installs Dell BIOS, firmware, and driver updates using Dell Command Update
    for desktop and laptop computers.
    .PARAMETER Scan
    Scans for updates and displays results on the console as well as the log file written
    to C:\ProgramData\Dell\logs\dcu\scan.log. Defaults to $false.
    .PARAMETER Install
    Scans and installs updates and displays results on the console as well as the log file
    written to C:\ProgramData\Dell\logs\dcu\scan.log. Defaults to $false.
    .PARAMETER Reboot
    Forcefully reboots the computer following a scan or install. Defaults to $false.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Switch]
        $Scan = $false,
        [Parameter()]
        [Switch]
        $Install = $false,
        [Parameter()]
        [Switch]
        $Reboot = $false
    )
    if ($Scan) {
        & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan -outputLog=C:\ProgramData\Dell\logs\dcu\scan.log
    }
    if ($Install) {
        & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure -silent -autoSuspendBitLocker=enable -userConsent=disable
        & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates -reboot=disable -outputLog=C:\ProgramData\Dell\logs\dcu\applyUpdates.log
    }
    if ($Reboot) {
        Restart-Computer -Force
    }
}

Export-ModuleMember -Function Install-ExceedioDellCommandUpdate, Invoke-ExceedioDellCommandUpdate, Invoke-ExceedioWindowsUpdate
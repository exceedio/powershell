function Invoke-ExceedioWindowsUpdate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Criteria = "(IsInstalled=0 and IsAssigned=1 and AutoSelectOnWebSites=1 and IsHidden=0)",
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
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $BaseUri = 'https://dl.dell.com/FOLDER07582763M/3',
        [Parameter()]
        [String]
        $Installer = 'Dell-Command-Update-Application-for-Windows-10_GRVPK_WIN_4.3.0_A00_02.EXE'
    )
    Set-Location $env:TEMP
    Write-Output "Downloading installer..."
    Start-BitsTransfer -Source "$BaseUri/$Installer" -Destination .\$Installer
    Write-Output "Installing Dell Command Update for Windows 10; please wait..."
    & .\$Installer /S
    Start-Sleep -Seconds 60
    Remove-Item .\$Installer
    Write-Output "Installation completed"
}

function Invoke-ExceedioDellCommandUpdate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Switch]
        $Reboot = $false,
        [Parameter()]
        [Switch]
        $Scan = $false,
        [Parameter()]
        [Switch]
        $Install = $false
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
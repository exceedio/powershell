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

Export-ModuleMember -Function Install-ExceedioDellCommandUpdate, Invoke-ExceedioDellCommandUpdate
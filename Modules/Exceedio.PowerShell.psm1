function Get-Configuration {
    param (
        [Parameter()]
        [String]
        $ConfigurationUri
    )
    return [xml] (Invoke-WebRequest -Uri $ConfigurationUri -UseBasicParsing).Content
}

function Get-FilenameFromUri {
    param (
        [Parameter()]
        [String]
        $Uri
    )
    return $Uri.Substring($Uri.LastIndexOf("/") + 1)
}

function Install-FromUri {
    param (
        [Parameter()]
        [String]
        $Name,
        [Parameter()]
        [String]
        $Uri,
        [Parameter()]
        [String]
        $SHA256Hash
    )
    $filename = Join-Path -Path $env:TEMP -ChildPath (Get-FilenameFromUri -Uri $Uri)
    Write-Output "[*] Downloading installer..."
    Start-BitsTransfer -Source "$Uri" -Destination "$filename"
    Write-Output "[*] Verifying file hash..."
    $hash = (Get-FileHash -Path "$filename" -Algorithm "SHA256").Hash
    if ($hash -ne $SHA256Hash) {
        Write-Error "[!] File hash $hash did not match expected hash $SHA256Hash" -ErrorAction Stop
    }
    Write-Output "[*] Installing $Name; please wait..."
    & $filename /S
    Start-Sleep -Seconds 60
    Remove-Item $filename
    Write-Output "[*] Installation completed"
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
    .EXAMPLE
    PS> Install-ExceedioDellCommandUpdate
    .EXAMPLE
    PS> Install-ExceedioDellCommandUpdate -ConfigurationUri https://somepath/to/your/config.xml
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ConfigurationUri = 'https://raw.githubusercontent.com/exceedio/powershell/master/Modules/Configuration.xml'
    )
    $xml = Get-Configuration -ConfigurationUri $ConfigurationUri
    Install-FromUri `
        -Name "Dell Command Update for Windows 10" `
        -Uri $xml.Configuration.Dell.CommandUpdate.Latest `
        -SHA256Hash $xml.Configuration.Dell.CommandUpdate.SHA256Hash
    & "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure -silent -autoSuspendBitLocker=enable -userConsent=disable
}

function Install-ExceedioDellCommandConfigure {
    <#
    .SYNOPSIS
    Installs the latest version of Dell Command Configure for Windows 10 32 and 64 bit.
    Dell Command Configure is used to configure Dell desktop and laptop computers.
    .PARAMETER ConfigurationUri
    Location of the configuration file that is used to get the latest version of the
    Dell Command Update installer. Defaults to the one we include and maintain in the
    Exceedio GitHub repostiory.
    .EXAMPLE
    PS> Install-ExceedioDellCommandUpdate
    .EXAMPLE
    PS> Install-ExceedioDellCommandUpdate -ConfigurationUri https://somepath/to/your/config.xml
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $ConfigurationUri = 'https://raw.githubusercontent.com/exceedio/powershell/master/Modules/Configuration.xml'
    )
    $xml = Get-Configuration
    Install-FromUri `
        -Name "Dell Command Configure for Windows 10" `
        -Uri $xml.Configuration.Dell.CommandConfigure.Latest `
        -SHA256Hash $xml.Configuration.Dell.CommandConfigure.SHA256Hash
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
    .EXAMPLE
    PS> Invoke-ExceedioDellCommandUpdate -Scan
    .EXAMPLE
    PS> Invoke-ExceedioDellCommandUpdate -Install
    .EXAMPLE
    PS> Invoke-ExceedioDellCommandUpdate -Install -Reboot
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
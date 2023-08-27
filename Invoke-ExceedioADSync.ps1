#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $AzureApiVersion = '2022-11-02',
    [Parameter()]
    [string]
    $AzureStorageAccount = $env:AZSTORAGEACCOUNT,
    [Parameter()]
    [string]
    $AzureQueueName = $env:AZQUEUENAME,
    [Parameter()]
    [string]
    $AzureSasToken = $env:AZSASTOKEN,
    [Parameter()]
    [string]
    $ActiveDirectoryServer = $env:ADSERVER,
    [Parameter()]
    [string]
    $ActiveDirectoryUsersContainer = $env:ADUSERSCONTAINER,
    [Parameter()]
    [string]
    $AzureADConnectServer = $env:AZADCONNECTSERVER,
    [Parameter()]
    [string]
    $UsersFolderPath = $env:USERSFOLDERPATH,
    [Parameter()]
    [string]
    $Company = $env:COMPANY,
    [Parameter()]
    [string]
    $ProgramDataPath = (Join-Path $env:ProgramData 'Exceedio'),
    [Parameter()]
    [int]
    $MinimumPasswordLength = 14,
    [Parameter()]
    [switch]
    $Preflight = $false,
    [Parameter()]
    [switch]
    $Setup = $false
)

function Write-Banner {
    Write-Output ''
    Write-Output '    |\__/,|   (`\ '
    Write-Output '  _.|o o  |_   ) )'
    Write-Output '-(((---(((------- '  
    Write-Output ''    
}

function Write-Preflight {
    Write-Output "Company............................. : $Company"
    Write-Output "Azure storage account name.......... : $AzureStorageAccount"
    Write-Output "Azure storage queue name............ : $AzureQueueName"
    Write-Output "Azure storage shared access token... : $(-join $AzureSasToken[0..40])..."
    Write-Output "Active directory server............. : $ActiveDirectoryServer"
    Write-Output "Active directory users container.... : $ActiveDirectoryUsersContainer"
    Write-Output "Azure AD Connect server (optional).. : $AzureADConnectServer"
    Write-Output "Users folder path (optional)........ : $UsersFolderPath"
    Write-Output ""
}

function Get-RunningElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return ($elevated -or $identity.IsSystem)
}

function New-ProgramDataFolder {
    if (-not (Test-Path $ProgramDataPath)) {
        New-Item -ItemType Directory -Path $ProgramDataPath -Force
        & icacls.exe $ProgramDataPath /inheritance:r | Out-Null
        & icacls.exe $ProgramDataPath /grant "SYSTEM:(OI)(CI)F" | Out-Null
        & icacls.exe $ProgramDataPath /grant "Administrators:(OI)(CI)F" | Out-Null
    }
}

function Receive-AzureStorageQueueMessage {
    Invoke-QueueRestMethod `
        -Method Get `
        -Uri "https://$AzureStorageAccount.queue.core.windows.net/$AzureQueueName/messages$AzureSasToken&numofmessages=1&peekonly=true"
}

function Get-AzureStorageQueueMessage {
    Invoke-QueueRestMethod `
        -Method Get `
        -Uri "https://$AzureStorageAccount.queue.core.windows.net/$AzureQueueName/messages$AzureSasToken&numofmessages=1"
}

function Remove-AzureStorageQueueMessage {
    param (
        [Parameter(Mandatory)]
        [string]
        $MessageId,
        [Parameter(Mandatory)]
        [string]
        $Receipt
    )
    Invoke-QueueRestMethod `
        -Method Delete `
        -Uri "https://$AzureStorageAccount.queue.core.windows.net/$AzureQueueName/messages/$MessageId$AzureSasToken&popreceipt=$Receipt"
}

function Invoke-QueueRestMethod {
    param (
        [Parameter(Mandatory)]
        [string]
        $Uri,
        [Parameter()]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
    )

    $headers = @{
        "x-ms-date"    = (Get-Date).ToUniversalTime().ToString("R")
        "x-ms-version" = $AzureApiVersion
    }
    
    Write-Debug "Calling $Uri using method $Method"
    $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -UseBasicParsing
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($response)
    $bytes = $bytes[6..($bytes.Length - 1)]
    $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
    return [xml] $decoded
}

function New-StrongRandomPassword {

    $uchars = 'ABCDEFGHJKMNPQRTUVWXYZ'.ToCharArray()
    $lchars = 'abcdefghjkmnpqrtuvwxyz'.ToCharArray()
    $nchars = '2346789'.ToCharArray()
    $schars = '!@#$^&*'.ToCharArray()

    $password = @(
        (Get-Random -InputObject $uchars)
        (Get-Random -InputObject $lchars)
        (Get-Random -InputObject $nchars)
        (Get-Random -InputObject $schars)
    )

    while ($password.Length -lt $MinimumPasswordLength) {
        $password += Get-Random -InputObject (Get-Random -InputObject @($uchars, $lchars, $nchars, $schars))
    }

    $password = $password | Get-Random -Count $password.Length
    $password = -join $password
    $password
}

function New-User {
    param (
        [Parameter]
        [xml]
        $Message
    )
    $user = $Message.MessageText | ConvertFrom-Json
    $pass = New-StrongRandomPassword
    $managerSearchFilter = "CN=$($user.Manager),$ActiveDirectoryUsersContainer"
    Write-Information "Looking up manager at $managerSearchFilter"
    $manager = Get-ADUser -Filter { distinguishedName -eq $managerSearchFilter } -Server $ActiveDirectoryServer
    Write-Information "Creating Active Directory user $($user.Firstname) $($user.Lastname) ($($user.Email)) with password $pass"
    New-ADUser `
        -AccountPassword ($pass | ConvertTo-SecureString -AsPlainText -Force) `
        -AllowReversiblePasswordEncryption $false `
        -CannotChangePassword $false `
        -ChangePasswordAtLogon $false `
        -City $user.City `
        -Company $user.Company `
        -Country $user.Country `
        -Department $user.Department `
        -Description $user.Title `
        -DisplayName "$($user.Firstname) $($user.Lastname)" `
        -EmailAddress $user.Email `
        -Enabled $true `
        -GivenName $user.Firstname `
        -Initials "$($user.Firstname[0])$($user.Lastname[0])" `
        -Manager $manager `
        -MobilePhone $user.Mobile `
        -Name "$($user.Firstname) $($user.Lastname)" `
        -Office $user.Office `
        -OfficePhone $user.Phone `
        -Organization $user.Company `
        -PasswordNeverExpires $false `
        -PasswordNotRequired $false `
        -Path $ActiveDirectoryUsersContainer `
        -PostalCode $user.Postal `
        -SamAccountName $user.Username `
        -State $user.State `
        -StreetAddress $user.Address `
        -Surname $user.Lastname `
        -Title $user.Title `
        -UserPrincipalName $user.Email
    $similarSearchFilter = "CN=$($user.Similar),$ActiveDirectoryUsersContainer"
    Write-Information "Looking up similar user at $similarSearchFilter"
    if ($similar = Get-ADUser -Filter { distinguishedName -eq $similarSearchFilter } -Server $ActiveDirectoryServer) {
        $currentGroupMembership = @(Get-ADPrincipalGroupMembership $user.Username)
        $similarGroupMembership = $similar | Get-ADPrincipalGroupMembership
        $missingGroupMembership = Compare-Object -ReferenceObject $currentGroupMembership -DifferenceObject $similarGroupMembership | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject }
        foreach ($group in $missingGroupMembership) {
            Write-Information "Adding $($user.Firstname) $($user.Lastname) to group '$($group.Name)'"
            Add-ADGroupMember -Identity $group -Members $user.Username
        }
    }

    if (Test-Path $UsersFolderPath) {
        $path = Join-Path -Path $UsersFolderPath -ChildPath $user.Username
        Write-Information "Creating user folder at $path and setting permissions"
        New-Item -ItemType Directory -Path $path | Out-Null
        icacls.exe "$path" /setowner $user.Username /T /C | Out-Null
        icacls.exe "$path" /reset /T /C | Out-Null
    }

    Write-Information "Saving generated credentials to $ProgramDataPath"
    $pass | Set-Content -Path (Join-Path $ProgramDataPath "$($user.Username).txt")
}

if (-not ($Company) -and -not ($Setup -or $Preflight)) {
    Write-Warning "Company name must be provided using -Company or the 'COMPANY' environment variable"
    return
}

if (-not ($AzureStorageAccount) -and -not ($Setup -or $Preflight)) {
    Write-Warning "Azure storage account must be provided using -AzureStorageAccount or the 'AZSTORAGEACCOUNT' environment variable"
    return
}

if (-not ($AzureQueueName) -and -not ($Setup -or $Preflight)) {
    Write-Warning "Azure queue name must be provided using -AzureQueueName or the 'AZQUEUENAME' environment variable"
    return
}

if (-not ($AzureSasToken) -and -not ($Setup -or $Preflight)) {
    Write-Warning -Message "Azure SAS token must be provided using -AzureSasToken or the 'AZSASTOKEN' environment variable"
    return
}

if (-not ($ActiveDirectoryServer)) {
    $ActiveDirectoryServer = (Get-ADDomain).PDCEmulator
}

if (-not ($ActiveDirectoryUsersContainer)) {
    $ActiveDirectoryUsersContainer = (Get-ADDomain).UsersContainer
}

if (-not ($AzureADConnectServer)) {
    if (Get-Module -Name ADSync -ListAvailable) {
        $AzureADConnectServer = [System.Net.Dns]::GetHostByName($env:computerName).HostName
    }
}

if ($Setup) {
    if (-not (Get-RunningElevated)) {
        Write-Warning "Setup requires running in an elevated session. Try again."
        return
    }
    Write-Banner
    Write-Preflight
    Write-Output "Answer the questions below. Leave blank to keep existing setting."
    Write-Output ""
    if ($response = Read-Host "Company name [$Company]") {
        $env:COMPANY = $response
        [Environment]::SetEnvironmentVariable('COMPANY', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Azure storage account name") {
        $env:AZSTORAGEACCOUNT = $response
        [Environment]::SetEnvironmentVariable('AZSTORAGEACCOUNT', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Azure storage queue name") {
        Write-Verbose "Setting AZQUEUENAME"
        $env:AZQUEUENAME = $response
        [Environment]::SetEnvironmentVariable('AZQUEUENAME', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Azure storage shared access signature token") {
        $env:AZSASTOKEN = $response
        [Environment]::SetEnvironmentVariable('AZSASTOKEN', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Active Directory server") {
        $env:ADSERVER = $response
        [Environment]::SetEnvironmentVariable('ADSERVER', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Active Directory users container (OU)") {
        $env:ADUSERSCONTAINER = $response
        [Environment]::SetEnvironmentVariable('ADUSERSCONTAINER', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Azure AD Connect server") {
        $env:AZADCONNECTSERVER = $response
        [Environment]::SetEnvironmentVariable('AZADCONNECTSERVER', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    if ($response = Read-Host "Root of user home folders in \\server\share\folder format") {
        $env:USERSFOLDERPATH = $response
        [Environment]::SetEnvironmentVariable('USERSFOLDERPATH', $response, [System.EnvironmentVariableTarget]::Machine)
    }
    New-ProgramDataFolder
    return
}

if ($Preflight) {
    Write-Banner
    Write-Preflight
    return
}

$xml = Receive-AzureStorageQueueMessage

if ($peekedmessages = @($xml.QueueMessagesList.QueueMessage)) {
    
    Write-Information "Found $($peekedmessages.Count) message(s) in the queue"

    foreach ($peekedmessage in $peekedmessages) {
    
        $user = $peekedmessage.MessageText | ConvertFrom-Json

        if ($user.Company -eq $Company) {

            Write-Information "Message with id '$($peekedmessage.MessageId)' is intended for us; handling it"

            #
            # here we actually get the message out of the queue so that we are able to
            # later remove the message from the queue with a receipt; peeking the message
            # does not give us a receipt that we can use to remvoe the message so this
            # step is necessary
            #
            $xml = Get-AzureStorageQueueMessage

            foreach ($message in @($xml.QueueMessagesList.QueueMessage)) {

                New-User -Message $message

                $id = $message.MessageId
                $receipt = $message.PopReceipt
                Write-Information "Removing message '$id' from '$AzureQueueName' using receipt '$receipt'"
                Remove-AzureStorageQueueMessage -MessageId $id -Receipt $receipt | Out-Null
            }

            if ($AzureADConnectServer) {
                Write-Information "Initiating sync cycle for Azure AD Connect on $AzureADConnectServer"
                $command = Invoke-Command -ComputerName $AzureADConnectServer -ScriptBlock { Start-ADSyncSyncCycle }
                Write-Host "Synchronization result: $($command.Result)"
            }
        } else {
            Write-Information "Peeked message with id '$($peekedmessage.MessageId)' was not intended for us; skipping"
        }
    }
}
else {
    Write-Information "No messages found in queue; nothing to do; exiting"
}
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
    [int]
    $MinimumPasswordLength = 14,
    [Parameter()]
    [switch]
    $Preflight = $false
)

function Write-Banner {
    Write-Host ''
    Write-Host '    |\__/,|   (`\ '
    Write-Host '  _.|o o  |_   ) )'
    Write-Host '-(((---(((------- '  
    Write-Host ''    
}

function Get-StrongRandomPassword {

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

if (-not ($AzureStorageAccount)) {
    Write-Warning "Azure storage account must be provided using -AzureStorageAccount or the 'AZSTORAGEACCOUNT' environment variable"
    return
}

if (-not ($AzureQueueName)) {
    Write-Warning "Azure queue name must be provided using -AzureQueueName or the 'AZQUEUENAME' environment variable"
    return
}

if (-not ($AzureSasToken)) {
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

if ($Preflight) {
    Write-Banner
    Write-Output "Azure storage account name.......... : $AzureStorageAccount"
    Write-Output "Azure storage queue name............ : $AzureQueueName"
    Write-Output "Azure storage shared access token... : $(-join $AzureSasToken[0..40])..."
    Write-Output "Active directory server............. : $ActiveDirectoryServer"
    Write-Output "Active directory users container.... : $ActiveDirectoryUsersContainer"
    Write-Output "Azure AD Connect server............. : $AzureADConnectServer"
    Write-Output "Users folder path................... : $UsersFolderPath"
    return
}

$queueuri = "https://$AzureStorageAccount.queue.core.windows.net/$AzureQueueName/messages"
$headers = @{
    "x-ms-date"    = (Get-Date).ToUniversalTime().ToString("R")
    "x-ms-version" = $AzureApiVersion
}

try {
    
    $response = Invoke-RestMethod -Uri "$queueuri$AzureSasToken" -Headers $headers -Method Get -UseBasicParsing
    
    #
    # The following code is to deal specifically with the fact that the XML returned from the Azure
    # REST API related to storage queues includes a BOM that throws off PowerShell XML decoding.
    # Apparently this will be fixed in PowerShell 7.4 but we're targeting 5.1 so we have to take
    # extra measures to remove the BOM before parsing the response into an XML object.
    # 
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($response)
    $bytes = $bytes[6..($bytes.Length - 1)]
    $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
    $xml = [xml] $decoded

    if ($messages = @($xml.QueueMessagesList.QueueMessage)) {
        Write-Output "Found $($messages.Count) user add message(s) in the queue"
    }
    else {
        Write-Output "No messages found in queue; nothing to do; exiting"
        return
    }

    foreach ($message in $messages) {
        
        $user = $message.MessageText | ConvertFrom-Json
        $pass = Get-StrongRandomPassword
        $managerSearchFilter = "CN=$($user.Manager),$ActiveDirectoryUsersContainer"
        Write-Output "Looking up manager at $managerSearchFilter"
        $manager = Get-ADUser -Filter { distinguishedName -eq $managerSearchFilter } -Server $ActiveDirectoryServer
        Write-Output "Creating Active Directory user $($user.Firstname) $($user.Lastname) ($($user.Email)) with password $pass"
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
        Write-Output "Looking up similar user at $similarSearchFilter"
        if ($similar = Get-ADUser -Filter { distinguishedName -eq $similarSearchFilter } -Server $ActiveDirectoryServer) {
            $currentGroupMembership = @(Get-ADPrincipalGroupMembership $user.Username)
            $similarGroupMembership = $similar | Get-ADPrincipalGroupMembership
            $missingGroupMembership = Compare-Object -ReferenceObject $currentGroupMembership -DifferenceObject $similarGroupMembership | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject }
            foreach ($group in $missingGroupMembership) {
                Write-Output "Adding $($user.Firstname) $($user.Lastname) to group '$($group.Name)'"
                Add-ADGroupMember -Identity $group -Members $user.Username
            }
        }

        if (Test-Path $UsersFolderPath) {
            $path = Join-Path -Path $UsersFolderPath -ChildPath $user.Username
            Write-Host "Creating user folder at $path and setting permissions"
            New-Item -ItemType Directory -Path $path | Out-Null
            icacls.exe "$path" /setowner $user.Username /T /C
            icacls.exe "$path" /reset /T /C
        }    
        
        Write-Output "Removing message $($message.MessageId) from $AzureQueueName using receipt $($message.PopReceipt)"
        Invoke-RestMethod -Uri "$queueuri/$($message.MessageId)$AzureSasToken&popreceipt=$($message.PopReceipt)" -Headers $headers -Method Delete -UseBasicParsing | Out-Null
    }

    if ($AzureADConnectServer) {
        Write-Output "Initiating sync cycle for Azure AD Connect on $AzureADConnectServer"
        $command = Invoke-Command -ComputerName $AzureADConnectServer -ScriptBlock { Start-ADSyncSyncCycle }
        Write-Host "Synchronization result: $($command.Result)"
    }

    Write-Output "Finished"
}
catch {
    Write-Warning "Error occured, please investigate: $_"
}
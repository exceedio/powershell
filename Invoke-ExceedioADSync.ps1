#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $AzureApiVersion = '2022-11-02',
    [Parameter()]
    [int]
    $MinimumPasswordLength = 14
)

function Write-Banner {
    Write-Host ''
    Write-Host '    |\__/,|   (`\ '
    Write-Host '  _.|o o  |_   ) )'
    Write-Host '-(((---(((------- '  
    Write-Host ''    
}

function New-UserFolder {
    if (-not (Test-Path $path)) {
        Write-Host "Creating user folder at $path and setting permissions"
        New-Item -ItemType Directory -Path $path | Out-Null
        icacls.exe "$path" /setowner $this.Username /T /C
        icacls.exe "$path" /reset /T /C
    }
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

if (-not ($azstorageaccount = $env:AZSTORAGEACCOUNT)) {
    Write-Warning -Message "Missing environment variable AZSTORAGEACCOUNT"
    return
}

if (-not ($azqueuename = $env:AZQUEUENAME)) {
    Write-Warning -Message "Missing environment variable AZQUEUENAME"
    return
}

if (-not ($azsastoken = $env:AZSASTOKEN)) {
    Write-Warning -Message "Missing environment variable AZSASTOKEN"
    return
}

if (-not ($adserver = $env:ADSERVER)) {
    Write-Warning -Message "Missing environment variable ADSERVER"
    return
}

if (-not ($adusersoupath = $env:ADUSERSOUPATH)) {
    Write-Warning -Message "Missing environment variable ADUSERSOUPATH"
    return
}

if (-not ($azadsyncserver = $env:AZADSYNCSERVER)) {
    Write-Warning -Message "Missing environment variable AZADSYNCSERVER; sync cycle will not be forced"
}

$queueuri = "https://$azstorageaccount.queue.core.windows.net/$azqueuename/messages"
$headers = @{
    "x-ms-date"    = (Get-Date).ToUniversalTime().ToString("R")
    "x-ms-version" = $AzureApiVersion
}

try {
    
    $response = Invoke-RestMethod -Uri "$queueuri$azsastoken" -Headers $headers -Method Get -UseBasicParsing
    
    #
    # The following code is to deal specifically with the fact that the XML returned
    # from the Azure REST API related to storage queues includes a BOM that throws off
    # PowerShell XML decoding. Apparently this will be fixed in PowerShell 7.4 but we're
    # targeting 5.1 here so we have to take extra measures to remove the BOM before
    # parsing the response into an XML object
    # 
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($response)
    $bytes = $bytes[6..($bytes.Length - 1)]
    $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
    $xml = [xml] $decoded

    if ($messages = @($xml.QueueMessagesList.QueueMessage)) {
        Write-Output "Found $($messages.Count) user add message(s) in the queue"
    }
    else {
        Write-Output "No user add messages found in the queue"
        return
    }

    foreach ($message in $messages) {
        
        $user = $message.MessageText | ConvertFrom-Json
        $pass = Get-StrongRandomPassword
        $managerSearchFilter = "CN=$($user.Manager),$($adusersoupath)"
        Write-Output "Looking up manager at $managerSearchFilter"
        $manager = Get-ADUser -Filter { distinguishedName -eq $managerSearchFilter } -Server $adserver
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
            -OfficePhone $user.Phone `
            -Organization $user.Company `
            -PasswordNeverExpires $false `
            -PasswordNotRequired $false `
            -Path $adusersoupath `
            -PostalCode $user.Postal `
            -SamAccountName $user.Username `
            -State $user.State `
            -StreetAddress $user.Address `
            -Surname $user.Lastname `
            -Title $user.Title `
            -UserPrincipalName $user.Email
        $similarSearchFilter = "CN=$($user.Similar),$($adusersoupath)"
        Write-Output "Looking up similar user at $similarSearchFilter"
        if ($similar = Get-ADUser -Filter { distinguishedName -eq $similarSearchFilter } -Server $adserver) {
            $currentGroupMembership = @(Get-ADPrincipalGroupMembership $user.Username)
            $similarGroupMembership = $similar | Get-ADPrincipalGroupMembership
            $missingGroupMembership = Compare-Object -ReferenceObject $currentGroupMembership -DifferenceObject $similarGroupMembership | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject }
            foreach ($group in $missingGroupMembership) {
                Write-Output "Adding $($user.Firstname) $($user.Lastname) to group '$($group.Name)'"
                Add-ADGroupMember -Identity $group -Members $user.Username
            }
        }
        
        Write-Output "Removing message $($message.MessageId) from $azqueuename using receipt $($message.PopReceipt)"
        Invoke-RestMethod -Uri "$queueuri/$($message.MessageId)$azsastoken&popreceipt=$($message.PopReceipt)" -Headers $headers -Method Delete -UseBasicParsing | Out-Null
    }

    if ($azadsyncserver) {
        Write-Output "Initiating sync cycle for Azure AD Connect on $azadsyncserver"
        $command = Invoke-Command -ComputerName $azadsyncserver -ScriptBlock { Start-ADSyncSyncCycle }
        Write-Host "Synchronization result: $($command.Result)"
    }

    Write-Output "Finished"
}
catch {
    Write-Warning "Error occured, please investigate: $_"
}
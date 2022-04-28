#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Mail

<#
.SYNOPSIS
    Generates a report of DMARC activity with pass/fail information
.DESCRIPTION
    Extracts XML files from an Exchange Online mailbox that contains DMARC aggregate
    reports, parses those files, and displays a table containing information about
    the aggregate report items that can be used to further investigate potential
    DMARC failures.

    See https://datatracker.ietf.org/doc/html/rfc7489 for general details on DMARC
    including the XML report format which is located in appendix C.
.PARAMETER TenantId
    Your Azure Active Directory Tenant ID that can be obtained from the Overview blade
    of the Azure Active Directory portal.
.PARAMETER ApplicationId
    The Application (client) ID of your app registration that is registrered in your
    Azure Active Directory instance. The app requires at least User.Read and
    Mail.Read.Shared delegated permissions for Microsoft Graph.
.PARAMETER AggregateReportMailbox
    The email address of the mailbox that receives DMARC aggregate reports.
.PARAMETER Scopes
    The Graph API permissions required for this script. You shouldn't need to use this.
.PARAMETER TemporaryZipPath
    The path in which email message attachments will be stored for processing. Content
    in this path will be deleted on every run so don't change this unless you know what
    you are doing.
.PARAMETER TemporaryXmlPath
    The path in which extracted XML documents will be stored for processing. Content
    in this path will be deleted on every run so don't change this unless you know what
    you are doing.
.PARAMETER StayConnectedToGraphAPIWhenFinished
    Causes the script to skip the Disconnect-MgGraph call at the end of its run so that
    you remain authenticated to the Graph API. Useful for running the script multiple times
    in a session without having to re-authenticate every time. Normally you won't need to
    use this.
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/Get-ExceedioDMARCReport.ps1'))
.EXAMPLE
    .\Get-ExceedioDMARCReport.ps1
.EXAMPLE
    .\Get-ExceedioDMARCReport.ps1 -TenantId 430b6c3f-3d7b-45cb-8bc1-f745acf4df74 -ApplicationId b133e7d1-8a79-49a0-a001-fdf82aee3081 -AggregateReportMailbox dmarcrua@contoso.com
.EXAMPLE
    .\Get-ExceedioDMARCReport.ps1 -StayConnectedToGraphAPIWhenFinished
.NOTES
    Filename : Get-ExceedioDMARCReport.ps1
    Author   : jreese@exceedio.com
    Modified : Apr 28, 2022
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage='Enter your Azure AD Tenent ID from Overview blade in portal')]
    [ValidateNotNullOrEmpty()]
    [String]
    $TenantId,
    [Parameter(Mandatory = $true, HelpMessage='Enter application (client) ID of Azure AD registered app')]
    [ValidateNotNullOrEmpty()]
    [String]
    $ApplicationId,
    [Parameter(Mandatory = $true, HelpMessage='Enter email address that receives DMARC reports (e.g. dmarcrua@contoso.com)')]
    [ValidateNotNullOrEmpty()]
    [String]
    $AggregateReportMailbox,
    [Parameter(Mandatory = $false)]
    [String[]]
    $Scopes = @('User.Read', 'Mail.Read.Shared'),
    [Parameter(Mandatory = $false)]
    [String]
    $TemporaryZipPath = "$env:temp\dmarc\zip",
    [Parameter(Mandatory = $false)]
    [String]
    $TemporaryXmlPath = "$env:temp\dmarc\xml",
    [Parameter(Mandatory = $false)]
    [Switch]
    $StayConnectedToGraphAPIWhenFinished = $false
)

function Expand-GZip {
    param (
        [String]
        $Path,
        [String]
        $DestinationPath
    )
    $src = New-Object System.IO.FileStream $Path, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $dst = New-Object System.IO.FileStream $DestinationPath, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $stm = New-Object System.IO.Compression.GzipStream $src, ([IO.Compression.CompressionMode]::Decompress)
    $stm.CopyTo($dst)
    $stm.Close()
    $dst.Close()
    $src.Close()
}

function Create-TemporaryPathsIfNeeded {
    if (-not (Test-Path $TemporaryZipPath)) {
        New-Item -Path $TemporaryZipPath -ItemType Directory -Force | Out-Null
    }
    if (-not (Test-Path $TemporaryXmlPath)) {
        New-Item -Path $TemporaryXmlPath -ItemType Directory -Force | Out-Null
    }    
    Remove-Item -Path $TemporaryZipPath\*
    Remove-Item -Path $TemporaryXmlPath\*
}

function Get-AttachmentsFromMailbox {
    Write-Host "[*] Opening $AggregateReportMailbox mailbox"
    $inbox = Get-MgUserMailFolder -UserId $AggregateReportMailbox | Where-Object { $_.DisplayName -eq 'Inbox' }
    Write-Host "[*] Retrieving messages from $AggregateReportMailbox"
    $messages = @(Get-MgUserMailFolderMessage -UserId $AggregateReportMailbox -MailFolderId $inbox.Id -All)
    $count = $messages.Count
    $current = 0
    Write-Host "[*] Compressed attachments will be saved to $TemporaryZipPath"
    foreach ($message in $messages) {
        $current++
        $attachment = Get-MgUserMessageAttachment -UserId $AggregateReportMailbox -MessageId $message.Id
        $base64Encoded = ($attachment | Select-Object -ExpandProperty AdditionalProperties).contentBytes
        $bytes = [System.Convert]::FromBase64String($base64Encoded)
        $filename = $attachment.Name
        $zipfile = Join-Path $TemporaryZipPath $filename
        Write-Host "[*] Saving attachment from message $current of $count ($filename)"
        Set-Content $zipfile -Value $bytes -Encoding Byte
    }    
}

function Extract-XmlReportsFromAttachments {
    $zipfiles = @(Get-ChildItem -Path $TemporaryZipPath -File)
    $count = $zipfiles.Count
    $current = 0
    Write-Host "[*] Decompressed XML files will be saved to $TemporaryXmlPath"
    foreach ($zipfile in $zipfiles) {
        $current++
        Write-Host "[*] Extracting XML report from compressed attachment $current of $count ($($zipfile.Name))"
        switch ($zipfile.Extension) {
            ".zip" {
                Expand-Archive -Path $zipfile.Fullname -DestinationPath $TemporaryXmlPath
                break
            }
            ".gz" {
                Expand-GZip -Path $zipfile.Fullname -DestinationPath $(Join-Path $TemporaryXmlPath $zipfile.Name.Replace('.gz',''))
                break
            }
            default { Write-Host "[!] Unsupported file extension" -ForegroundColor Yellow }
        }
    }
}

function Get-XmlReportResults {
    $xmlfiles = @(Get-ChildItem -Path $TemporaryXmlPath -File)
    $count = $xmlfiles.Count
    $current = 0
    $results = @()
    foreach ($xmlfile in $xmlfiles) {
        $current++
        Write-Host "[*] Reading data from XML file $current of $count ($($xmlfile.Name))"
        $xml = [xml] (Get-Content -Path $xmlfile.Fullname)
        $provider = $xml.feedback.report_metadata.org_name
        $domain = $xml.feedback.policy_published.domain
        foreach ($record in $xml.feedback.record) {
            $results += New-Object PSObject -Property @{
                Provider = $provider
                Domain = $domain
                Header = $record.identifiers.header_from
                SourceIP = $record.row.source_ip
                Count = $record.row.count
                Disposition = $record.row.policy_evaluated.disposition
                DKIMDomain = $record.auth_results.dkim.domain
                SPFDomain = $record.auth_results.spf.domain
                DKIM = $record.row.policy_evaluated.dkim
                SPF = $record.row.policy_evaluated.spf
            }
        }
    }
    return $results    
}

#
# connect to Graph API if we're not already connected
#

if ($null -eq (Get-MgContext)) {
    Write-Host "[*] Connecting to Graph API"
    Connect-MgGraph -TenantId $TenantId -ClientId $ApplicationId -Scopes $Scopes | Out-Null
}

#
# call our functions in the correct sequence
#

Create-TemporaryPathsIfNeeded
Get-AttachmentsFromMailbox
Extract-XmlReportsFromAttachments
Get-XmlReportResults | Format-Table Provider,Domain,SourceIP,Count,Header,Disposition,DKIMDomain,SPFDomain,DKIM,SPF

#
# disconnect from Graph API
#

if (-not $StayConnectedToGraphAPIWhenFinished) {
    Write-Host "[*] Disconnecting from Graph API"
    Disconnect-MgGraph
}

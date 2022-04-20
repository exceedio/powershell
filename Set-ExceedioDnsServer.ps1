<#
.SYNOPSIS
    Configures a Windows Server 2016 or later DNS server to specification
.DESCRIPTION
    Sets forwarding, logging, and root hint settings. You can run as-is with no parameters
    using the example 
.EXAMPLE
    iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/Set-ExceedioDnsServer.ps1'))
.NOTES
    Filename : Set-ExceedioDnsServer.ps1
    Author   : jreese@exceedio.com
    Modified : Apr 19, 2022
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String[]]
    $ForwarderAddresses = @('8.8.8.8','8.8.4.4')
)

Set-DnsServerForwarder -IPAddress $ForwarderAddresses -EnableReordering $false -UseRootHint $true

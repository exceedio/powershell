#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Finds, lists, and optionally deletes GPOs with Windows Update settings
.DESCRIPTION
    Intended to be run when converting a domain from GPO-based Windows Update
    settings to one based on your RMM tool of choice. We're looking for any
    settings related to Windows Update in group policy.

    If you receive an error The request was aborted: Could not create SSL/TLS
    secure channel when calling this then you must run the following first
    when calling this using the example below then you must run the following
    and then try your call again:

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    This script is best run from a domain controller.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Find-ExceedioGPOForWindowsUpdate.ps1 | iex
.NOTES
    Filename: Find-ExceedioGPOForWindowsUpdate.ps1
    Author:   jreese@exceedio.com
    Modified: Sep 26, 2024
#>

# Import the GroupPolicy module
Import-Module GroupPolicy

# Initialize an array to hold the results
$Results = @()

# Get all GPOs in the domain
$AllGPOs = Get-GPO -All

foreach ($GPO in $AllGPOs | Sort-Object DisplayName)
{
    Write-Host "Processing GPO: $($GPO.DisplayName)"
    
    # Generate a report in XML format for each GPO
    $GPOReport = Get-GPOReport -Guid $GPO.Id -ReportType XML
    
    # Load the XML content
    $Xml = [xml]$GPOReport
    
    $FoundWindowsUpdate = $false
    
    # Search for Windows Update settings in Computer Configuration
    if ($Xml.GPO.Computer.ExtensionData.Extension)
    {
        foreach ($Extension in $Xml.GPO.Computer.ExtensionData.Extension)
        {
            if ($Extension.Policy)
            {
                foreach ($Policy in $Extension.Policy)
                {
                    if ($Policy.Category -like '*Windows Update*')
                    {
                        $FoundWindowsUpdate = $true
                        break
                    }
                }
            }
            if ($FoundWindowsUpdate)
            { break 
            }
        }
    }

    # If not found, search User Configuration
    if (-not $FoundWindowsUpdate -and $Xml.GPO.User.ExtensionData.Extension)
    {
        foreach ($Extension in $Xml.GPO.User.ExtensionData.Extension)
        {
            if ($Extension.Policy)
            {
                foreach ($Policy in $Extension.Policy)
                {
                    if ($Policy.Category -like '*Windows Update*')
                    {
                        $FoundWindowsUpdate = $true
                        break
                    }
                }
            }
            if ($FoundWindowsUpdate)
            { break 
            }
        }
    }

    if ($FoundWindowsUpdate)
    {
        $LinkLocations = @()
        foreach ($link in (Get-ADOrganizationalUnit -Filter * | Get-GPInheritance).GpoLinks)
        {
            if ($link.DisplayName -eq $GPO.DisplayName)
            {
                $LinkLocations += $link.Target
            }
        }

        # Add the result to the array
        $Results += [PSCustomObject]@{
            'Name' = $GPO.DisplayName
            'ID'   = $GPO.Id
            'Links'    = ($LinkLocations -join '; ')
        }
    }
}

# Display the results in a table
$Results | Format-Table -AutoSize

foreach ($gpo in $Results)
{
    if (-not ($gpo.Links))
    {
        if ((Read-Host "$($gpo.Name) has no links; do you want to delete it? [y/n]") -eq 'y')
        {
            $gpo | Remove-GPO
        }
    }
}

Write-Host "Finished"

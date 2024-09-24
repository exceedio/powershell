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
            'GPO Name' = $GPO.DisplayName
            'GPO ID'   = $GPO.Id
            'Links'    = ($LinkLocations -join '; ')
        }
    }
}

# Display the results in a table
$Results | Format-Table -AutoSize

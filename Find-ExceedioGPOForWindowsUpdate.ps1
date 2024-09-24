# Import the GroupPolicy module
Import-Module GroupPolicy

# Initialize an array to hold the results
$Results = @()

# Get all GPOs in the domain
$AllGPOs = Get-GPO -All

foreach ($GPO in $AllGPOs)
{
    Write-Host "Processing GPO: $($GPO.DisplayName)"
    
    # Generate a report in XML format for each GPO
    $GPOReport = Get-GPOReport -Guid $GPO.Id -ReportType XML
    
    # Load the XML content
    $Xml = [xml]$GPOReport
    
    $FoundWindowsUpdate = $false
    
    # Search for Windows Update settings in Computer Configuration
    $ComputerExtensions = $Xml.GPO.Computer.ExtensionData.Extension
    if ($ComputerExtensions)
    {
        foreach ($Extension in $ComputerExtensions)
        {
            if ($Extension.Name -eq 'Administrative Templates')
            {
                foreach ($Policy in $Extension.Policy)
                {
                    if ($Policy.Parent -like '*Windows Update*')
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
    if (-not $FoundWindowsUpdate)
    {
        $UserExtensions = $Xml.GPO.User.ExtensionData.Extension
        if ($UserExtensions)
        {
            foreach ($Extension in $UserExtensions)
            {
                if ($Extension.Name -eq 'Administrative Templates')
                {
                    foreach ($Policy in $Extension.Policy)
                    {
                        if ($Policy.Parent -like '*Windows Update*')
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
    }

    if ($FoundWindowsUpdate)
    {
        # Get the links where the GPO is applied
        $Links = Get-GPOLink -Guid $GPO.Id

        # Build a list of linked locations
        $LinkLocations = if ($Links)
        {
            $Links | Select-Object -ExpandProperty Target
        } else
        {
            'Not linked'
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

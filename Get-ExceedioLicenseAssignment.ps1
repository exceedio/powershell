#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Users

<#
.SYNOPSIS
    Gets per-user license assignment information for a tenant.
.DESCRIPTION
    Use this script to determine which licenses are assigned to which users and the method used for the
    license assignment (direct vs. group-based). You can also use the results to determine if you have
    disabled users that are assigned licenses as well as users that may be in a licensing error state
    due to the lack of available licenses.
.NOTES
    This script relies on a CSV file that is provided by Microsoft at the path given by the ProductNameUri
    parameter. The parameter defaults to the correct Url as of September of 2023 but it's possible that the
    Url could change in the future. The Url was documented at the page below:

    https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
.LINK
    https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-powershell-graph-examples
.PARAMETER TenantId
    The unique id of the tenant for which licensing assignment information should be gathered
.PARAMETER ProductNameUri
    The Uri to the CSV file that Microsoft provides for mapping Office product SKUs to friendly names. See
    the NOTES section for for information. Defaults to the correct known URL as of the last update to this
    script.
.PARAMETER DisconnectWhenFinished
    Switch indicating whether we should sign out of Microsoft Graph when this script is finished running.
    You may want to exclude this switch if you are running the script multiple times or if you are running
    multiple scripts that utilize Microsoft Graph and want to avoid re-authenticating between scripts.
.EXAMPLE
    Get-ExceedioLicenseAssignment.ps1 -TenantId <guid>
.EXAMPLE
    Get-ExceedioLicenseAssignment.ps1 -TenantId <guid> | Export-Csv 'assignments.csv' -NoTypeInformation
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $TenantId,
    [Parameter()]
    [string]
    $ProductNameUri = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv',
    [Parameter()]
    [switch]
    $DisconnectWhenFinished = $false
)

if (-not (Get-MGContext).TenantId -eq $TenantId) {
    Connect-MgGraph -Scopes "User.Read.All" -TenantId $TenantId
}

$users = @(Get-MgUser -All -Property AccountEnabled, AssignedLicenses, LicenseAssignmentStates, DisplayName | Select-Object DisplayName, AccountEnabled, AssignedLicenses -ExpandProperty LicenseAssignmentStates | Select-Object DisplayName, AccountEnabled, AssignedByGroup, State, Error, SkuId)
$skuIdToName = Invoke-RestMethod -Uri $ProductNameUri -Method Get | ConvertFrom-Csv
$output = @()
$progress = 0

foreach ($user in $users) {
    Write-Progress -Activity "Gathering license info" -Status $user.DisplayName -PercentComplete (($progress++ / $users.Count) * 100)
    $skuName = $skuIdToName | Where-Object GUID -eq $user.SkuId | Select-Object -ExpandProperty Product_Display_Name | Get-Unique
    if ($null -ne $user.AssignedByGroup) {
        $groupId = $user.AssignedByGroup
        $groupName = Get-MgGroup -GroupId $groupId | Select-Object -ExpandProperty DisplayName
        $result = [pscustomobject]@{
            User            = $user.DisplayName
            Enabled         = $user.AccountEnabled
            Sku             = $skuName
            SkuId           = $user.SkuId
            State           = $user.State
            Error           = $user.Error
            AssignedByGroup = $true
            GroupName       = $groupName
            GroupId         = $groupId
        }
        $output += $result
    }
    else {
        $result = [pscustomobject]@{
            User            = $user.DisplayName
            Enabled         = $user.AccountEnabled
            Sku             = $skuName
            SkuId           = $user.SkuId
            State           = $user.State
            Error           = $user.Error
            AssignedByGroup = $false
            GroupName       = "NA"
            GroupId         = "NA"
        }
        $output += $result
    }
}

if ($DisconnectWhenFinished) {
    Disconnect-MgGraph | Out-Null
}

$output
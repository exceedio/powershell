[CmdletBinding()]
param()

try
{
    Import-Module -Name DellBIOSProvider
} catch
{
    Find-Module -Name DellBIOSProvider | Install-Module -Scope AllUsers -AllowClobber -Force
    Import-Module -Name DellBIOSProvider
}

function Set-DellSmbiosValue
{
    param (
        $Path,
        $DesiredValue
    )

    if ($value = (Get-Item -Path $Path -ErrorAction SilentlyContinue).CurrentValue)
    {
        if ($value -ne $DesiredValue)
        {
            Set-Item -Path $Path -Value $DesiredValue -Force
            Write-Host "Set $Path to $DesiredValue" -ForegroundColor Yellow
        } else
        {
            Write-Host "$Path is already set to $DesiredValue"
        }
    }
}

function Set-NetAdapterAdvancedPropertyIfExists
{
    param (
        $NetAdapter,
        $Property,
        $DesiredValue = 'Disabled'
    )
    if ($current = ($NetAdapter | Get-NetAdapterAdvancedProperty -DisplayName $Property -ErrorAction SilentlyContinue).DisplayValue)
    {
        if ($current -ne $DesiredValue)
        {
            $NetAdapter | Set-NetAdapterAdvancedProperty -DisplayName $Property -DisplayValue $DesiredValue
            Write-Host "Set net adapter advanced property $Property to $DesiredValue" -ForegroundColor Yellow
        } else
        {
            Write-Host "Net adapter advanced property $Property is already set to $DesiredValue"
        }
    }
}

Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AcPwrRcvry" -DesiredValue 'On'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOn" -DesiredValue 'Everyday'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnHr" -DesiredValue '0'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\AutoOnMn" -DesiredValue '5'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\DeepSleepCtrl" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\BlockSleep" -DesiredValue 'Disabled'
Set-DellSmbiosValue -Path "DellSmbios:\PowerManagement\WakeOnLan" -DesiredValue 'LanOnly'

if ($nic = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.PhysicalMediaType -eq '802.3'})
{
    Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy-Efficient Ethernet'
    Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Energy Efficient Ethernet'
    Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Green Ethernet'
    Set-NetAdapterAdvancedPropertyIfExists -NetAdapter $nic -Property 'Wake on Magic Packet' -DesiredValue 'Enabled'
}

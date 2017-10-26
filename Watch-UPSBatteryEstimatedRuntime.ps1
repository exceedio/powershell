<#
.SYNOPSIS
    Watches estimated runtime on a battery and shuts down at a configured threshold.
.DESCRIPTION
    Use schtasks.exe to schedule this to run on startup. The script will run indefinitely
    or until the system is shutdown. The script uses WMI to obtain battery status from
    Win32_Battery and shuts down the machine if it detects that the system is on battery
    and the estimated runtime is less than the configured value.
.PARAMETER MinimumRuntimeInMinutes
    The minimum estimated runtime in minutes that the script will allow before shutting
    down the system. This value should be large enough to allow for shutting down of all
    virtual machines if running on a hypervisor. Defaults to 20 minutes.
.PARAMETER SleepTimeInSeconds
    The time that the script will sleep between iterations. Defaults to 60 seconds.
.PARAMETER DischargingState
    The Win32_Battery.BatteryStatus value to look for to indicate that the battery is
    discharging (lost AC power). Defaults to 1. See documentation on Win32_Battery
    for details.
.PARAMETER ShuttingDown
    Should always be False when calling the script. Do not change.
.EXAMPLE
    iwr https://raw.githubusercontent.com/exceedio/powershell/master/Watch-UPSBatteryEstimatedRuntime.ps1 -UseBasicParsing | iex
#>

param (
    [parameter(Mandatory=$false)]
    [int] $MinimumRuntimeInMinutes = 20,

    [parameter(Mandatory=$false)]
    [int] $SleepTimeInSeconds = 60,

    [parameter(Mandatory=$false)]
    [int] $DischargingState = 1,

    [parameter(Mandatory=$false)]
    [bool] $ShuttingDown = $false
)

function Find-BatteryAndExitIfNotFound
{
    if ((Get-WmiObject Win32_Battery) -eq $null)
    {
        Write-Warning "This computer does not have a battery; exiting"
        exit 1
    }
    else
    {
        Write-Output "Watching battery $((Get-WmiObject Win32_Battery).Name) every $sleepseconds seconds"
    }
}

function Check-BatteryStatus
{
    $battery = Get-WmiObject Win32_Battery
    $charge  = $battery.EstimatedChargeRemaining
    $runtime = $battery.EstimatedRunTime

    if ($battery.BatteryStatus -eq $DischargingState)
    {
        Write-Output "Battery is discharging; $charge% charge ($runtime minute(s) remaining)"

        if ($battery.EstimatedRunTime -le $MinimumRuntimeInMinutes)
        {
            Write-Warning "Server has less than $MinimumRuntimeInMinutes minute(s)"

            if (-not ($ShuttingDown))
            {
                Write-Warning "Shutting down"
                $ShuttingDown = $true
                Stop-Computer
            }
        }
    }
    else
    {
        Write-Output "System has access to AC; $charge% charge ($runtime minute(s) remaining)"
    }   
}

Find-BatteryAndExitIfNotFound

while ($true)
{
    Check-BatteryStatus
    Start-Sleep -Seconds $SleepTimeInSeconds
}

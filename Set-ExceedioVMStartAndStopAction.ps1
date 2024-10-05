#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures start and stop actions for all virtual machines on a server
.DESCRIPTION
    This script is intended to be run on a Hyper-V server. It will assess
    the virtual machines for the appropriate automatic start and stop
    actions based on the role of the virtual machine (domain controller or
    not domain controller). Role determiniation is made by interrogating
    port UDP/53.
.EXAMPLE
    irm https://raw.githubusercontent.com/exceedio/powershell/refs/heads/master/Set-ExceedioVMStartAndStopAction.ps1
.NOTES
    Filename : Set-ExceedioVMStartAndStopAction.ps1
    Author   : jreese@exceedio.com
    Modified : Oct 5, 2024
#>

[CmdletBinding()]
param (
)

Write-Host "[*] Obtaining list of virtual machines"
$vms = @(Get-VM | Where-Object {$_.State -eq 'Running'})

Write-Host "[*] Found $($vms.Count) virtual machine(s)"
foreach ($vm in $vms)
{
    Write-Host "[*] Assessing virtual machine $($vm.Name)"
    Write-Host "[*] Current automatic stop action for $($vm.Name) is $($vm.AutomaticStopAction)"
    Write-Host "[*] Current automatic start action for $($vm.Name) is $($vm.AutomaticStartAction)"
    Write-Host "[*] Current automatic start delay for $($vm.Name) is $($vm.AutomaticStartDelay)"
    
    $netadapters = $vm | Get-VMNetworkAdapter

    if ($netadapters.IPAddresses -and $netadapters.IPAddresses.Count -gt 0)
    {
        $addresses = $netadapters.IPAddresses
        $isDomainController = $false
        foreach ($ip in $addresses)
        {
            try {
                Write-Host "[*] Sending DNS request to $($vm.Name) at $ip"
                $response = Resolve-DnsName -Name 'localhost' -Server $ip -ErrorAction Stop
                if ($response)
                {
                    $isDomainController = $true
                    break
                }
            }
            catch {
                Write-Host "[*] VM at $ip did not respond to DNS request"
            }
        }
        if ($isDomainController)
        {
            $vm | Set-VM -AutomaticStopAction Shutdown -AutomaticStartDelay 0
            Write-Host "[+] Configured DC $($vm.Name) to shutdown on stop and start with no delay"
        }
        else
        {
            $delayInSeconds = Get-Random -Minimum 300 -Maximum 600
            $vm | Set-VM -AutomaticStopAction Save -AutomaticStartDelay $delayInSeconds
            Write-Host "[+] Configured non-DC $($vm.Name) to save on stop and start with delay of $delayInSeconds seconds"
        }
    }
    else
    {
        Write-Host "[!] No IP addresses found for VM $($vm.Name); skipping"
    }
}


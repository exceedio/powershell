# Desired State Configuration (DSC)

## Overview

This folder contains resources that can utilize Desired State Configuration (DSC)
to ensure that a machine is in a desired state.

## When to use

- Provisioning a new Dell Hypervisor with Windows Server 2022 Standard

## How to use

1. Log on as local Administrator
2. Open an elevated PowerShell command window
3. Install the required modules (one-time)

```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Install-RequiredModules.ps1'))
```

4. Configure DSC to reboot as needed (one-time)

```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Set-LcmRebootIfNeeded.ps1'))
```

5. Run the script appropriate for your scenario

## Scenario-specific scripts

### Provisioning a new Dell Hypervisor with Windows Server 2022 Standard

```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Deploy-Hypervisor.ps1'))
```

This script does the following:

- Sets computer name
- Enables the SNMP, Hyper-V, and Hyper-V Tools features
- Disables first run experience in Edge
- Disables automatic running of Server Manager when logging on
- Disables printer mapping when using RDP (to prevent printer driver installation)
- Enables Remote Desktop and appropriate Remote Desktop firewall rules
- Configures and enables Public, Private, and Domain Windows Firewall profiles
- Stops and disables the DefragSvc Windows service
- Enables and configures the W32Time service to sync with time.google.com
- Formats the selected disk using ReFS as D: (Data) and sets as default path for Hyper-V
- Removes the Windows default Hyper-V path (C:\Users\Public\Documents\Hyper-V)
- Creates a Hyper-V external virtual switch using the specific NICs
- Installs Dell OpenManage Server Administrator (OMSA) Managed Node and secures its web server
- Configures the iDRAC address and DNS name
- Downloads installation media ISO files to C:\Users\Public\Documents\ISO

## Verifying success

Run the following and verify that `InDesiredState` is True:

```
Test-DscConfiguration -Path $env:systemdrive\dsc
```

If `InDesiredState` is False then you can run the following to view what failed:

```
Test-DscConfiguration -Path $env:systemdrive\dsc | Select-Object -ExpandProperty ResourcesNotInDesiredState
```
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

Provisioning a new Dell Hypervisor with Windows Server 2022 Standard:

```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Deploy-Hypervisor.ps1'))
```
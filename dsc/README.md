Install required modules
```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Install-RequiredModules.ps1'))
```
Configure DSC to reboot as needed
```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Set-LcmRebootIfNeeded.ps1'))
```
Configure a Windows Server 2022 Standard (Desktop Experience) Hypervisor
```
iex ((new-object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/exceedio/powershell/master/dsc/Deploy-Hypervisor.ps1'))
```
[DSCLocalConfigurationManager()]
Configuration Server2022Lcm {
    Node 'localhost' {
        Settings {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndMonitor'
            RebootNodeIfNeeded = $true
        }
    }
}

Server2022Lcm -Output "$env:systemdrive\Dsc"
Set-DscLocalConfigurationManager -Path "$env:systemdrive\Dsc" -Verbose
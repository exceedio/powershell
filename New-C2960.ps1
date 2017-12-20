$eid        = Read-Host "EID"
$address    = Read-Host "IP address (e.g. 192.168.1.10)"
$netmask    = Read-Host "IP netmask (e.g. 255.255.255.0)"
$gateway    = Read-Host "IP gateway (e.g. 192.168.1.1)"
$ports      = Read-Host "Port count (e.g. 10, 24, 52)"
$vlan_v     = Read-Host "Voice VLAN (e.g. 100 - leave blank for no voice vlan)"
$vlan_g     = Read-Host "Guest VLAN (e.g. 200 - leave blank for no guest vlan)"
$uplink     = Read-Host "Uplink port (e.g. 8)"
$uplink_eid = Read-Host "EID of device to uplink (e.g. 1234)"
$core       = Read-Host "Is this the core switch? (y/n)"
$location   = Read-Host "Location"
$secret     = Read-Host "Password secret for 'cisco' user"
$clock      = get-date -Format "HH:mm:ss dd MMM yyyy"

Write-Output ""
Write-Host   "Paste this config into your switch:" -ForegroundColor Yellow
Write-Output ""
Write-Output "enable"
Write-Output "config t"
Write-Output "hostname SW$eid"
Write-Output "ip domain-name exceedio.net"
Write-Output "crypto key generate rsa general-keys modulus 2048"
Write-Output "username cisco privilege 15 secret $secret"
Write-Output "enable secret 0 $secret"
Write-Output "line vty 0 4"
Write-Output "exec-timeout 60 0"
Write-Output "login local"
Write-Output "no password"
Write-Output "exit"
Write-Output "line vty 5 15"
Write-Output "exec-timeout 60 0"
Write-Output "login local"
Write-Output "no password"
Write-Output "exit"
Write-Output "clock summer-time PDT recurring"
Write-Output "clock timezone PST -8"
Write-Output "no enable password"
Write-Output "snmp-server community public"
Write-Output "snmp-server contact support@exceedio.com"
Write-Output "snmp-server location $location"
if ($vlan_v)
{
    Write-Output "vlan $vlan_v"
    Write-Output "name voice"
    Write-Output "exit"
}
if ($vlan_g)
{
    Write-Output "vlan $vlan_g"
    Write-Output "name guest"
    Write-Output "exit"
}
Write-Output "interface vlan 1"
Write-Output "ip address $address $netmask"
Write-Output "no shutdown"
Write-Output "exit"
Write-Output "ip default-gateway $gateway"
Write-Output "lldp run"

#
# default all ports to desktop / phone
#

Write-Output "interface range GigabitEthernet1/0/1-$ports"
Write-Output "description desktop / phone"
Write-Output "switchport mode access"
Write-Output "switchport access vlan 1"
if ($vlan_v)
{
    Write-Output "switchport voice vlan $vlan_v"
}
Write-Output "spanning-tree portfast"
Write-Output "auto qos voip cisco-phone"
Write-Output "exit"

#
# uplink port
#

Write-Output "default interface GigabitEthernet0/$uplink"
Write-Output "interface GigabitEthernet0/$uplink"
Write-Output "switchport trunk native vlan 1"
Write-Output "switchport trunk allowed vlan ALL"
Write-Output "switchport mode trunk"
Write-Output "auto qos voip trust"
Write-Output "spanning-tree link-type point-to-point"
Write-Output "description uplink to $uplink_eid"
Write-Output "exit"

#
# set as root bridge if core switch
#

if ($core)
{
    Write-Output "spanning-tree vlan 1 root primary"
    
    if ($vlan_v)
    {
        Write-Output "spanning-tree vlan $vlan_v root primary"
    }
    if ($vlan_g)
    {
        Write-Output "spanning-tree vlan $vlan_g root primary"
    }
}


Write-Output "end"
Write-Output "clock set $clock"
Write-Output "write mem"
Write-Output ""

# nmap_tracker
nmap_tracker component for Home Assistant

NOTE: Temporary until PR submittal to HASS core

Sample configuration.yaml

```
device_tracker:
  - platform: nmap_tracker
    hosts:
     - 192.168.0.0/24
    home_interval: 30
    scan_options: " --privileged -n --host-timeout 2s "
    exclude:
     - 192.168.0.254
    local_mac_hostname: "localhostunique"
    exclude-mac:
     - FF:FF:FF:FF:FF:FF
```

- local_mac_hostname default is 'localhost', which would create a sensor 'device_tracker.localhost'
- local_mac_hostname can also be a mac to match other created sensors.
- exclude-mac must be in all caps.


To install, see HASS docs for custom_component install.
Essentially, place these files in custom_compoenent subfolder


STATUS:

I believe this update resolves the below 2 issues, but I'm still examining how to resolve 33281

26553
Nmap tracker keep rediscovering excluded hosts with DHCP #26553

31986
nmap_tracker.device_tracker reports "No MAC address found for" itself #31986



33281
Issue with nmap_tracker since 107.6 #33281

>> Above issue could be migitigated by either:
a) - create sep thread to perform nmap scan, kill if too long
b) - request nmap package update to perform timeout (bitbucket)
c) - both a & b 

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
New OPTIONAL config fields:

- local_mac_hostname default is 'localhost', which would create a sensor 'device_tracker.localhost'
- local_mac_hostname can also be a mac to match other created sensors.
- exclude-mac item list entires must be in all caps.

Recommend to delete known_devices.yaml prior to install.

To install, see HASS docs for custom_component install.
Essentially, place these files in custom_component subfolder


STATUS:

I believe this update resolves the below 2 issues, but I'm still examining how to resolve 33281

26553
Nmap tracker keep rediscovering excluded hosts with DHCP #26553

31986
nmap_tracker.device_tracker reports "No MAC address found for" itself #31986

33281
Issue with nmap_tracker since 107.6 #33281
- Based on personal testing and other reports, I have observed cases where the python-nmap package will actually never return. This could be remedied by a timeout in the package itself.

q)s

>> Above issue could be migitigated by either:
a) - create sep thread to perform nmap scan, kill if too long
b) - request nmap package update to perform timeout (bitbucket)
c) - both a & b 

>> How would a duplicate device_tracker be handled by HASS? Would each update clobber the other?
-- this is possible since the user can define any mac address in the config for localhost, so does this need to be blocked at startup?

>> Nmap results return could also be getting stalled by a single host or subnet, so recommending for users to define seperate instances of nmap might be useful.

>> Furthermore, by default, nmap is doing reverse DNS lookups for devices to get names, so that also could be causing some user's issues and hangs.



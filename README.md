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

>> Nmap results return could also be getting stalled by a single host or subnet, so allowing the user to define seperate instances of nmap might be useful.
-- in another method, each line in the hosts config could evaulate to seperate Nmap call, allowing for varing user config options
-- such as:
```
Config A:
-- 192.168.0.0/24

Config B:
-- 192.168.0.1-124
-- 192.168.0.125-254
```
Currently, the component will combine both of these to a single nmap call, waiting until everything returns. I suggest making this into 2 separate calls to the package, allowing a user to define each call down to a single ip, or over an entire range. Based on personal testing, adding an external subnet will cause nmap to slow dramatically or potentially hang, so allowing what data can be retrieved would be much more valuable over a no data from a stall. On the other hand, nmap is primarily used for local devices, but a user can enter anything into the yaml. Yet, the potential for user disagnosis and subnet splitting to deal with local variances seems a clear improvement.

Furthermore, by default, nmap is doing reverse DNS lookups for devices to get names, so that also could be causing some user's issues and hangs.



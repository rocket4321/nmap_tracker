# nmap_tracker
nmap_tracker component for Home Assistant

NOTE: Temporary until PR submittal to HASS core

Sample configuration.yaml

```
device_tracker:
  - platform: nmap_tracker
    hosts:
     - 192.168.2.0/24
    home_interval: 30
    scan_options: " --privileged -n --host-timeout 5s "
    exclude:
     - 192.168.2.9
    local_mac_hostname: "localhostunique"
    exclude-mac:
     - FF:FF:FF:FF:FF:FF
```

- local_mac_hostname default is 'localhost', which would create a sensor 'device_tracker.localhost'
- local_mac_hostname can also be a mac to match other created sensors.
- exclude-mac must be in all caps.


To install, see HASS docs for custom_component install.
Essentially, place these files in custom_compoenent subfolder

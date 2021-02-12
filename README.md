# nmap_tracker
nmap_tracker component for Home Assistant

NOTE: Temporary until PR submittal to HASS core

Sample configuration.yaml

```
device_tracker:
  - platform: nmap_tracker
    hosts:
     - 192.168.0.0/24
    home_interval: 20
    interval_seconds: 150
    scan_options: " --dns-servers 192.168.0.1 --privileged -n --host-timeout 2s "
    exclude:
     - 192.168.0.69
    local_mac_hostname: "localhostunique"
    exclude-mac:
     - FF:FF:FF:FF:FF:FF

  - platform: nmap_tracker
    hosts:
     - 192.168.100.1-254
    home_interval: 10
    interval_seconds: 300
    scan_options: " -sn --privileged --host-timeout 5s "
    new_device_defaults:
      track_new_devices: false

```
New OPTIONAL config fields:

- local_mac_hostname default is 'localhost', which would create a sensor 'device_tracker.localhost'
- local_mac_hostname can also be a mac to match other created sensors.
- exclude-mac item list entires must be in all caps.
- debug_log_level is integer (1-5) that allows for limited or expanded debug to log, when debug level is active
->> Privacy Warning: debug_log_level of 3+ includes MAC addresses

Recommend to delete known_devices.yaml prior to install.

To install, see HASS docs for custom_component install.
Essentially, place these files in custom_component subfolder

Recommendations for posting issues:
- alter log level, as below
- set debug_log_level to 5
- set configuration.yaml to have only nmap_device tracker
- execute for at lengthy period (30+ min?) and upload log to github issue
```
logger:
  default: warning
  logs:
    homeassistant.components.device_tracker: debug
    custom_components.nmap_tracker: debug
```

STATUS:

I believe this update resolves the below 3 issues

26553
Nmap tracker keep rediscovering excluded hosts with DHCP #26553

31986
nmap_tracker.device_tracker reports "No MAC address found for" itself #31986

33281
Issue with nmap_tracker since 107.6 #33281
>>> Essentially, you will see this line in your log on every nmap scan:
[homeassistant.components.device_tracker] Updating device list from legacy took longer than the scheduled scan interval 0:05:00


Further thoughts:

>> How would a duplicate device_tracker be handled by HASS? Would each update clobber the other?
-- this is possible since the user can define any mac address in the config for localhost, so does this need to be blocked at startup?

>> Nmap results return could also be getting stalled by a single host or subnet, so recommending for users to define seperate instances of nmap device tracker for seperate subnets or for sporatic network responsiveness. Each device_tracker instance translates a different nmap process that could be either succeed or fail. It's defined in the user's config how each group is segmented, but multiple host line definitions are combined to a single process call for each nmap device tracker instance.

>> Furthermore, by default, nmap is doing reverse DNS lookups for devices to get names, so that also could be causing some user's issues and hangs.

>> Other failure causes could simply be resource limitations, such as local computing hardware, network delays/errors, wifi reception... If a nmap scan can't complete in enough time that a device is subsequently marked 'not_home', it then would only to be toggled back to 'home' when the scan completed. All this definitely would imply either a timing or resource bottleneck.

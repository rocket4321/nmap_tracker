# nmap_tracker
nmap_tracker component for Home Assistant

Looking for user feedback before submission to HA.......

Sample configuration.yaml

Use Cases ![link](./use-cases.rd)

```
device_tracker:
# Minimum Required
  - platform: nmap_tracker
    hosts:
     - 192.168.100.0/24

# Default
  - platform: nmap_tracker
    hosts:
     - 192.168.0.0/24
    consider_home: 180
    # Note 'consider_home' is replacement for 'home_interval', but consider_home value is now in seconds
    exclude_active: true
    timeout: 11   
    include_no_mac: false
    scan_options: "-F --host-timeout 5s"
    local_mac_hostname: "localhost"
    debug_log_level: 2
    # base options of device_tracker
    interval_seconds: 12
    new_device_defaults:
      track_new_devices: true

# Transient Device Use-Case
# Helpful to change parameters for just a few devices, rather than entire subnet
  - platform: nmap_tracker
    hosts:
     - 192.168.0.0/24
    consider_home: 300 
    exclusive_mac:
     - 00:11:22:33:44:55
     - 00:11:22:33:44:56
     - 00:11:22:33:44:57
    
# Advanced/Experimental
  - platform: nmap_tracker
    hosts:
     - 192.168.0.0/24
    consider_home: 600
    exclude_active: false
    timeout: 20
    interval_seconds: 60
    include_no_mac: true
    scan_options: "--dns-servers 192.168.0.1 --privileged --host-timeout 5s"
    exclude:
     - 192.168.0.69
    local_mac_hostname: "localhostunique"
    exclude_mac:
     - FF:FF:FF:FF:FF:FF
    debug_log_level: 5
    
# Note: Below config for testing ONLY  
  - platform: nmap_tracker
    hosts:
     - www.google.com
    include_no_mac: true
    interval_seconds: 90
    consider_home: 600
    timeout: 30
    scan_options: "--host-timeout 10s"
    debug_log_level: 5
```

# Breaking Changes (minimal):

- config option 'consider_home' is replacement for 'home_interval'. Change from minutes to seconds to match device tracker standards.


Highly Recommended fields:

- timeout may require adjustment in every network, but should always be less than interval_seconds

- interval_seconds defines how often the network is scanned by nmap in seconds. Default is 12 seconds. 
>> This value may by okay for a few hosts, but for an entire network, it should be increased to a recommended minimum of 60 or more.



New OPTIONAL config fields:

- debug_log_level is integer (1-5) that allows for limited or expanded debug to log, when debug level is active
->> Privacy Warning: debug_log_level of 3+ includes MAC addresses

- exclude_active is a boolean, enabled by default. When disabled, forces nmap to scan all configured host(s) on every scan. 
>> By default, this component optimizes to only scan for devices that could be marked as 'not_home' within the next <home_interval> minutes. This provides only a single scan for a device to continue to be marked as home. If some device connections are irregular, then a device would toggle back and forth. This is likely the best next option for a user to be able to enable if devices are toggling back and forth, but may increase resource consumption, based on configuration settings.

- exclude_mac is a list of MAC address to be ignored when returned by nmap results. Default is empty list.

- exclusive_mac is a list of MAC address to be exclusively monitored and all others ignored. The hosts defintion must be include a ip range to include each mac. If empty list (default), no hosts are filtered by this feature.

- include_no_mac is a boolean, disabled by default. When enabled, if a MAC address is not returned by nmap, it will be included and monitored. Naming scheme will will use hostname, or ip address if unavailable. MAC address is marked as 'XX:XX:XX:XX:XX:XX' in known_devices.xml

- local_mac_hostname default is 'localhost', which would create a sensor 'device_tracker.localhost'
- local_mac_hostname can also be a mac to match other created sensors.

- timeout: postive integer in seconds to allow nmap process to perform


# Results:
from current HASS nmap_tracker:
![plot](./images/history_rare_down.png)

from improved with exclude_active (set to false):
![plot](./images/history_no_down.png)


# Installation
Recommend to delete known_devices.yaml prior to install. (take a backup first, silly!)

To install, see HASS docs for custom_component install. 
Essentially, place these files in custom_components subfolder. That HASS config folder structure would then look like:
```
configuration.yaml
groups.yaml
...
> custom_components
> > nmap_tracker
> > > __init__.py
> > > device_tracker.py
> > > manifest.json 
```

Component change design note:
Due to HASS and nmap design, a scan may take longer than 10 seconds, so an error similar to below will often be displayed. To mitigate this issue, hass is instead provided the previous scan's results on an update request. In practical use, this means nmap data in hass is delayed by at least the time period of 'interval_seconds', so this value should be minimized while balancing host and network resources.
```
Updating device list from legacy took longer than the scheduled scan interval
```

# Troubleshooting
Recommendations for users with issues:
- set configuration.yaml to have only nmap_device tracker
- alter log level, as below
- logs will include the actual nmap command performed if valid options are provided
-- attempt to perform command within same execution as hass
-- such as for docker: 
```docker exec <container-name>> nmap <options> <hosts>```

If you still have issues, create an Issue here and please:
- Post entire configuration.yaml (should only be nmap_tracker)
- Post functioning nmap command (for your network) and results
- >> NOTE: May require experimention and investigation into nmap command pararmeters - https://nmap.org/book/port-scanning-options.html
- Activate debug log, set debug_log_level to 5 within nmap_tracker component config, and upload log to github issue
```
logger:
  default: warning
  logs:
    homeassistant.components.device_tracker: debug
    custom_components.nmap_tracker: debug
```

# Status

I believe this update resolves the below issues

26553
Nmap tracker keep rediscovering excluded hosts with DHCP #26553

31986
nmap_tracker.device_tracker reports "No MAC address found for" itself #31986

33281
Issue with nmap_tracker since 107.6 #33281

34813
Log spam: "Updating device list from legacy took longer than the scheduled scan interval" #34813

>>> Essentially, you will see this line in your log on every nmap scan:
[homeassistant.components.device_tracker] Updating device list from legacy took longer than the scheduled scan interval 0:05:00


Further thoughts:

>> By default, nmap is doing reverse DNS lookups for devices to get names, so that also could be causing some user's issues and hangs. Further code improvements should incorporate so that this action is not completed every scan, but simply on a startup/interval basis. Some of the examples above control where DNS requests go and/or disable it.

>> interval_seconds: I really recommend no smaller than the default 300 (5 min). I've seen some posts of sub 60 seconds, so could translate to a heavy network workload for older devices across an entire subnet.

>> Nmap results return could also be getting stalled by a single host or subnet, so recommending for users to define seperate instances of nmap device tracker for seperate subnets or for sporatic network responsiveness. Each device_tracker instance translates a different nmap process that could be either succeed or fail. It's defined in the user's config how each group is segmented, but multiple host line definitions are combined to a single process call for each nmap device tracker instance.

>> Other failure causes could simply be resource limitations, such as local computing hardware, network delays/errors, wifi reception... If a nmap scan can't complete in enough time that a device is subsequently marked 'not_home', it then would only to be toggled back to 'home' when the scan completed. All this definitely would imply either a timing or resource bottleneck.


Qs for HASS team:

>> Is a default MAC address of 'xx:xx:xx:xx:xx:xx' acceptable in known_devices.xml ?

>> How would a duplicate device_tracker be handled by HASS? Would each update clobber the other?
-- this is possible since the user can define any mac address in the config for localhost, so does this need to be blocked at startup?



Latest:

- Incorporated changes to python-nmap and released latest RC candidate. Looking for user feedback
- Added exclusive_mac list config option, to allow for option changes to specific mac(s)

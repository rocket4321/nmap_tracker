
# CASE 1 - My personal use case
# Many of us have a mixed environment, some devices respond timely and reliably, others not so much.

 - Initial base config (NOTE: Very 'aggressive' values):
```
    hosts:
     - 192.168.0.0/24
    consider_home: 3
    timeout: 60
    interval_seconds: 120
    scan_options: "--host-timeout 2s"
```
# These settings reduce latency from a lost device, but will not work for every device since many could oscillate
# So, transition those devices to another nmap instance, by using exclusive_mac

- Final config (Allows for specific settings for each ip and/or mac):
```
    hosts:
     - 192.168.0.0/24
    consider_home: 3
    timeout: 60
    interval_seconds: 120
    # Ignore the transient devices in this group            
    exclude_mac:
     - 11:22:33:44:55:66
     - aa:bb:cc:dd:ee:ff                
    scan_options: "--host-timeout 2s"

    hosts:
     - 192.168.0.0/24
    consider_home: 5
    timeout: 120
    interval_seconds: 180
    # Only monitor the transient devices in this group             
    exclusive_mac:
     - 11:22:33:44:55:66
     - aa:bb:cc:dd:ee:ff
    scan_options: "--host-timeout 10s"
```

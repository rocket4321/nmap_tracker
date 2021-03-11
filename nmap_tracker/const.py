"""Constants for the Nmap Tracker component."""

ATTR_DURATION = "duration_sec"
ATTR_PROCESSOR = "processor"
ATTR_RESPONSE_REASON = "response_reason"

CONF_DEBUG_LEVEL = "debug_log_level"
CONF_EXCLUDE = "exclude"
CONF_EXCLUDE_ACTIVE = "exclude_active"
CONF_EXCLUDE_MAC = "exclude_mac"

# Interval in minutes to exclude devices from a scan while they are home
CONF_HOME_INTERVAL = "home_interval"
CONF_INCLUDE_NO_MAC = "include_no_mac"
CONF_OPTIONS = "scan_options"

# Timeout in seconds before nmap quits, default is 60 seconds
CONF_TIMEOUT = "timeout"
CONF_LOCAL_MAC_NAME = "local_mac_hostname"

DEFAULT_EXCLUDE_ACTIVE = True
DEFAULT_INCLUDE_NO_MAC = False
DEFAULT_OPTIONS = "-F --host-timeout 5s"
DEFAULT_LOCAL_MAC_NAME = "localhost"
DEFAULT_PROCESS_EVAL_INTERVAL = 5
#DEFAULT_TIMEOUT = "10"
DEFAULT_TIMEOUT = "60"

# Debug log verbosity
# WARNING: Level 3+ includes MAC addresses in logs
DEFAULT_DEBUG_LEVEL = "1"

# MAC utilized when none provided by nmap results scan (local device)
DEFAULT_MAC = "XX:XX:XX:XX:XX:XX"

# Provides Info level message to user if duration is exceeded
NMAP_DURATION_MAX_MSG = 10

NMAP_STATUS_REASON_LOCAL = "localhost-response"


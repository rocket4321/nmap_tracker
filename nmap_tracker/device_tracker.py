"""Support for scanning a network with nmap."""
from collections import namedtuple
from datetime import timedelta
import logging

from getmac import get_mac_address
from nmap import PortScanner, PortScannerError
import voluptuous as vol

from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import CONF_HOSTS
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util

_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = "exclude"
CONF_EXCLUDE_MAC = "exclude-mac"
# Interval in minutes to exclude devices from a scan while they are home
CONF_HOME_INTERVAL = "home_interval"
CONF_OPTIONS = "scan_options"
CONF_LOCAL_MAC_NAME = "local_mac_hostname"
DEFAULT_OPTIONS = "-F --host-timeout 5s"
DEFAULT_LOCAL_MAC_NAME = "localhost"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOSTS): cv.ensure_list,
        vol.Required(CONF_HOME_INTERVAL, default=0): cv.positive_int,
        vol.Optional(CONF_EXCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUDE_MAC, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS): cv.string,
        vol.Optional(CONF_LOCAL_MAC_NAME, default=DEFAULT_LOCAL_MAC_NAME): cv.string,
    }
)


def get_scanner(hass, config):
    """Validate the configuration and return a Nmap scanner."""
    return NmapDeviceScanner(config[DOMAIN])


Device = namedtuple("Device", ["mac", "name", "ip", "last_update"])


class NmapDeviceScanner(DeviceScanner):
    """This class scans for devices using nmap."""

    exclude = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []

        self.hosts = config[CONF_HOSTS]
        self.exclude = config[CONF_EXCLUDE]
        self.exclude_mac = config[CONF_EXCLUDE_MAC]
        minutes = config[CONF_HOME_INTERVAL]
        self._options = config[CONF_OPTIONS]
        self.home_interval = timedelta(minutes=minutes)
        self.local_mac_name = config[CONF_LOCAL_MAC_NAME]

        _LOGGER.debug("Scanner initialized")

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        _LOGGER.debug("Nmap last results %s", self.last_results)

        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        filter_named = [
            result.name for result in self.last_results if result.mac == device
        ]

        if filter_named:
            return filter_named[0]
        return None

    def get_extra_attributes(self, device):
        """Return the IP of the given device."""
        filter_ip = next(
            (result.ip for result in self.last_results if result.mac == device), None
        )
        return {"ip": filter_ip}

    def _update_info(self):
        """Scan the network for devices.

        Returns boolean if scanning successful.
        """
        _LOGGER.debug("Scanning...")

        scanner = PortScanner()

        options = self._options

        if self.home_interval:
            boundary = dt_util.now() - self.home_interval
            last_results = [
                device for device in self.last_results if device.last_update > boundary
            ]
            if last_results:
                exclude_hosts = self.exclude + [device.ip for device in last_results]
            else:
                exclude_hosts = self.exclude
        else:
            last_results = []
            exclude_hosts = self.exclude
        if exclude_hosts:
            options += f" --exclude {','.join(exclude_hosts)}"

        try:
            # As of python-nmap v0.6.1, this may never return
            # https://github.com/home-assistant/core/issues/33281
            result = scanner.scan(hosts=" ".join(self.hosts), arguments=options)
        except:
            return False

        _LOGGER.debug("Command: %s", scanner.command_line())
        if result is None:
            _LOGGER.debug("Scan result was empty.")
            return False

        now = dt_util.now()
        for ipv4, info in result["scan"].items():
            if info["status"]["state"] != "up":
                continue
            name = info["hostnames"][0]["name"] if info["hostnames"] else ipv4
            # Mac address only returned if nmap ran as root
            mac = info["addresses"].get("mac") or get_mac_address(ip=ipv4)
            if mac is None:
                # nmap will not report MAC for local ip, so ignore for single case
                if info["status"]["reason"] != "localhost-response":
                    _LOGGER.info("No MAC address found for %s", ipv4)
                    continue
                else:
                    # provide default mac as name for fill-in
                    mac = self.local_mac_name
            if (mac.upper() in self.exclude_mac):
                _LOGGER.debug("MAC address %s ignored at %s", mac.upper(), ipv4)
                continue
            last_results.append(Device(mac.upper(), name, ipv4, now))

        self.last_results = last_results

        _LOGGER.debug("nmap scan successful")
        return True


"""Support for scanning a network with nmap."""
from collections import namedtuple
from datetime import timedelta

import ctypes 
import logging
import threading
import time
import voluptuous as vol

from getmac import get_mac_address
from nmap import PortScanner, PortScannerError, PortScannerTimeout

from homeassistant.components.device_tracker import (
    DeviceScanner,
    PLATFORM_SCHEMA,
)

from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_SCAN_INTERVAL,
    DEFAULT_CONSIDER_HOME,
    DOMAIN,
    SCAN_INTERVAL,
)

from homeassistant.const import CONF_HOSTS
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util

from .const import (
    ATTR_RESPONSE_REASON,
    CONF_DEBUG_LEVEL,
    CONF_EXCLUDE,
    CONF_EXCLUDE_ACTIVE,
    CONF_EXCLUDE_MAC,
    CONF_EXCLUSIVE_MAC,
    CONF_HOME_INTERVAL,
    CONF_INCLUDE_NO_MAC,
    CONF_OPTIONS,
    CONF_LOCAL_MAC_NAME,
    CONF_TIMEOUT,
    DEFAULT_DEBUG_LEVEL,
    DEFAULT_EXCLUDE_ACTIVE,
    DEFAULT_INCLUDE_NO_MAC,
    DEFAULT_LOCAL_MAC_NAME,
    DEFAULT_MAC,
    DEFAULT_OPTIONS,
    DEFAULT_TIMEOUT,
    NMAP_STATUS_REASON_LOCAL,
)

_LOGGER = logging.getLogger(__name__)


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOSTS): cv.ensure_list,
        vol.Optional(CONF_EXCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUDE_ACTIVE, default=DEFAULT_EXCLUDE_ACTIVE): cv.boolean,
        vol.Optional(CONF_EXCLUDE_MAC, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUSIVE_MAC, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS): cv.string,
        vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
        vol.Optional(CONF_DEBUG_LEVEL, default=DEFAULT_DEBUG_LEVEL): cv.positive_int,
        vol.Optional(CONF_LOCAL_MAC_NAME, default=DEFAULT_LOCAL_MAC_NAME): cv.string,
        vol.Optional(CONF_INCLUDE_NO_MAC, default=DEFAULT_INCLUDE_NO_MAC): cv.boolean,
    }
)


def get_scanner(hass, config):
    """Validate the configuration and return a Nmap scanner."""
    return NmapDeviceScanner(config[DOMAIN])


Device = namedtuple("Device", ["mac", "name", "ip", "last_update", "reason"])


class NmapDeviceScanner(DeviceScanner):
    """This class scans for devices using nmap."""

    exclude = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.command_line = []
        self.last_results = []
        self.hosts = config[CONF_HOSTS]
        self.exclude = config[CONF_EXCLUDE]
        self.exclude_active = config[CONF_EXCLUDE_ACTIVE]
        exclude_mac = config[CONF_EXCLUDE_MAC]
        self.exclude_mac = [mac.upper() for mac in exclude_mac]
        exclusive_mac = config[CONF_EXCLUSIVE_MAC]
        self.exclusive_mac = [mac.upper() for mac in exclusive_mac]
        self.home_interval = config[CONF_CONSIDER_HOME]
        self.timeout = timedelta(seconds=config[CONF_TIMEOUT])
        self._options = config[CONF_OPTIONS]
        self.local_mac_name = config[CONF_LOCAL_MAC_NAME]
        self.debug_level = int(config[CONF_DEBUG_LEVEL])
        self.include_no_mac = config[CONF_INCLUDE_NO_MAC]
        self.scanner = PortScanner()

        # Validate user inputs
        try:
            scan_interval = config[CONF_SCAN_INTERVAL]
            scan_interval_sec = scan_interval.total_seconds()
        except:
            scan_interval = SCAN_INTERVAL
            scan_interval_sec = scan_interval.total_seconds()
        # Confirm scan interval is shorter than home interval                
        if self.home_interval.total_seconds() <= scan_interval_sec:
            _LOGGER.warning("Value set for '%s'='%s' conflicts with '%s'='%s'. Consider home (seconds) should exceed scan interval (seconds).",
                 CONF_CONSIDER_HOME, self.home_interval.total_seconds(), CONF_SCAN_INTERVAL, scan_interval_sec)
        # Confirm scan interval is longer than timeout
        if (config[CONF_TIMEOUT]) >= scan_interval_sec:
            _LOGGER.warning("Value set for '%s'='%s' conflicts with '%s'='%s'. Scan interval (seconds) should exceed timeout (seconds).",
                 CONF_TIMEOUT, config[CONF_TIMEOUT], CONF_SCAN_INTERVAL, scan_interval_sec)
        _LOGGER.debug("Scanner initialized")
       
    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        if self.debug_level >= 4:
            _LOGGER.debug("Nmap last results for %s = %s"
                , ','.join(self.hosts), self.last_results)
        if len(self.exclusive_mac) > 0:
            return [device.mac for device in self.last_results if device.mac in self.exclusive_mac]
        if self.include_no_mac:
            return [device.mac for device in self.last_results]
        else:
            return [device.mac for device in self.last_results if device.reason != NMAP_STATUS_REASON_LOCAL]
            
    def get_device_name(self, device):
        """Return the name of the given device, prioritized by 
           - dns name
           - mac address
           - ip
           - or None if we don't know or it's a filtered device.
        """
        results = [
            result for result in self.last_results if result.mac == device
        ]
        result = results[0] 
        if result.name and len(result.name) > 0:
            if self.debug_level >= 5:
                _LOGGER.debug("get_device_name (name) for %s = %s"
                    , device, result.name)
            return result.name
        # Ignore mac if <NMAP_STATUS_REASON_LOCAL> reason
        if result.mac and result.reason != NMAP_STATUS_REASON_LOCAL:
            if self.debug_level >= 5:
                _LOGGER.debug("get_device_name (mac) for %s = %s"
                    , device, result.mac)
            return result.mac.lower()
        # Unusual, but possible for nmap to return results with no mac
        if result.ip:
            if self.debug_level >= 5:
                _LOGGER.debug("get_device_name (ip) for %s = %s"
                    , device, result.ip)
            return result.ip
        return None

    def get_extra_attributes(self, device):
        """Return the IP of the given device."""
        filter_ip = next(
            (result.ip for result in self.last_results if result.mac == device), None
        )
        filter_reason = next(
            (result.reason for result in self.last_results if result.mac == device), None
        )
        return {
		    "ip": filter_ip,
		    "mac": device,
            ATTR_RESPONSE_REASON: filter_reason,
	    }

    def _update_info(self):
        """Scan the network for devices.
        """
        options = self._options
        if self.home_interval:
            boundary = dt_util.now() - self.home_interval
            last_results = [
                device for device in self.last_results if device.last_update > boundary
            ]
            if last_results and self.exclude_active:
                exclude_hosts = self.exclude + [device.ip for device in last_results]
            else:
                exclude_hosts = self.exclude
        else:
            last_results = []
            exclude_hosts = self.exclude
        if exclude_hosts:
            options += f" --exclude {','.join(exclude_hosts)}"
       
        # start a thread to start nmap and process results
        self.last_results = last_results
        self._process_host(self.last_results
                        , self.command_line
                        , self.hosts
                        , exclude_hosts
                        , self.exclusive_mac
                        , options
                        , self.timeout
                        , self.exclude_mac
                        , self.local_mac_name
                        , self.include_no_mac
                        , self.debug_level
                )

    def _process_host(self
                        , last_results
                        , command_line
                        , hosts
                        , exclude_hosts
                        , exclusive_mac
                        , options
                        , timeout
                        , exclude_mac
                        , local_mac_name
                        , include_no_mac
                        , debug_level):
        """Scan the network for devices.
        """
        # start a thread to start nmap and process results
        start_time = dt_util.now()
        processor = NmapProcessor(
		    last_results
			, command_line
			, hosts
			, exclude_hosts
			, exclusive_mac
			, options
			, timeout
			, exclude_mac
			, local_mac_name
			, include_no_mac
			, debug_level
		)
        processor.start()


class NmapProcessor(threading.Thread):
    """This class scans for devices using nmap."""

    def __init__(self
		, last_results
		, command_line
		, hosts
		, exclude_hosts
		, exclusive_mac
		, options
		, timeout
		, exclude_mac
		, local_mac_name
		, include_no_mac
		, debug_level
		):
        """Initialize nmap processing thread."""
        super().__init__()
        self.daemon = True
        self._last_results = last_results
        self._command_line = command_line
        self._hosts = hosts
        self._exclude_hosts = exclude_hosts
        self._exclusive_mac = exclusive_mac
        self._options = options
        self._timeout = timeout
        self._exclude_mac = exclude_mac
        self._local_mac_name = local_mac_name
        self._debug_level = debug_level
        self._include_no_mac = include_no_mac
        self._scanner = PortScanner()
        hosts = self._scanner.listscan(hosts=','.join(hosts))
        _LOGGER.debug("Nmap host list: %s", ','.join(hosts))
        if self._debug_level >= 2:
           _LOGGER.debug("Processor [%s] initialized for %s"
		, threading.currentThread().getName(), self._hosts)

    def _process_result(self, result):
        now = dt_util.now()
        for ipv4, info in result["scan"].items():
            if self._debug_level >= 3:
                _LOGGER.debug("Processing %s %s", ipv4, info["status"]["state"])
            if info["status"]["state"] != "up":
                continue
            name = info["hostnames"][0]["name"] if info["hostnames"] else ipv4
            # Mac address only returned if nmap ran as root
            mac = info["addresses"].get("mac") or get_mac_address(ip=ipv4)
            if len(self._exclusive_mac) > 0 and mac not in self._exclusive_mac:
                if self._debug_level >= 4:
                    _LOGGER.debug("Ignoring (reason: not in exclusive mac list) %s %s", ipv4, mac)
                continue
            reason = info["status"]["reason"]
            if mac is None:
                # nmap will not report MAC for local ip, so ignore for single case
                if info["status"]["reason"] != NMAP_STATUS_REASON_LOCAL:
                    if self._include_no_mac:
                        mac = DEFAULT_MAC
                    else:
                        _LOGGER.info("No MAC address found for %s. Enable '%s' for nmap for device monitoring."
				, ipv4, CONF_INCLUDE_NO_MAC)
                        continue
                else:
                    mac = self._local_mac_name
            else:
               mac = mac.upper()
            if (mac in self._exclude_mac):
                if self._debug_level >= 3:
                    _LOGGER.debug("MAC address %s ignored at %s", mac, ipv4)
                continue
            self._last_results.append(Device(mac, name, ipv4, now, reason))

    def _run(self):
        result = None
        try:
            result = self._scanner.scan(hosts=','.join(self._hosts)
			, arguments=self._options
			, timeout=self._timeout.total_seconds()
			)
        except PortScannerTimeout:
            _LOGGER.info("Nmap Timeout for %s", self._hosts)
            return
        except PortScannerError as e:
            _LOGGER.info("Nmap Exception for %s : %s", ','.join(self._hosts), str(e))
            return
        if self._debug_level >= 1:
            _LOGGER.debug("Nmap Command: %s", self._scanner.command_line())
        self._process_result(result)
        self._command_line.append(self._scanner.command_line())

    def run(self):
        """Run the processor."""
        if self._debug_level >= 4:
            _LOGGER.debug("Nmap Processor thread started: %s", threading.currentThread().getName() )
        self._run()


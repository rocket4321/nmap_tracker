"""Support for scanning a network with nmap."""
from collections import namedtuple
from datetime import timedelta
from datetime import datetime
from getmac import get_mac_address
#from nmap import PortScanner, PortScannerError
import ctypes 
import logging
import queue
import threading
import time
import voluptuous as vol

#from nmap import PortScanner, PortScannerError
# nmap copy - submit Issue and PR when cody ready
import csv
import io
import os
import re
import shlex
import subprocess
import sys
from xml.etree import ElementTree as ET
from multiprocessing import Process

# Submit PR
import requests


from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import CONF_HOSTS
import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util

_LOGGER = logging.getLogger(__name__)

ATTR_PROCESSOR = "processor"
CONF_DEBUG_LEVEL = "debug_log_level"
CONF_EXCLUDE = "exclude"
CONF_EXCLUDE_MAC = "exclude-mac"
# Interval in minutes to exclude devices from a scan while they are home
CONF_HOME_INTERVAL = "home_interval"
CONF_OPTIONS = "scan_options"
CONF_TIMEOUT = "timeout"
CONF_LOCAL_MAC_NAME = "local_mac_hostname"
DEFAULT_OPTIONS = "-F --host-timeout 5s"
DEFAULT_LOCAL_MAC_NAME = "localhost"
DEFAULT_PROCESS_EVAL_INTERVAL = 5
DEFAULT_TIMEOUT = "20"
DEFAULT_ALERT_THREAD_COUNT_MIN = 3
# Varying increase in log debug
# WARNING: Level 3+ includes MAC addresses in logs
DEFAULT_DEBUG_LEVEL = "1"


PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOSTS): cv.ensure_list,
        vol.Required(CONF_HOME_INTERVAL, default=0): cv.positive_int,
        vol.Optional(CONF_EXCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_EXCLUDE_MAC, default=[]): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS): cv.string,
        vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
        vol.Optional(CONF_DEBUG_LEVEL, default=DEFAULT_DEBUG_LEVEL): cv.positive_int,
        vol.Optional(CONF_LOCAL_MAC_NAME, default=DEFAULT_LOCAL_MAC_NAME): cv.string,
    }
)


def get_scanner(hass, config):
    """Validate the configuration and return a Nmap scanner."""
    return NmapDeviceScanner(config[DOMAIN])


Device = namedtuple("Device", ["mac", "name", "ip", "last_update"])

class NmapDeviceScanner(DeviceScanner):
    """This class scans for devices using nmap."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []
        self.thread_idents = []
        self.hosts = config[CONF_HOSTS]
        self.exclude = config[CONF_EXCLUDE]
        self.exclude_mac = config[CONF_EXCLUDE_MAC]
        home_interval_minutes = config[CONF_HOME_INTERVAL]
        self.timeout = timedelta(seconds=config[CONF_TIMEOUT])
        self._options = config[CONF_OPTIONS]
        self.home_interval = timedelta(minutes=home_interval_minutes)
        self.local_mac_name = config[CONF_LOCAL_MAC_NAME]
        self.debug_level = int(config[CONF_DEBUG_LEVEL])
        self.nmap_process_queue = queue.SimpleQueue()
       
    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        try:
           self._update_info()
           if self.debug_level >= 4:
               _LOGGER.debug("Nmap last results for %s = %s"
			, " ".join(self.hosts), self.last_results)
        except Exception as e:
           _LOGGER.error("Nmap Exception: %s", str(e))

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
        """
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

        start_time = datetime.now()

        # start a thread to start nmap and process results
        processor_thread = None
        processor = NmapProcessor(
		self.nmap_process_queue
			, last_results
			, " ".join(self.hosts)
			, exclude_hosts
			, options
			, self.timeout
			, self.exclude_mac
			, self.local_mac_name
			, self.debug_level
		)
        processor.start()
        check_interval_sec=DEFAULT_PROCESS_EVAL_INTERVAL

        # Keep track of how many active threads related to nmap
        ident = self.nmap_process_queue.get()
        if ident not in self.thread_idents:
            self.thread_idents.append(ident)
        # Remove threads in list that have terminated
        active_thread_idents = []
        for thread in threading.enumerate():
            if self.debug_level >= 5:
                _LOGGER.debug("Active thread %s - %s", thread.name , thread.ident)
            active_thread_idents.append(thread.ident) 
        # New list is intersection of both active and previous thread list
        self.thread_idents = [value for value in self.thread_idents if value in active_thread_idents]

        if len(self.thread_idents) > DEFAULT_ALERT_THREAD_COUNT_MIN:
            _LOGGER.warning("Processor thread count is high at %s", len(self.thread_idents))
        else:
            if self.debug_level >= 2:
                _LOGGER.debug("Processor thread count is %s", len(self.thread_idents))

        # Wait twice as long here, since this will just become a zombie thread 
        # and this is backup if nmap doesn't terminate properly or timeout not set properly
        wait_sec = self.timeout.total_seconds()
        wait_sec += self.timeout.total_seconds()

        # monitor for typical thread termination
        while ((datetime.now() - start_time).total_seconds() <= wait_sec):
                time.sleep(check_interval_sec)
                if not processor.is_alive():
                    if self.debug_level >= 5:
                        _LOGGER.debug("Processor thread completed normally after %s seconds for %s.",
                            (datetime.now() - start_time).total_seconds() , " ".join(self.hosts))
                    self.last_results = last_results
                    break
        # Confirm nmap has returned, otherwise inform
        if processor.is_alive():
            _LOGGER.info("Processor thread %s has potentially hung after %s seconds; total count is %s."
                 , ident, str(wait_sec), len(self.thread_idents))


class NmapProcessor(threading.Thread):
    """This class scans for devices using nmap."""

    def __init__(self
		, queue
		, last_results
		, hosts
		, exclude_hosts
		, options
		, timeout
		, exclude_mac
		, local_mac_name
		, debug_level
		):
        """Initialize nmap processing thread."""
        super().__init__()
        self.daemon = True
        self._last_results = last_results
        self._hosts = hosts
        self._exclude_hosts = exclude_hosts
        self._options = options
        self._timeout = timeout
        self._exclude_mac = exclude_mac
        self._local_mac_name = local_mac_name
        self._debug_level = debug_level
        self._queue = queue

        if self._debug_level >= 2:
           _LOGGER.debug("Processor [%s] initialized for %s"
		, threading.currentThread().getName(), self._hosts)

    def _process_result(self, result):
        now = dt_util.now()
        for ipv4, info in result["scan"].items():
            _LOGGER.debug("Processing %s", ipv4)
            if info["status"]["state"] != "up":
                continue
            name = info["hostnames"][0]["name"] if info["hostnames"] else ipv4
            # Mac address only returned if nmap ran as root
            mac = info["addresses"].get("mac") or get_mac_address(ip=ipv4)
            if mac is None:
                # nmap will not report MAC for local ip, so ignore for single case
                if info["status"]["reason"] != "localhost-response":
                    _LOGGER.debug("No MAC address found for %s", ipv4)
                    continue
                else:
                    # provide default mac as name for fill-in
                    mac = self._local_mac_name
            if (mac.upper() in self._exclude_mac):
                if self._debug_level >= 3:
                    _LOGGER.debug("MAC address %s ignored at %s", mac.upper(), ipv4)
                continue
            self._last_results.append(Device(mac.upper(), name, ipv4, now))

    def _run(self):
        result = None
        try:
            scanner = PortScanner()
            # As of python-nmap v0.6.1, this may never return
            # https://github.com/home-assistant/core/issues/33281
            result = scanner.scan(hosts=self._hosts
			, arguments=self._options
			, timeout=self._timeout.total_seconds()
			)
        except Exception as e:
            _LOGGER.warning("Nmap Exception for %s : %s", str(e))
            return
        if self._debug_level >= 1:
            _LOGGER.debug("Nmap Command: %s", scanner.command_line())
        self._process_result(result)

    def run(self):
        """Run the processor."""
        try:
            if self._debug_level >= 4:
               _LOGGER.debug("Nmap Processor thread started: %s", threading.currentThread().getName() )
            self._queue.put(threading.currentThread().ident)
            self._run()
        except Exception as e:
            _LOGGER.warning("Exception during nmap processor: %s", str(e))









###########################################################################
#
# ONLY TEMP - BELOW  
# FOR TEST ONLY 
###########################################################################
#
#
# BELOW I COPIED FROM:
# https://bitbucket.org/xael/python-nmap/src/master/nmap/nmap.py
#
#  And a PR to incorp these changes will be submitted when code is ready
#

###########################################################################




class PortScanner(object):
    """
    PortScanner class allows to use nmap from python

    """
    def __init__(self, nmap_search_path=('nmap',
                                         '/usr/bin/nmap',
                                         '/usr/local/bin/nmap',
                                         '/sw/bin/nmap',
                                         '/opt/local/bin/nmap')):
        """
        Initialize PortScanner module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        :param nmap_search_path: tupple of string where to search for nmap executable. Change this if you want to use a specific version of nmap.
        :returns: nothing

        """
        self._nmap_path = ''                # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_last_output = ''  # last full ascii nmap output
        is_nmap_found = False       # true if we have found nmap

        self.__process = None

        # regex used to detect nmap (http or https)
        regex = re.compile(
            'Nmap version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)'
        )
        # launch 'nmap -V', we wait after
        # 'Nmap version 5.0 ( http://nmap.org )'
        # This is for Mac OSX. When idle3 is launched from the finder, PATH is not set so nmap was not found
        for nmap_path in nmap_search_path:
            try:
                if sys.platform.startswith('freebsd') \
                   or sys.platform.startswith('linux') \
                   or sys.platform.startswith('darwin'):
                    p = subprocess.Popen([nmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE,
                                         close_fds=True)
                else:
                    p = subprocess.Popen([nmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE)

            except OSError:
                pass
            else:
                self._nmap_path = nmap_path  # save path
                break
        else:
            raise PortScannerError(
                'nmap program was not found in path. PATH is : {0}'.format(
                    os.getenv('PATH')
                )
            )

        self._nmap_last_output = bytes.decode(p.communicate()[0])  # sav stdout
        for line in self._nmap_last_output.split(os.linesep):
            if regex.match(line) is not None:
                is_nmap_found = True
                # Search for version number
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._nmap_version_number = int(line[rv.start():rv.end()])
                    self._nmap_subversion_number = int(
                        line[rsv.start()+1:rsv.end()]
                    )
                break

        if not is_nmap_found:
            raise PortScannerError('nmap program was not found in path')

        return

    def get_nmap_last_output(self):
        """
        Returns the last text output of nmap in raw text
        this may be used for debugging purpose

        :returns: string containing the last text output of nmap in raw text
        """
        return self._nmap_last_output

    def nmap_version(self):
        """
        returns nmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        :returns: (nmap_version_number, nmap_subversion_number)
        """
        return (self._nmap_version_number, self._nmap_subversion_number)

    def listscan(self, hosts='127.0.0.1'):
        """
        do not scan but interpret target hosts and return a list a hosts
        """
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
        output = self.scan(hosts, arguments='-sL')
        # Test if host was IPV6
        if 'scaninfo' in output['nmap'] \
           and 'error' in output['nmap']['scaninfo']  \
           and len(output['nmap']['scaninfo']['error']) > 0 \
           and 'looks like an IPv6 target specification' in output['nmap']['scaninfo']['error'][0]:  # noqa
            self.scan(hosts, arguments='-sL -6')

        return self.all_hosts()

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, timeout=0):
        """
        Scan given hosts

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know
        if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param sudo: launch nmap with sudo if True
        :param timeout: int, if > zero, will terminate scan after seconds, otherwise will wait indefintely

        :returns: scan_result as dictionnary
        """
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))  # noqa
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))  # noqa
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))  # noqa

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        # Launch scan
        args = [self._nmap_path, '-oX', '-'] + h_args + ['-p', ports] * (ports is not None) + f_args
        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args, bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # wait until finished
        # get output
        # Terminate after user timeout
        #(self._nmap_last_output, nmap_err) = p.communicate()
        if timeout < 1:
            (self._nmap_last_output, nmap_err) = p.communicate()
        else:
            try:
                (self._nmap_last_output, nmap_err) = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                raise PortScannerError('Timeout from nmap process')

        nmap_err = bytes.decode(nmap_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-nmap mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # nmap.scan() returns nothing. This behavior also diverges significantly
        # from commandline nmap, which simply stderrs individual problems but
        # keeps on trucking.

        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        # sys.stderr.write(line+os.linesep)
                        nmap_warn_keep_trace.append(line+os.linesep)
                    else:
                        # raise PortScannerError(nmap_err)
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_nmap_xml_scan(
            nmap_xml_output=self._nmap_last_output,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace
        )


    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace='', nmap_warn_keep_trace=''):
        """
        Analyses NMAP xml scan ouput

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param nmap_xml_output: xml string to analyse
        :returns: scan_result as dictionnary
        """

        # nmap xml output looks like :
        # <host starttime="1267974521" endtime="1267974522">
        #   <status state="up" reason="user-set"/>
        #   <address addr="192.168.1.1" addrtype="ipv4" />
        #   <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
        #   <ports>
        #     <port protocol="tcp" portid="22">
        #       <state state="filtered" reason="no-response" reason_ttl="0"/>
        #       <service name="ssh" method="table" conf="3" />
        #     </port>
        #     <port protocol="tcp" portid="25">
        #       <state state="filtered" reason="no-response" reason_ttl="0"/>
        #       <service name="smtp" method="table" conf="3" />
        #     </port>
        #   </ports>
        #   <hostscript>
        #    <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
        #    <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
        #    <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
        #   </hostscript>
        #   <times srtt="-1" rttvar="-1" to="1000000" />
        # </host>

        # <port protocol="tcp" portid="25">
        #  <state state="open" reason="syn-ack" reason_ttl="0"/>
        #   <service name="smtp" product="Exim smtpd" version="4.76" hostname="grostruc" method="probed" conf="10">
        #     <cpe>cpe:/a:exim:exim:4.76</cpe>
        #   </service>
        #   <script id="smtp-commands" output="grostruc Hello localhost [127.0.0.1], SIZE 52428800, PIPELINING, HELP, &#xa; Commands supported: AUTH HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP "/>
        # </port>

        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output

        scan_result = {}


        try:
            dom = ET.fromstring(self._nmap_last_output)
        except Exception:
            if len(nmap_err) > 0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        # nmap command line
        scan_result['nmap'] = {
            'command_line': dom.get('args'),
            'scaninfo': {},
            'scanstats': {'timestr': dom.find("runstats/finished").get('timestr'),
                          'elapsed': dom.find("runstats/finished").get('elapsed'),
                          'uphosts': dom.find("runstats/hosts").get('up'),
                          'downhosts': dom.find("runstats/hosts").get('down'),
                          'totalhosts': dom.find("runstats/hosts").get('total')}
            }

        # if there was an error
        if len(nmap_err_keep_trace) > 0:
            scan_result['nmap']['scaninfo']['error'] = nmap_err_keep_trace

        # if there was a warning
        if len(nmap_warn_keep_trace) > 0:
            scan_result['nmap']['scaninfo']['warning'] = nmap_warn_keep_trace

        # info about scan
        for dsci in dom.findall('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {
                'method': dsci.get('type'),
                'services': dsci.get('services')
                }

        scan_result['scan'] = {}

        for dhost in dom.findall('host'):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') is not None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')

            hostnames = []
            if len(dhost.findall('hostnames/hostname')) > 0:
                for dhostname in dhost.findall('hostnames/hostname'):
                    hostnames.append({
                        'name': dhostname.get('name'),
                        'type': dhostname.get('type'),
                    })
            else:
                hostnames.append({
                    'name': '',
                    'type': '',
                })

            scan_result['scan'][host] = PortScannerHostDict({'hostnames': hostnames})

            scan_result['scan'][host]['addresses'] = address_block
            scan_result['scan'][host]['vendor'] = vendor_block

            for dstatus in dhost.findall('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                                       'reason': dstatus.get('reason')}
            for dstatus in dhost.findall('uptime'):
                # uptime : seconds, lastboot
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                                'lastboot': dstatus.get('lastboot')}
            for dport in dhost.findall('ports/port'):
                # protocol
                proto = dport.get('protocol')
                # port number converted as integer
                port = int(dport.get('portid'))
                # state of the port
                state = dport.find('state').get('state')
                # reason
                reason = dport.find('state').get('reason')
                # name, product, version, extra info and conf if any
                name = product = version = extrainfo = conf = cpe = ''
                for dname in dport.findall('service'):
                    name = dname.get('name')
                    if dname.get('product'):
                        product = dname.get('product')
                    if dname.get('version'):
                        version = dname.get('version')
                    if dname.get('extrainfo'):
                        extrainfo = dname.get('extrainfo')
                    if dname.get('conf'):
                        conf = dname.get('conf')

                    for dcpe in dname.findall('cpe'):
                        cpe = dcpe.text
                # store everything
                if proto not in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}

                scan_result['scan'][host][proto][port] = {'state': state,
                                                          'reason': reason,
                                                          'name': name,
                                                          'product': product,
                                                          'version': version,
                                                          'extrainfo': extrainfo,
                                                          'conf': conf,
                                                          'cpe': cpe}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.findall('script'):
                    script_id = dscript.get('id')
                    script_out = dscript.get('output')
                    if 'script' not in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out

            # <hostscript>
            #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
            #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
            #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
            # </hostscript>
            for dhostscript in dhost.findall('hostscript'):
                for dname in dhostscript.findall('script'):
                    hsid = dname.get('id')
                    hsoutput = dname.get('output')

                    if 'hostscript' not in list(scan_result['scan'][host].keys()):
                        scan_result['scan'][host]['hostscript'] = []

                    scan_result['scan'][host]['hostscript'].append(
                        {
                            'id': hsid,
                            'output': hsoutput
                            }
                        )

            # <osmatch name="Juniper SA4000 SSL VPN gateway (IVE OS 7.0)" accuracy="98" line="36241">
            # <osclass type="firewall" vendor="Juniper" osfamily="IVE OS" osgen="7.X"
            # accuracy="98"><cpe>cpe:/h:juniper:sa4000</cpe><cpe>cpe:/o:juniper:ive_os:7</cpe></osclass>
            # </osmatch>
            # <osmatch name="Cymphonix EX550 firewall" accuracy="98" line="17929">
            # <osclass type="firewall" vendor="Cymphonix" osfamily="embedded"
            # accuracy="98"><cpe>cpe:/h:cymphonix:ex550</cpe></osclass>
            # </osmatch>
            for dos in dhost.findall('os'):
                osmatch = []
                portused = []
                for dportused in dos.findall('portused'):
                    # <portused state="open" proto="tcp" portid="443"/>
                    state = dportused.get('state')
                    proto = dportused.get('proto')
                    portid = dportused.get('portid')
                    portused.append({
                        'state': state,
                        'proto': proto,
                        'portid': portid,
                    })

                scan_result['scan'][host]['portused'] = portused

                for dosmatch in dos.findall('osmatch'):
                    # <osmatch name="Linux 3.7 - 3.15" accuracy="100" line="52790">
                    name = dosmatch.get('name')
                    accuracy = dosmatch.get('accuracy')
                    line = dosmatch.get('line')

                    osclass = []
                    for dosclass in dosmatch.findall('osclass'):
                        # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                        ostype = dosclass.get('type')
                        vendor = dosclass.get('vendor')
                        osfamily = dosclass.get('osfamily')
                        osgen = dosclass.get('osgen')
                        accuracy = dosclass.get('accuracy')

                        cpe = []
                        for dcpe in dosclass.findall('cpe'):
                            cpe.append(dcpe.text)

                        osclass.append({
                            'type': ostype,
                            'vendor': vendor,
                            'osfamily': osfamily,
                            'osgen': osgen,
                            'accuracy': accuracy,
                            'cpe': cpe,
                        })

                    osmatch.append({
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        'osclass': osclass
                    })
                else:
                    scan_result['scan'][host]['osmatch'] = osmatch

            for dport in dhost.findall('osfingerprint'):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = dport.get('fingerprint')

                scan_result['scan'][host]['fingerprint'] = fingerprint

        self._scan_result = scan_result  # store for later use
        return scan_result

    def __getitem__(self, host):
        """
        returns a host detail
        """
        if sys.version_info[0] == 2:
            assert type(host) in (str, unicode), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        else:
            assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]

    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if 'scan' not in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh

    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'command_line' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['command_line']

    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scaninfo' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scaninfo']

    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scanstats']

    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False

    def csv(self):
        """
        returns CSV output as text

        Example :
        host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
        127.0.0.1;localhost;PTR;tcp;22;ssh;open;OpenSSH;protocol 2.0;syn-ack;5.9p1 Debian 5ubuntu1;10;cpe
        127.0.0.1;localhost;PTR;tcp;23;telnet;closed;;;conn-refused;;3;
        127.0.0.1;localhost;PTR;tcp;24;priv-mail;closed;;;conn-refused;;3;
        """
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if sys.version_info < (3, 0):
            fd = io.BytesIO()
        else:
            fd = io.StringIO()

        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = [
            'host',
            'hostname',
            'hostname_type',
            'protocol',
            'port',
            'name',
            'state',
            'product',
            'extrainfo',
            'reason',
            'version',
            'conf',
            'cpe'
            ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    hostname = ''
                    for h in self[host]['hostnames']:
                        hostname = h['name']
                        hostname_type = h['type']
                        csv_row = [
                            host, hostname, hostname_type,
                            proto, port,
                            self[host][proto][port]['name'],
                            self[host][proto][port]['state'],
                            self[host][proto][port]['product'],
                            self[host][proto][port]['extrainfo'],
                            self[host][proto][port]['reason'],
                            self[host][proto][port]['version'],
                            self[host][proto][port]['conf'],
                            self[host][proto][port]['cpe']
                        ]
                        csv_ouput.writerow(csv_row)

        return fd.getvalue()

############################################################################


def __scan_progressive__(self, hosts, ports, arguments, callback, sudo, timeout):
    """
    Used by PortScannerAsync for callback
    """
    for host in self._nm.listscan(hosts):
        try:
            scan_data = self._nm.scan(host, ports, arguments, sudo, timeout)
        except PortScannerError:
            scan_data = None

        if callback is not None:
            callback(host, scan_data)
    return

############################################################################


class PortScannerAsync(object):
    """
    PortScannerAsync allows to use nmap from python asynchronously
    for each host scanned, callback is called with scan result for the host

    """
    def __init__(self):
        """
        Initialize the module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        """
        self._process = None
        self._nm = PortScanner()
        return

    def __del__(self):
        """
        Cleanup when deleted

        """
        if self._process is not None:
            try:
                if self._process.is_alive():
                    self._process.terminate()
            except AssertionError:
                # Happens on python3.4
                # when using PortScannerAsync twice in a row
                pass

        self._process = None
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None, sudo=False, timeout=0):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about but get None as scan_data

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch nmap with sudo if true
        :param timeout: int, if > zero, will terminate scan after seconds, otherwise will wait indefintely

        """

        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, unicode, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
            assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(str(callback))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        self._process = Process(
            target=__scan_progressive__,
            args=(self, hosts, ports, arguments, callback, sudo, timeout)
            )
        self._process.daemon = True
        self._process.start()
        return

    def stop(self):
        """
        Stop the current scan process

        """
        if self._process is not None:
            self._process.terminate()
        return

    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout

        :param timeout: default = None, wait timeout seconds

        """
        assert type(timeout) in (int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    def still_scanning(self):
        """
        :returns: True if a scan is currently running, False otherwise

        """
        try:
            return self._process.is_alive()
        except:
            return False


############################################################################


class PortScannerYield(PortScannerAsync):
    """
    PortScannerYield allows to use nmap from python with a generator
    for each host scanned, yield is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        """
        PortScannerAsync.__init__(self)
        return

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, timeout=0):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about it

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch nmap with sudo if true
        :param timeout: int, if > zero, will terminate scan after seconds, otherwise will wait indefintely

        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo, timeout)
            except PortScannerError:
                scan_data = None
            yield (host, scan_data)
        return

    def stop(self):
        pass

    def wait(self, timeout=None):
        pass

    def still_scanning(self):
        pass


############################################################################


class PortScannerHostDict(dict):
    """
    Special dictionnary class for storing and accessing host scan result

    """
    def hostnames(self):
        """
        :returns: list of hostnames

        """
        return self['hostnames']

    def hostname(self):
        """
        For compatibility purpose...
        :returns: try to return the user record or the first hostname of the list hostnames

        """
        hostname = ''
        for h in self['hostnames']:
            if h['type'] == 'user':
                return h['name']
        else:
            if len(self['hostnames']) > 0 and 'name' in self['hostnames'][0]:
                return self['hostnames'][0]['name']
            else:
                return ''

        return hostname

    def state(self):
        """
        :returns: host state

        """
        return self['status']['state']

    def uptime(self):
        """
        :returns: host state

        """
        return self['uptime']

    def all_protocols(self):
        """
        :returns: a list of all scanned protocols

        """
        def _proto_filter(x):
            return x in ['ip', 'tcp', 'udp', 'sctp']

        lp = list(filter(_proto_filter, list(self.keys())))
        lp.sort()
        return lp

    def all_tcp(self):
        """
        :returns: list of tcp ports

        """
        if 'tcp' in list(self.keys()):
            ltcp = list(self['tcp'].keys())
            ltcp.sort()
            return ltcp
        return []

    def has_tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: True if tcp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('tcp' in list(self.keys())
            and port in list(self['tcp'].keys())):
            return True
        return False

    def tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: info for tpc port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self['tcp'][port]

    def all_udp(self):
        """
        :returns: list of udp ports

        """
        if 'udp' in list(self.keys()):
            ludp = list(self['udp'].keys())
            ludp.sort()
            return ludp
        return []

    def has_udp(self, port):
        """
        :param port: (int) udp port
        :returns: True if udp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('udp' in list(self.keys())
            and 'port' in list(self['udp'].keys())):
            return True
        return False

    def udp(self, port):
        """
        :param port: (int) udp port
        :returns: info for udp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['udp'][port]

    def all_ip(self):
        """
        :returns: list of ip ports

        """
        if 'ip' in list(self.keys()):
            lip = list(self['ip'].keys())
            lip.sort()
            return lip
        return []

    def has_ip(self, port):
        """
        :param port: (int) ip port
        :returns: True if ip port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('ip' in list(self.keys())
            and port in list(self['ip'].keys())):
            return True
        return False

    def ip(self, port):
        """
        :param port: (int) ip port
        :returns: info for ip port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['ip'][port]

    def all_sctp(self):
        """
        :returns: list of sctp ports

        """
        if 'sctp' in list(self.keys()):
            lsctp = list(self['sctp'].keys())
            lsctp.sort()
            return lsctp
        return []

    def has_sctp(self, port):
        """
        :returns: True if sctp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('sctp' in list(self.keys())
            and port in list(self['sctp'].keys())):
            return True
        return False

    def sctp(self, port):
        """
        :returns: info for sctp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['sctp'][port]

############################################################################


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)


############################################################################

def __get_last_online_version():
    """
    Gets last python-nmap published version

    WARNING : it does an http connection to http://xael.org/pages/python-nmap/python-nmap_CURRENT_VERSION.txt

    :returns: a string which indicate last published version (example :'0.4.3')

    """
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/pages/python-nmap/python-nmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version


############################################################################

def convert_nmap_output_to_encoding(value, code="ascii"):
    """
    Change encoding for scan_result object from unicode to whatever

    :param value: scan_result as dictionnary
    :param code: default = "ascii", encoding destination

    :returns: scan_result as dictionnary with new encoding
    """
    new_value = {}
    for k in value:
        if type(value[k]) in [dict, PortScannerHostDict]:
            new_value[k] = convert_nmap_output_to_encoding(value[k], code)
        else:
            if type(value[k]) is list:
                new_value[k] = [
                    convert_nmap_output_to_encoding(x, code) for x in value[k]
                ]
            else:
                new_value[k] = value[k].encode(code)
    return new_value

# <EOF>######################################################################
 


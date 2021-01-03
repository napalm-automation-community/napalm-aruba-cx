"""NAPALM driver for Aruba AOS-CX."""
# Copyright 2020 Hewlett Packard Enterprise Development LP. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import copy
import functools
import os
import re
import socket
import telnetlib
import tempfile
import uuid
import inspect
import logging
from collections import defaultdict

from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from netmiko import FileTransfer, InLineTransfer

# NAPALM Base libs
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ConnectionException,
    ReplaceConfigException,
    MergeConfigException,
    ConnectionClosedException,
    SessionLockedException,
    CommandErrorException,
)
from napalm.base.helpers import (
    canonical_interface_name,
    transform_lldp_capab,
    textfsm_extractor,
)
import napalm.base.constants as c

# Aruba AOS-CX lib
import pyaoscx
from pyaoscx import session, interface, system, common_ops, port, lldp, mac, vrf, arp

class AOSCXDriver(NetworkDriver):
    """NAPALM driver for Aruba AOS-CX."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Constructor for AOS-CX."""
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.platform = "aoscx"
        self.profile = [self.platform]
        self.session_info = {}
        self.isAlive = False
        self.candidate_config = ''

        self.base_url = "https://{0}/rest/v1/".format(self.hostname)

    def open(self):
        """
        Implementation of NAPALM method 'open' to open a connection to the device.
        """
        try:
            self.session_info = dict(s=pyaoscx.session.login(self.base_url, self.username,
                                                             self.password), url=self.base_url)
            self.isAlive = True
        except ConnectionError as error:
            # Raised if device not available or HTTPS REST is not enabled
            raise ConnectionException(str(error))

    def close(self):
        """
        Implementation of NAPALM method 'close'. Closes the connection to the device and does
        the necessary cleanup.
        """
        pyaoscx.session.logout(**self.session_info)
        self.isAlive = False

    def is_alive(self):
        """
        Implementation of NAPALM method 'is_alive'. This is used to determine if there is a
        pre-existing REST connection that must be closed.
        :return: Returns a flag with the state of the connection.
        """
        return {"is_alive": self.isAlive}

    def get_facts(self):
        """
        Implementation of NAPALM method 'get_facts'.  This is used to retrieve device information
        in a dictionary.
        :return: Returns a dictionary containing the following information:
         * uptime - Uptime of the device in seconds.
         * vendor - Manufacturer of the device.
         * model - Device model.
         * hostname - Hostname of the device
         * fqdn - Fqdn of the device
         * os_version - String with the OS version running on the device.
         * serial_number - Serial number of the device
         * interface_list - List of the interfaces of the device
        """
        systeminfo = pyaoscx.system.get_system_info(**self.session_info)
        productinfo = pyaoscx.system.get_product_info(**self.session_info)

        uptime_seconds = (int(systeminfo['boot_time']))/1000

        fact_info = {
            'uptime': uptime_seconds,
            'vendor': 'Aruba',
            'os_version': systeminfo['software_info']['build_id'],
            'serial_number': productinfo['product_info']['serial_number'],
            'model': productinfo['product_info']['product_name'],
            'hostname': systeminfo['hostname'],
            'fqdn':systeminfo['hostname'],
            'interface_list': pyaoscx.interface.get_all_interface_names(**self.session_info)
        }
        return fact_info

    def get_interfaces(self):
        """
        Implementation of NAPALM method 'get_interfaces'.  This is used to retrieve all interface
        information.  If the interface is a logical interface that does not have hardware info, the
        value will be 'N/A'.
        Note: 'last_flapped' is not implemented and will always return a default value of -1.0
        :return: Returns a dictionary of dictionaries. The keys for the first dictionary will be the
        interfaces in the devices. The inner dictionary will containing the following data for
        each interface:
         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * speed (int in Mbit)
         * MTU (in Bytes)
         * mac_address (string)
        """
        interfaces_return = {}
        interface_list = pyaoscx.interface.get_all_interface_names(**self.session_info)
        for line in interface_list:
            interface_details = pyaoscx.interface.get_interface(line, **self.session_info)
            if 'description' not in interface_details:
                interface_details['description'] = ""
            if 'max_speed' not in interface_details['hw_intf_info']:
                speed = 'N/A'
            else:
                speed = interface_details['hw_intf_info']['max_speed']
            if 'mtu' not in interface_details:
                mtu = 'N/A'
            else:
                mtu = interface_details['mtu']
            if 'mac_addr' not in interface_details['hw_intf_info']:
                mac_address = 'N/A'
            else:
                mac_address = interface_details['hw_intf_info']['mac_addr']
            interface_dictionary = {
                line: {
                    'is_up': (interface_details['link_state'] == "up"),
                    'is_enabled': (interface_details['admin_state'] == "up"),
                    'description': interface_details['description'],
                    'last_flapped': -1.0,
                    'speed': speed,
                    'mtu': mtu,
                    'mac_address': mac_address
                }
            }
            interfaces_return.update(interface_dictionary)

        return interfaces_return

    def get_interfaces_counters(self):
        """
        Implementation of NAPALM method get_interfaces_counters.  This gives statistic information
        for all interfaces that are on the switch.
        Note:  Not currently implementing tx_errors, rx_errors, rx_discards, and tx_discards, and
        those values will return -1.
        :return: Returns a dictionary of dictionaries where the first key is an interface name
        and the inner dictionary contains the following keys:

            * tx_errors (int)
            * rx_errors (int)
            * tx_discards (int)
            * rx_discards (int)
            * tx_octets (int)
            * rx_octets (int)
            * tx_unicast_packets (int)
            * rx_unicast_packets (int)
            * tx_multicast_packets (int)
            * rx_multicast_packets (int)
            * tx_broadcast_packets (int)
            * rx_broadcast_packets (int)
        """
        interface_stats_dictionary = {}
        interface_list = pyaoscx.interface.get_all_interface_names(**self.session_info)
        for line in interface_list:
            interface_details = pyaoscx.interface.get_interface(line, **self.session_info)
            print(interface_details['name'])
            interface_stats_dictionary.update(
                {
                    line: {
                        'tx_errors': -1,
                        'rx_errors': -1,
                        'tx_discards': -1,
                        'rx_discards': -1,
                        'tx_octets': interface_details['statistics']['tx_bytes'],
                        'rx_octets': interface_details['statistics']['rx_bytes'],
                        'tx_unicast_packets':
                            interface_details['statistics']['if_hc_out_unicast_packets'],
                        'rx_unicast_packets':
                            interface_details['statistics']['if_hc_in_unicast_packets'],
                        'tx_multicast_packets':
                            interface_details['statistics']['if_out_multicast_packets'],
                        'rx_multicast_packets':
                            interface_details['statistics']['if_in_multicast_packets'],
                        'tx_broadcast_packets':
                            interface_details['statistics']['if_out_broadcast_packets'],
                        'rx_broadcast_packets':
                            interface_details['statistics']['if_in_broadcast_packets']
                    }
                }
            )
        return interface_stats_dictionary

    def get_lldp_neighbors(self):
        """
        Implementation of NAPALM method 'get_lldp_neighbors'.  This is used to retrieve all
        lldp neighbor information.
        :return: Returns a dictionary where the keys are local ports and the value is a list of
        dictionaries with the following information:
            * hostname
            * port
        """
        lldp_brief_return = {}
        lldp_interfaces_list = pyaoscx.lldp.get_all_lldp_neighbors(**self.session_info)
        for interface_uri in lldp_interfaces_list:
            interface_name = interface_uri[interface_uri.find('interfaces/') + 11:
                                           interface_uri.rfind('/lldp_neighbors')]
            interface_name = pyaoscx.common_ops._replace_percents(interface_name)
            interface_details = \
                pyaoscx.lldp.get_lldp_neighbor_info(interface_name, **self.session_info)

            if interface_name not in lldp_brief_return.keys():
                lldp_brief_return[interface_name] = []

            lldp_brief_return[interface_name].append(
                {
                    'hostname': interface_details['neighbor_info']['chassis_name'],
                    'port:': interface_details['port_id']
                }
            )

        return lldp_brief_return

    def get_lldp_neighbors_detail(self, interface=""):
        """
        Implementation of NAPALM method get_lldp_neighbors_detail.
        :param interface: Alphanumeric Interface name (e.g. 1/1/1)
        :return: Returns a detailed view of the LLDP neighbors as a dictionary
        containing lists of dictionaries for each interface.

        Empty entries are returned as an empty string (e.g. '') or list where applicable.

        Inner dictionaries contain fields:

            * parent_interface (string)
            * remote_port (string)
            * remote_port_description (string)
            * remote_chassis_id (string)
            * remote_system_name (string)
            * remote_system_description (string)
            * remote_system_capab (list) with any of these values
                * other
                * repeater
                * bridge
                * wlan-access-point
                * router
                * telephone
                * docsis-cable-device
                * station
            * remote_system_enabled_capab (list)

        """
        lldp_interfaces = []
        lldp_details_return = {}
        if interface:
            lldp_interfaces.append(interface)
        else:
            lldp_interfaces_list = pyaoscx.lldp.get_all_lldp_neighbors(**self.session_info)
            for interface_uri in lldp_interfaces_list:
                interface_name = interface_uri[interface_uri.find('interfaces/') + 11:
                                               interface_uri.rfind('/lldp_neighbors')]
                interface_name = pyaoscx.common_ops._replace_percents(interface_name)
                lldp_interfaces.append(interface_name)

        for single_interface in lldp_interfaces:
            if single_interface not in lldp_details_return.keys():
                lldp_details_return[single_interface] = []

            interface_details = pyaoscx.lldp.get_lldp_neighbor_info(single_interface, **self.session_info)
            remote_capabilities = ''.join(
                [x.lower() for x in interface_details['neighbor_info']['chassis_capability_available']])
            remote_enabled = ''.join(
                [x.lower() for x in interface_details['neighbor_info']['chassis_capability_enabled']])
            lldp_details_return[single_interface].append(
                {
                    'parent_interface': single_interface,
                    'remote_chassis_id': interface_details['chassis_id'],
                    'remote_system_name': interface_details['neighbor_info']['chassis_name'],
                    'remote_port': interface_details['port_id'],
                    'remote_port_description':
                        interface_details['neighbor_info']['port_description'],
                    'remote_system_description':
                        interface_details['neighbor_info']['chassis_description'],
                    'remote_system_capab': remote_capabilities,
                    'remote_system_enable_capab':  remote_enabled
                    }
            )
        return lldp_details_return

    def get_environment(self):
        """
        Implementation of NAPALM method get_environment()
        :return: Returns a dictionary where:
            * fans is a dictionary of dictionaries where the key is the location and the values:
                 * status (True/False) - True if it's ok, false if it's broken
            * temperature is a dict of dictionaries where the key is the location and the values:
                 * temperature (float) - Temperature in celsius the sensor is reporting.
                 * is_alert (True/False) - True if the temperature is above the alert threshold
                 * is_critical (True/False) - True if the temp is above the critical threshold
            * power is a dictionary of dictionaries where the key is the PSU id and the values:
                 * status (True/False) - True if it's ok, false if it's broken
                 * capacity (float) - Capacity in W that the power supply can support
                 * output (float) - Watts drawn by the system (Not Supported)
            * cpu is a dictionary of dictionaries where the key is the ID and the values:
                 * %usage - Current percent usage of the device
            * memory is a dictionary with:
                 * available_ram (int) - Total amount of RAM installed in the device (Not Supported)
                 * used_ram (int) - RAM in use in the device
        """
        fan_details = self._get_fan_info(**self.session_info)
        fan_dict = {}
        for fan in fan_details:
            new_dict = {fan['name']: fan['status'] == 'ok'}
            fan_dict.update(new_dict)

        temp_details = self._get_temperature(**self.session_info)
        temp_dict = {}
        for sensor in temp_details:
            new_dict = {
                sensor['location']: {
                    'temperature': float(sensor['temperature']/1000),
                    'is_alert': sensor['status'] == 'critical',
                    'is_critical': sensor['status'] == 'emergency'
                }
            }
            temp_dict.update(new_dict)

        psu_details = self._get_power_supplies(**self.session_info)
        psu_dict = {}
        for psu in psu_details:
            new_dict = {
                psu['name']: {
                    'status': psu['status'] == 'ok',
                    'capacity': float(psu['characteristics']['maximum_power']),
                    'output': 'N/A'
                }
            }
            psu_dict.update(new_dict)

        resources_details = self._get_resource_utilization(**self.session_info)
        cpu_dict = {}
        mem_dict = {}
        for mm in resources_details:
            new_dict = {
                mm['name']: {
                    '%usage': mm['resource_utilization']['cpu']
                }
            }
            cpu_dict.update(new_dict)
            mem_dict = {
                'available_ram': 'N/A',
                'used_ram': mm['resource_utilization']['memory']
            }

        environment = {
            'fans': fan_dict,
            'temperature': temp_dict,
            'power': psu_dict,
            'cpu': cpu_dict,
            'memory': mem_dict
        }
        return environment

    def get_arp_table(self, vrf=""):
        """
        Implementation of NAPALM method get_arp_table.
        Note: 'age' not  implemented and defaults to 0.0
        :param vrf: Alphanumeric value of vrf for ARP table list. 'vrf' of null-string will default
        to all VRFs. Specific 'vrf' will return the ARP table entries for that VRFs (including
        potentially 'default' or 'global').
        In all cases the same data structure is returned and no reference to the VRF that was used
        is included in the output.
        :return: Returns a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)
        """
        arp_entries = []
        vrf_list = pyaoscx.vrf.get_all_vrfs(**self.session_info)
        if vrf in vrf_list:
            vrf_list = [vrf]
        for vrf_entry in vrf_list:
            #remove '/rest/v1/system/vrfs' from vrf name...
            myvrf = vrf_entry.replace('/rest/v1/system/vrfs/','')
            arp_list = pyaoscx.arp.get_arp_entries(myvrf, **self.session_info)
            for entry in arp_list:
                arp_entries.append(
                    {
                        'interface': entry['Physical Port'],
                        'mac': entry['MAC Address'],
                        'ip': entry['IPv4 Address'],
                        'age': 0.0
                    }
                )
        return arp_entries

    def get_interfaces_ip(self):
        """
        Implementation of NAPALM method get_interfaces_ip.  This retrieves all of the IP addresses
        on all interfaces.
        :return: Returns all configured IP addresses on all interfaces as a dictionary of
        dictionaries. Keys of the main dictionary represent the name of the interface.
        Values of the main dictionary represent are dictionaries that may consist of two keys
        'ipv4' and 'ipv6' (one, both or none) which are themselves dictionaries with the IP
        addresses as keys.
        Each IP Address dictionary has the following keys:
            * prefix_length (int)
        """
        interface_ip_dictionary = {}
        interface_list = pyaoscx.interface.get_all_interface_names(**self.session_info)
        for line in interface_list:
            interface_info = pyaoscx.port.get_port(line, **self.session_info)
            interface_ip_dictionary = {
                line: {}
            }

            try:

                if interface_info['ip4_address']:
                    # if interface_info.get('ip4_address'):
                    interface_ip_dictionary[line]['ipv4'] = {
                        interface_info['ip4_address'][:interface_info['ip4_address'].rfind('/')]: {
                            'prefix_length':
                                int(interface_info['ip4_address']
                                    [interface_info['ip4_address'].rfind('/') + 1:])
                        }
                    }
                if interface_info.get('ip6_addresses'):
                    for address in interface_info['ip6_addresses']:
                        if (interface_ip_dictionary.get(line)):
                            if (interface_ip_dictionary.get(line).get('ipv6')):
                                interface_ip_dictionary.get(line).get('ipv6').update(
                                    {
                                        address[:address.rfind('/')]: {
                                            'prefix_length': int(address[address.rfind('/') + 1:])
                                        }
                                    }
                                )
                if interface_info.get('ip6_address_link_local'):
                    for address_ll in interface_info['ip6_address_link_local']:
                        if interface_ip_dictionary.get(line):
                            if interface_ip_dictionary.get(line).get('ipv6'):
                                interface_ip_dictionary.get(line).get('ipv6').update(
                                    {
                                        address_ll[:address_ll.rfind('/')]: {
                                            'prefix_length': int(
                                                address_ll[address_ll.rfind('/') + 1:])
                                        }
                                    }
                                )
                if interface_info.get('ip6_autoconfigured_addresses'):
                    for address_auto in interface_info['ip6_autoconfigured_addresses']:
                        # if interface_
                        interface_ip_dictionary[line]['ipv6'].update(
                            {
                                address_auto[:address_auto.rfind('/')]: {
                                    'prefix_length': int(address_auto[address_auto.rfind('/') + 1:])
                                }
                            }
                        )
            except Exception as e:
                print(line)
                print(e)
        return interface_ip_dictionary

    def get_mac_address_table(self):
        """
        Implementation of NAPALM method get_mac_address_table.  This retrieves information of all
        entries of the MAC address table.
        Note: 'last_move' is not supported, and will default to None
        :return: Returns a lists of dictionaries. Each dictionary represents an entry in the
        MAC Address Table, having the following keys:
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)
        """
        mac_entries = []
        mac_list = pyaoscx.mac.get_all_mac_addresses_on_system(**self.session_info)
        for mac_uri in mac_list:
            full_uri = mac_uri[mac_uri.find('vlans/') + 6:]
            mac = pyaoscx.common_ops._replace_special_characters(full_uri[full_uri.rfind('/') + 1:])
            full_uri = full_uri[:full_uri.rfind('/')]
            mac_type = full_uri[full_uri.rfind('/') + 1:]
            full_uri = full_uri[:full_uri.rfind('/')]
            vlan = int(full_uri[:full_uri.rfind('/')])
            mac_info = pyaoscx.mac.get_mac_info(vlan, mac_type, mac, **self.session_info)
            mac_entries.append(
                {
                    'mac': mac,
                    'interface': mac_info['port'][mac_info['port'].rfind('/')+1],
                    'vlan': vlan,
                    'static': (mac_type == 'static'),
                    'active': True,
                    'moves': None,
                    'last_move': None
                }
            )
        return mac_entries

    def get_snmp_information(self):
        """
        Implementation of NAPALM method get_snmp_information.  This returns a dict of dicts containing SNMP
        configuration.
        :return: Returns a lists of dictionaries. Each inner dictionary contains these fields:
            * chassis_id (string)
            * community (dictionary with community string specific information)
                * acl (string) # acl number or name (Unsupported)
                * mode (string) # read-write (rw), read-only (ro) (Unsupported)
            * contact (string)
            * location (string)
        """
        snmp_dict = {
            "chassis_id": "",
            "community": {},
            "contact": "",
            "location": ""
        }

        systeminfo = pyaoscx.system.get_system_info(**self.session_info)
        productinfo = pyaoscx.system.get_product_info(**self.session_info)

        communities_dict = {}
        for community_name in systeminfo['snmp_communities']:
            communities_dict[community_name] = {
                'acl': '',
                'mode': ''
            }

        snmp_dict['chassis_id'] = productinfo['product_info']['serial_number']
        snmp_dict['community'] = communities_dict
        snmp_dict['contact'] = systeminfo['other_config']['system_contact']
        snmp_dict['location'] = systeminfo['other_config']['system_location']

        return snmp_dict

    def get_ntp_servers(self):
        """
        Implementation of NAPALM method get_ntp_servers.  Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Note: Inner dictionaries do not have yet any available keys.
        :return: A dictionary with keys that are the NTP associations.
        """
        return self._get_ntp_associations(**self.session_info)

    def get_config(self, retrieve="all", full=False):
        """
        Return the configuration of a device. Currently this is limited to JSON format

        :param retrieve: String to determine which configuration type you want to retrieve, default is all of them.
                              The rest will be set to "".
        :param full: Boolean to retrieve all the configuration. (Not supported)
        :return: The object returned is a dictionary with a key for each configuration store:
            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the candidate configuration.
            - startup(string) - Representation of the native startup configuration.
        """
        if retrieve not in ["running", "candidate", "startup", "all"]:
            raise Exception("ERROR: Not a valid option to retrieve.\nPlease select from 'running', 'candidate', "
                            "'startup', or 'all'")
        else:
            config_dict = {
                "running": "",
                "startup": "",
                "candidate": ""
            }
            if retrieve in ["running", "all"]:
                config_dict['running'] = self._get_json_configuration("running-config")
            if retrieve in ["startup", "all"]:
                config_dict['startup'] = self._get_json_configuration("startup-config")
            if retrieve in ["candidate", "all"]:
                config_dict['candidate'] = self.candidate_config

        return config_dict


    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT, size=c.PING_SIZE,
             count=c.PING_COUNT, vrf=c.PING_VRF):
        """
        Executes ping on the device and returns a dictionary with the result.  Currently only IPv4 is supported.

        :param destination: Host or IP Address of the destination
        :param source (optional): Source address of echo request (Not Supported)
        :param ttl (optional): Maximum number of hops (Not Supported)
        :param timeout (optional): Maximum seconds to wait after sending final packet
        :param size (optional): Size of request (bytes)
        :param count (optional): Number of ping request to send
        :return: Output dictionary that has one of following keys:
            * error
            * success - In case of success, inner dictionary will have the followin keys:
                * probes_sent (int)
                * packet_loss (int)
                * rtt_min (float)
                * rtt_max (float)
                * rtt_avg (float)
                * rtt_stddev (float)
                * results (list)
                    * ip_address (str)
                    * rtt (float)
        """
        ping_results = self._ping_destination(destination, is_ipv4=True, data_size=size, time_out=timeout,
                                              interval=2, reps=count, time_stamp=False, record_route=False,
                                              vrf=vrf, **self.session_info)

        full_results = ping_results['statistics']
        transmitted = 0
        loss = 0
        rtt_min = 0.0
        rtt_avg = 0.0
        rtt_max = 0.0
        rtt_mdev = 0.0

        lines = full_results.split('\n')
        for count, line in enumerate(lines):
            cell = line.split(' ')
            if count == 1:
                transmitted = cell[0]
                loss = cell[5]
                loss = int(loss[:-1]) #Shave off the %
            if count == 2:
                numbers = cell[3].split('/')
                rtt_min = numbers[0]
                rtt_avg = numbers[1]
                rtt_max = numbers[2]
                rtt_mdev = numbers[3]

        output_dict = {}
        results_list = []
        if loss < 100:
            results_list.append(
                {
                    'ip_address': destination,
                    'rtt': rtt_avg
                }
            )

            output_dict['success'] = {
                'probes_sent': transmitted,
                'packet_loss': loss,
                'rtt_min': rtt_min,
                'rtt_max': rtt_max,
                'rtt_avg': rtt_avg,
                'rtt_stddev': rtt_mdev,
                'results': results_list
            }
        else:
            output_dict['error'] = 'unknown host {}'.format(destination)

        return output_dict

    def _ping_destination(self, ping_target, is_ipv4=True, data_size=100, time_out=2, interval=2,
                          reps=5, time_stamp=False, record_route=False, vrf="default", **kwargs):
        """
        Perform a Ping command to a specified destination

        :param ping_target: Destination address as a string
        :param is_ipv4: Boolean True if the destination is an IPv4 address
        :param data_size: Integer for packet size in bytes
        :param time_out: Integer for timeout value
        :param interval: Integer for time between packets in seconds
        :param reps: Integer for the number of signals sent in repetition
        :param time_stamp: Boolean True if the time stamp should be included in the results
        :param record_route: Boolean True if the route taken should be recorded in the results
        :param vrf: String of the VRF name that the ping should be sent.  If using the Management VRF, set this to mgmt
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing fan information
        """

        target_url = kwargs["url"] + "ping?"
        print(str(ping_target))
        if not ping_target:
            raise Exception("ERROR: No valid ping target set")
        else:
            target_url += 'ping_target={}&'.format(str(ping_target))
            target_url += 'is_ipv4={}&'.format(str(is_ipv4))
            target_url += 'data_size={}&'.format(str(data_size))
            target_url += 'ping_time_out={}&'.format(str(time_out))
            target_url += 'ping_interval={}&'.format(str(interval))
            target_url += 'ping_repetitions={}&'.format(str(reps))
            target_url += 'include_time_stamp={}&'.format(str(time_stamp))
            target_url += 'record_route={}&'.format(str(record_route))
            if vrf == 'mgmt':
                target_url += 'mgmt=true'
            else:
                target_url += 'mgmt=false'

        response = kwargs["s"].get(target_url, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Ping failed with status code %d: %s"
                            % (response.status_code, response.text))
            ping_dict = {}
        else:
            logging.info("SUCCESS: Ping succeeded")
            ping_dict = response.json()

        return ping_dict

    def _get_fan_info(self, params={}, **kwargs):
        """
        Perform a GET call to get the fan information of the switch
        Note that this works for physical devices, not an OVA.

        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing fan information
        """

        target_url = kwargs["url"] + "system/subsystems/*/*/fans/*"

        response = kwargs["s"].get(target_url, params=params, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting dictionary of fan information failed with status code %d: %s"
                            % (response.status_code, response.text))
            fan_info_dict = {}
        else:
            logging.info("SUCCESS: Getting dictionary of fan information succeeded")
            fan_info_dict = response.json()

        return fan_info_dict

    def _get_temperature(self, params={}, **kwargs):
        """
        Perform a GET call to get the temperature information of the switch
        Note that this works for physical devices, not an OVA.

        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing temperature information
        """

        target_url = kwargs["url"] + "system/subsystems/*/*/temp_sensors/*"

        response = kwargs["s"].get(target_url, params=params, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting dictionary of temperature information failed with status code %d: %s"
                            % (response.status_code, response.text))
            temp_info_dict = {}
        else:
            logging.info("SUCCESS: Getting dictionary of temperature information succeeded")
            temp_info_dict = response.json()

        return temp_info_dict

    def _get_power_supplies(self, params={}, **kwargs):
        """
        Perform a GET call to get the power supply information of the switch
        Note that this works for physical devices, not an OVA.

        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing power supply information
        """

        target_url = kwargs["url"] + "system/subsystems/*/*/power_supplies/*"

        response = kwargs["s"].get(target_url, params=params, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting dictionary of PSU information failed with status code %d: %s"
                            % (response.status_code, response.text))
            temp_info_dict = {}
        else:
            logging.info("SUCCESS: Getting dictionary of PSU information succeeded")
            temp_info_dict = response.json()

        return temp_info_dict

    def _get_resource_utilization(self, params={}, **kwargs):
        """
        Perform a GET call to get the cpu, memory, and open_fds of the switch
        Note that this works for physical devices, not an OVA.

        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing resource utilization information
        """

        target_url = kwargs["url"] + "system/subsystems/management_module/*"

        response = kwargs["s"].get(target_url, params=params, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting dictionary of resource utilization info failed with status code %d: %s"
                            % (response.status_code, response.text))
            resources_dict = {}
        else:
            logging.info("SUCCESS: Getting dictionary of resource utilization information succeeded")
            resources_dict = response.json()

        return resources_dict

    def _get_ntp_associations(self, params={}, **kwargs):
        """
        Perform a GET call to get the NTP associations across all VRFs

        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: Dictionary containing all of the NTP associations on the switch
        """

        target_url = kwargs["url"] + "system/vrfs/*/ntp_associations"

        response = kwargs["s"].get(target_url, params=params, verify=False)

        associations_dict = {}
        for server_uri in response:
            server_name = server_uri[(server_uri.rfind('/') + 1):]  # Takes string after last '/'
            associations_dict[server_name] = {}

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting dictionary of resource utilization info failed with status code %d: %s"
                            % (response.status_code, response.text))
            associations_dict = {}
        else:
            logging.info("SUCCESS: Getting dictionary of resource utilization information succeeded")
            associations_dict = response.json()

        return associations_dict

    def _get_json_configuration(self, checkpoint="running-config", params={}, **kwargs):
        """
        Perform a GET call to retrieve a configuration file based off of the checkpoint name

        :param checkpoint: String name of the checkpoint configuration
        :param params: Dictionary of optional parameters for the GET request
        :param kwargs:
            keyword s: requests.session object with loaded cookie jar
            keyword url: URL in main() function
        :return: JSON format of the configuration
        """

        target_url = kwargs["url"] + "fullconfigs/{}".format(checkpoint)

        response = kwargs["s"].get(target_url, params=params, verify=False)

        if not common_ops._response_ok(response, "GET"):
            logging.warning("FAIL: Getting configuration checkpoint named %s failed with status code %d: %s"
                            % (checkpoint, response.status_code, response.text))
            configuration_json = {}
        else:
            logging.info("SUCCESS: Getting configuration checkpoint named %s succeeded" % checkpoint)
            configuration_json = response.json()

        return configuration_json

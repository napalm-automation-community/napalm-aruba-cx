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
import napalm.base.constants as C

# Aruba AOS-CX lib
import pyaoscx
from pyaoscx import session, interface, system, common_ops, port, lldp, mac

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
            interface_dictionary = {
                interface_name: {
                    [
                        {
                            'hostname': interface_details['neighbor_info']['chassis_name'],
                            'port:': interface_details['port_id']
                        }
                    ]
                }
            }
            lldp_brief_return.update(interface_dictionary)

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
        interface_details = pyaoscx.lldp.get_lldp_neighbor_info(interface, **self.session_info)
        remote_capabilities = [x.lower() for x in interface_details['chassis_capability_available']]
        remote_enabled = [x.lower() for x in interface_details['chassis_capability_enabled']]
        lldp_details_return = {
            interface: [
                {
                    'parent_interface': interface,
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
            ]
        }

        return lldp_details_return

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
            arp_list = pyaoscx.arp.get_arp_entries(vrf_entry, **self.session_info)
            for entry in arp_list:
                arp_entries.append(
                    {
                        'interface': entry['Physical Port'],
                        'mac': entry['MAC Address'],
                        'ip': entry['MAC Address'],
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


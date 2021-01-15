# Napalm-aruba-cx
[NAPALM][napalm-link] Driver implementation for AOS-CX Switches.

## Supported Devices
All AOS-CX devices are supported, however the AOS-CX switch firmware should be version 10.05 or later, as some modules 
may have not been properly tested in older versions.

## Current Support Functionality 
    * get_arp_table - Get the ARP table from a device.
    * get_config - Get configuration from the device.
    * get_facts - Get the version, serial number, vendor, model, and uptime from a device.
    * get_interfaces - Get list of interfaces from a device.
    * get_interfaces_ip - Get list of interface IP addresses from a device.
    * get_lldp_neighbors - Get the list of LLDP Neighbors from a device.
    * get_lldp_neighbors_detail - Get LLDP Neighbor details from a device.
    * get_mac_address_table - Get the MAC Address table from a device.
    * get_ntp_servers - Gets NTP information from a network device.
    * get_snmp_information - Get the SNMP information of a device.
    * is_alive - Check to see if the connection to the device is up.
    * ping - Execute a ping command from the device.
    
    Early versions of this driver will focus on the Get functions.  Configuration handling is in current development.

## Getting Started
For more information and guides to help get started, check out the [Aruba Developer Hub section for NAPALM][devhub-link]. 


## Prerequisites
The following software is required:
 - Python3
 - Pip
 - Python modules specified in `requirements.txt`
    - pyaoscx
    - requests
    - urllib3


## Installing
To install simply run:
```
pip3 install napalm-aruba-cx
```

### Switch configuration
The AOS-CX driver utilizes the REST API on the switches. 
Depending on the switch model, this may already be enabled.  If not, please use the CLI commands below to enable REST on
the specified VRF.

1) There must be a user on the switch who belongs to the "administrators group" and has a password set.  This user 
would then be allowed to access the REST API.  In the below example, replace the username "admin" and password 
"mypassword" with your own username and password respectively.
```
8320(config)# user admin group administrators password plaintext mypassword
```
2) Set the access mode for the HTTPS server to "read-write" and enable the HTTPS server on the VRF through which the 
client making the NAPALM calls can reach the switch.  In the below example, this specifies both the management VRF and 
the default VRF.
```
8320(config)# https-server rest access-mode read-write
8320(config)# https-server vrf default
8320(config)# https-server vrf mgmt
```

## Contributing
Please read [CONTRIBUTING](CONTRIBUTING.md) for details on our process for submitting issues and requests.

## License
This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details

[devhub-link]: https://developer.arubanetworks.com/aruba-aoscx/docs/getting-started-with-napalm
[napalm-link]: https://napalm-automation.net/

#!/usr/bin/env python3
# Carve packets


import binascii
import re

from Functions_and_test_suites.carve_ipv4 import carve_ipv4
from carve_arp import carve_arp


def carve_packets(data):
    """
    Tries to carve all supported packets found in data
    """
    hex_data = binascii.hexlify(data).upper()
    hex_data_len = len(hex_data)

    # Supported ethertypes:
    # 0x0800 Internet Protocol version 4 (IPv4)
    # 0x0806 Address Resolution Protocol (ARP) requests and responses
    ether_types = ['0800', '0806']

    raw_packets = []

    # Check for valid ethertypes being present in mempage
    if any(eth_type in hex_data for eth_type in ether_types):
        for eth_type in ether_types:
            for match in re.finditer(eth_type, hex_data):

                # Check that there is room for a potential packet before and after eth_type
                if 24 < match.start():

                    # Try to carve IPv4 packet
                    if eth_type == '0800':
                        raw_packets.append(carve_ipv4(hex_data, match.start(), match.end()))

                    # Try to carve ARP packet
                    if eth_type == '0806':
                        carve_arp(hex_data, match.start(), match.end())




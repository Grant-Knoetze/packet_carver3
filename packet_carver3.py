#!/usr/bin/env python3

# Import modules
import binascii
import datetime
import json
import logging
import os
import re
import socket
import sys

from volatility3.framework import interfaces, renderers

vollog = logging.getLogger(__name__)


# Define a class that inherits from PluginInterface
class PacketCarver(interfaces.plugins.PluginInterface):
    """Carve and analyse IPv4 and ARP packets in memory dump
    and analyse the carved packets"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name='poolscanner',
                                            component=poolscanner.PoolScanner,
                                            version=(1, 0, 0)),
            requirements.VersionRequirement(name='info', component=info.Info, version=(1, 0, 0)),
            requirements.VersionRequirement(name='verinfo', component=verinfo.VerInfo, version=(1, 0, 0)),
            requirements.BooleanRequirement(
                name='include-corrupt',
                description=
                "Radically eases result validation. This will show partially overwritten data. WARNING: the results "
                "are likely to include garbage and/or corrupt data. Be cautious!",
                default=False,
                optional=True),
        ]

    @classmethod
    def verify_ipv4_header(cls, ip_header_in_hex):
        """
        Internal helper function header checksum value and returns true if packet header is
        correct or false if incorrect, takes IP-header in hex string as arg
        Creds to: http://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python
        """

        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        def checksum(msg):
            s = 0
            for i in range(0, len(msg), 2):
                w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
                s = carry_around_add(s, w)
            return ~s & 0xffff

        try:
            ip_header_in_hex = [ip_header_in_hex[i:i + 2] for i in range(0, len(ip_header_in_hex), 2)]
            ip_header_in_hex = map(lambda x: int(x, 16), ip_header_in_hex)
            ip_header_in_hex = struct.pack("%dB" % len(ip_header_in_hex), *ip_header_in_hex)
            if checksum(ip_header_in_hex) == 0:
                return True
            else:
                return False

        except Exception as e:
            return False

    @classmethod
    def format_mac_address(cls, hex_mac):
        """
        Internal helper function for human MAC formatting
        """
        return ':'.join(s.encode('hex') for s in hex_mac.decode('hex'))

    @classmethod
    def add_pcap_packet_header(cls, raw_packet):
        """
        Internal helper function for adding correct packet header for pcaps packets
        """
        time_t_ts_sec = '00000000'
        uint32_ts_usec = '00000000'
        uint32_incl_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
        uint32_orig_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
        raw_packet_with_header = binascii.unhexlify(
            time_t_ts_sec + uint32_ts_usec + uint32_incl_len + uint32_orig_len + binascii.hexlify(raw_packet))

        return raw_packet_with_header

    @classmethod
    def is_ip(cls, ip):
        """
        Check IP address to confirm if IPV4
        """
        ipv4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return ipv4.match(ip)

    @classmethod
    def ips_not_to_test(cls, ip):
        """
        Function that tests to see if ip's are worth testing, ie: not loopback, internal, bogon etc
        """
        # 10.0.0.0 - 10.255.255.255
        if ip[:3] == '10.':
            return True

        # 172.16.0.0 - 172.31.255.255
        if ip[:4] == '172.' and ip[6:7] == '.' and int(ip[4:6]) in range(16, 31, 1):
            return True

        # 192.168.0.0 - 192.168.255.255
        if ip[:8] == '192.168.':
            return True

        # 255.255.255.255
        if ip == '255.255.255.255':
            return True

        # Multicast 224.0.0.0 - 239.255.255.255
        if int(ip[:3]) in range(224, 240, 1):
            return True

        # 0.0.0.0
        if ip == '0.0.0.0':
            return True

        return False


# We should figure out what we are returning

def run(self):
    filter_func = netscan.NetScan.create_networkobject_filter(self.config.get('packet', None))

    return renderers.TreeGrid([("Offset", format_hints.Hex),
                               ("Protocol", str),
                               ("LocalAddr", str),
                               ("LocalPort", int),
                               ("RemoteAddr", str),
                               ("RemotePort", str),
                               ("State", str),
                               ("PID", int),
                               ("Owner", str),
                               ("Created", str)],
                              self._generator(netscan.NetScan.list_networkobjects(self.context,
                                                                                  self.config['primary'],
                                                                                  self.config['nt_symbols'],
                                                                                  filter_func=filter_func)))


def _generator(self):
    pass

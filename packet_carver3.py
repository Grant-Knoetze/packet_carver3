#!/usr/bin/env python3

# Import modules
import binascii
import datetime
import json
import logging
import os
import re
import socket
import struct
import sys

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.plugins.windows import poolscanner, info, verinfo, netscan
from volatility3.framework.renderers import format_hints
from volatility3.framework.renderers import TreeGrid


# Define a class that inherits from PluginInterface
class PacketCarver(interfaces.plugins.PluginInterface):
    """Carve and analyse IPv4 and ARP packets in memory dump
    and analyse the carved packets"""

    def __int__(self):
        pass

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

    def verify_ipv4_header(self, ip_header_in_hex):
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

    def format_mac_address(self, hex_mac):
        """
        Internal helper function for human MAC formatting
        """
        return ':'.join(s.encode('hex') for s in hex_mac.decode('hex'))

    def add_pcap_packet_header(self, raw_packet):
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

    def is_ip(self, ip):
        """
        Check IP address to confirm if IPV4
        """
        ipv4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return ipv4.match(ip)

    def ips_not_to_test(self, ip):
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

    def carve_ipv4(self, hex_data, match_start, match_end):
        """Carve IPv4 packets from hex data"""
        packet_dict = dict()

        # Ethernet layer
        packet_dict['ethernet_header'] = hex_data[match_start - 24:match_end]
        packet_dict['ethernet_dst_mac'] = hex_data[match_start - 24:match_start - 12]
        packet_dict['ethernet_dst_mac_str'] = self.format_mac_address(packet_dict['ethernet_dst_mac'])
        packet_dict['ethernet_src_mac'] = hex_data[match_start - 12:match_start]
        packet_dict['ethernet_src_mac_str'] = self.format_mac_address(packet_dict['ethernet_src_mac'])
        packet_dict['ethernet_type'] = hex_data[match_start:match_start + 4]

        # IPv4 layer
        ip_header_begin = match_end

        packet_dict['ip_version'] = hex_data[match_end:ip_header_begin + 1]

        # Validate potential packet as an IPv4 packet

        if packet_dict['ip_version'] == '4':

            # Calculate offsets for IPv4 header length
            packet_dict['ip_header_len_int'] = int(hex_data[ip_header_begin + 1:ip_header_begin + 2], 16) * 4 * 2
            packet_dict['ip_header'] = hex_data[ip_header_begin:ip_header_begin + packet_dict['ip_header_len_int']]

            # Check that IPv4 header is above minimum lenght of 20 bytes
            if len(packet_dict['ip_header']) >= 40:

                # Verify checksum
                if self.verify_ipv4_header(packet_dict['ip_header']) is True:

                    packet_dict['ip_service_field'] = hex_data[ip_header_begin + 2:ip_header_begin + 4]

                    packet_dict['ip_total_lenght'] = int(hex_data[ip_header_begin + 4:ip_header_begin + 8], 16)

                    packet_dict['ip_layer'] = hex_data[match_end:ip_header_begin + packet_dict['ip_total_lenght'] * 2]

                    packet_dict['ip_identification'] = hex_data[ip_header_begin + 8:ip_header_begin + 12]

                    packet_dict['ip_flags'] = hex_data[ip_header_begin + 12:ip_header_begin + 16]

                    packet_dict['ip_ttl'] = hex_data[ip_header_begin + 16:ip_header_begin + 18]

                    packet_dict['ip_protocol'] = hex_data[ip_header_begin + 18:ip_header_begin + 20]

                    packet_dict['ip_header_checksum'] = hex_data[ip_header_begin + 20:ip_header_begin + 24]

                    packet_dict['ip_src'] = hex_data[ip_header_begin + 24:ip_header_begin + 32]

                    packet_dict['ip_src_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_src'], 16)))

                    packet_dict['ip_dst'] = hex_data[ip_header_begin + 32:ip_header_begin + 40]

                    packet_dict['ip_dst_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_dst'], 16)))

                    full_packet_data = packet_dict['ethernet_header'] + packet_dict['ip_layer']

                    self.hex_packets.append(full_packet_data)

                    # Parse TCP layer for src and dst ports
                    if packet_dict['ip_protocol'] == '06':

                        tcp_begin = ip_header_begin + packet_dict['ip_header_len_int']

                        packet_dict['src_port'] = hex_data[tcp_begin:tcp_begin + 4]

                        packet_dict['src_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])

                        packet_dict['dst_port'] = hex_data[tcp_begin + 4:tcp_begin + 8]

                        packet_dict['dst_port_str'] = str( struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])

                        self.parsed_packets.append(packet_dict)

                        # Parse UDP layer for src and dst ports
                    elif packet_dict['ip_protocol'] == '11':

                        udp_begin = ip_header_begin + packet_dict['ip_header_len_int']

                        packet_dict['src_port'] = hex_data[udp_begin:udp_begin + 4]

                        packet_dict['src_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])

                        packet_dict['dst_port'] = hex_data[udp_begin + 4:udp_begin + 8]

                        packet_dict['dst_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])

                        packet_dict['udp_len'] = hex_data[udp_begin + 8:udp_begin + 12]

                        packet_dict['udp_len_int'] = int(packet_dict['udp_len'], 16) * 2

                        packet_dict['udp_checksum'] = hex_data[udp_begin + 12:udp_begin + 16]

                        self.parsed_packets.append(packet_dict)

                    else:
                        self.parsed_packets.append(packet_dict)


def run(self):
    pass

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
                              self._generator())


def generator(self):
    pass

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
from volatility3.framework.plugins.windows import netscan
from volatility3.plugins.windows import *
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


# Define a class that inherits from PluginInterface
class PacketCarver(interfaces.plugins.PluginInterface):
    """Carve and analyse IPv4 and ARP packets in memory dump
    and analyse the carved packets"""

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols",
                                                    description="Windows kernel symbols"),
                requirements.PluginRequirement(name='pslist',
                                               plugin=pslist.PsList,
                                               version=(1, 0, 0)),
                requirements.PluginRequirement(name='netstat',
                                               plugin=netstat.NetStat,
                                               version=(1, 0, 0)),
                requirements.PluginRequirement(name='netscan',
                                               plugin=netscan.NetScan,
                                               version=(1, 0, 0)),
                requirements.ListRequirement(name='pid',
                                             element_type=int,
                                             description="Process IDs to include (all other processes are excluded)",
                                             optional=True)]
    @classmethod
    def _verify_ipv4_header(cls, ip_header_in_hex):
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

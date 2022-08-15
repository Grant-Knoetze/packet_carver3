#!/usr/bin/env python3

# Import modules
import binascii
import datetime
import json
import os
import re
import socket
import sys

from volatility3.framework import interfaces, renderers
from volatility3.framework.plugins.windows import netscan
from volatility3.plugins.windows import *
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility


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
                requirements.PluginRequirement(name='netstat',
                                               plugin=netscan.NetScan,
                                               version=(1, 0, 0)),
                requirements.PluginRequirement(name='netstat',
                                               plugin=netscan.NetScan,
                                               version=(1, 0, 0)),
                requirements.ListRequirement(name='pid',
                                             element_type=int,
                                             description="Process IDs to include (all other processes are excluded)",
                                             optional=True)]

# Define the plugin requirements.

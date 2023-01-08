#!/usr/bin/env python3

import unittest

from add_pcap_packet_header import add_pcap_packet_header


class TestAddPcapPacketHeader(unittest.TestCase):
    testcases = '001122334455'
    expected = '00:11:22:33:44:55'

    def test_add_pcap_packet_header(self):
        self.assertEqual(add_pcap_packet_header('001122334455'), '00:11:22:33:44:55')
        print('test_add_pcap_packet_header passed')

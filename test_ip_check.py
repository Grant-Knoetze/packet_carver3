#!/usr/bin/env python3
# Test suite for the packet_carver3.py script

from packet_carver3 import is_ip


import unittest


class TestPacketCarve(unittest.TestCase):
    def test_ip(self):
        testcase = "192.168.1.2"
        expected = "match object"
        """Unit test to test the is_ip function from
            the packet_carver3 script"""
        self.assertEqual(is_ip(testcase), expected)






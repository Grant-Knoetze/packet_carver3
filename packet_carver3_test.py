#!/usr/bin/env python3


from packet_carver3 import is_ip

import unittest


class TestPacketCarve(unittest.TestCase):
    def test_basic(self):
        testcase = "192.168.1.2"
        expected = "match object"
        """Unit test to test the is_ip function from
            the packet_carver3 script"""
        self.assertEqual(is_ip(testcase), expected)

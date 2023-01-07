#!usr/bin/env python3

# Test suite for the packet_carver3.py script

from ip_not_to_test import ips_not_to_test

import unittest


class TestPacketCarve(unittest.TestCase):
    def test_ips_1(self):
        testcase = "10.255.255.255"
        expected = True
        """Unit test to test the ips_not_to_test function from"""
        self.assertEqual(ips_not_to_test(testcase), expected)

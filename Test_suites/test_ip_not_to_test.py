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
        if expected == True:
            print("IP is not worth testing")

    def test_ips_2(self):
        testcase = "192.168.1.1"
        expected = False
        """Unit test to test the ips_not_to_test function for a valid IP"""
        self.assertEqual(ips_not_to_test(testcase), expected)
        if expected == False:
            print("IP is worth testing")

#!/usr/bin/env python3

# Test suite for verify_ip function.

from verify_ip_header import verify_ipv4_header

import unittest


class TestPacketCarve(unittest.TestCase):
    def test_ips_1(self):
        testcase = "4500003c000000004011c4a7c0a80101c0a80102"
        expected = True
        """Unit test to test the ips_not_to_test function from"""
        self.assertEqual(verify_ipv4_header(testcase), expected)
        if expected:
            print("IP is worth testing")
        else:
            print("IP is not worth testing")

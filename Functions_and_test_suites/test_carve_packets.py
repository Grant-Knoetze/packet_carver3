#!/usr/bin/env python3

# Test suite for carve_ipv4 function.

import unittest

from Functions_and_test_suites.carve_ipv4 import carve_ipv4


class TestCarveIpv4(unittest.TestCase):

    def test_carveipv4(self):
        """Test carve_ipv4 function"""
        testcase = '4e4f4e45000000000000000008004500002e0000000040110000c0a80101c0a80101'
        expected = True
        self.assertEqual(carve_ipv4(testcase), expected)

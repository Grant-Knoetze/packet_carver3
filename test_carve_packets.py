#!/usr/bin/env python3

import unittest
from carve_packets import carve_packets


class TestCarvePackets(unittest.TestCase):
    def test_carve_packets(self):
            testcase = "4e4f4e45000000000000000008004500002e0000000040110000c0a80101c0a80101"
            expected = "0800"
            self.assertEqual(carve_packets(testcase), expected)
            return True


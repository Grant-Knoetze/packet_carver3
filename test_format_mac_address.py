#!usr/bin/env python3


import unittest

from format_mac_address import format_mac_address


class TestFormatMacAddress(unittest.TestCase):
    testcases = '001122334455'
    expected = '00:11:22:33:44:55'

    def test_format_mac_address(self):
        self.assertEqual(format_mac_address('001122334455'), '00:11:22:33:44:55')

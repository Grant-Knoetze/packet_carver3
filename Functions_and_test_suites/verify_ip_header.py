#!/usr/bin/env python3
import struct


# Verify IPV4 header.

def verify_ipv4_header(ip_header_in_hex):
    """
    Internal helper function header checksum value and returns true if packet header is
    correct or false if incorrect, takes IP-header in hex string as arg
    Creds to: http://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python
    """

    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    def checksum(msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            s = carry_around_add(s, w)
        return ~s & 0xffff

    try:
        ip_header_in_hex = [ip_header_in_hex[i:i + 2] for i in range(0, len(ip_header_in_hex), 2)]
        ip_header_in_hex = map(lambda x: int(x, 16), ip_header_in_hex)
        ip_header_in_hex = struct.pack("%dB" % len(ip_header_in_hex), *ip_header_in_hex)
        if checksum(ip_header_in_hex) == 0:
            return True
        else:
            return False

    except Exception as e:
        return False


print(verify_ipv4_header("4500003c000000004011c4a7c0a80101c0a80102"))

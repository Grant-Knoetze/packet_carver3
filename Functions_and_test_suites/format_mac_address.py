#!/usr/bin/env python3

# Format MAC address

def format_mac_address(hex_mac):
    """
    Internal helper function for human MAC formatting
    """
    return ':'.join(s.encode('hex') for s in hex_mac.decode('hex'))




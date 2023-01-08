#!usr/bin/env python3
import binascii
import struct


# Add pcap packet header

def add_pcap_packet_header(raw_packet):
    """
    Internal helper function for adding correct packet header for pcaps packets
    """
    time_t_ts_sec = '00000000'
    uint32_ts_usec = '00000000'
    uint32_incl_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
    uint32_orig_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
    raw_packet_with_header = binascii.unhexlify(
        time_t_ts_sec + uint32_ts_usec + uint32_incl_len + uint32_orig_len + binascii.hexlify(raw_packet))

    return raw_packet_with_header

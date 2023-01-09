#!/usr/bin/env python3
import socket
import struct


def carve_arp(self, hex_data, match_start, match_end):
    """
    Internal function for carving and validating ARP packets
    """
    packet_dict = dict()

    # Ethernet layer
    packet_dict['ethernet_header'] = hex_data[match_start - 24:match_end]
    packet_dict['ethernet_dst_mac'] = hex_data[match_start - 24:match_start - 12]
    packet_dict['ethernet_dst_mac_str'] = self._format_mac_address(packet_dict['ethernet_dst_mac'])
    packet_dict['ethernet_src_mac'] = hex_data[match_start - 12:match_start]
    packet_dict['ethernet_src_mac_str'] = self._format_mac_address(packet_dict['ethernet_src_mac'])
    packet_dict['ethernet_type'] = hex_data[match_start:match_start + 4]

    # ARP layer
    arp_header_begin = match_end
    packet_dict['arp_layer'] = hex_data[match_end:match_end + 52]
    packet_dict['arp_hardware_type'] = hex_data[match_end:match_end + 4]
    valid_arp_hardware_types = ['0001']

    if any(i in packet_dict['arp_hardware_type'] for i in valid_arp_hardware_types):

        packet_dict['arp_protocol'] = hex_data[arp_header_begin + 4:arp_header_begin + 8]

        # Valid ARP protocols
        valid_arp_protocols = ['0800']

        if any(i in packet_dict['arp_protocol'] for i in valid_arp_protocols):
            packet_dict['arp_hardware_length'] = hex_data[arp_header_begin + 8:arp_header_begin + 10]

            # Valid hardware ARP-addresses
            valid_arp_hardware_lengths = ['06']

            if any(i in packet_dict['arp_hardware_length'] for i in valid_arp_hardware_lengths):

                packet_dict['arp_protocol_len'] = hex_data[arp_header_begin + 10:arp_header_begin + 12]

                valid_arp_protocol_lens = ['04']

                if any(i in packet_dict['arp_protocol_len'] for i in valid_arp_protocol_lens):
                    packet_dict['arp_operation'] = hex_data[arp_header_begin + 12:arp_header_begin + 16]

                    # 0001 = request
                    # 0002 = reply
                    valid_arp_operations = ['0001', '0002']

                    if any(i in packet_dict['arp_operation'] for i in valid_arp_operations):
                        packet_dict['arp_sender_hardware_address'] = hex_data[
                                                                     arp_header_begin + 16:arp_header_begin + 28]
                        packet_dict['arp_sender_hardware_address_str'] = self._format_mac_address(
                            packet_dict['arp_sender_hardware_address'])
                        packet_dict['arp_sender_ip_address'] = hex_data[arp_header_begin + 28:arp_header_begin + 36]
                        packet_dict['arp_sender_ip_address_str'] = socket.inet_ntoa(
                            struct.pack('!I', int(packet_dict['arp_sender_ip_address'], 16)))
                        packet_dict['arp_target_hardware_address'] = hex_data[
                                                                     arp_header_begin + 36:arp_header_begin + 48]
                        packet_dict['arp_target_hardware_address_str'] = self._format_mac_address(
                            packet_dict['arp_target_hardware_address'])
                        packet_dict['arp_target_ip_address'] = hex_data[arp_header_begin + 48:arp_header_begin + 56]
                        packet_dict['arp_target_ip_address_str'] = socket.inet_ntoa(
                            struct.pack('!I', int(packet_dict['arp_target_ip_address'], 16)))

                        full_packet_data = packet_dict['ethernet_header'] + packet_dict['arp_layer']
                        full_packet_data_len = len(full_packet_data)

                        # Check if packet needs padding
                        if full_packet_data_len < 128:
                            padding = (128 - full_packet_data_len) * '0'
                            full_packet_data = packet_dict['ethernet_header'] + packet_dict['arp_layer'] + padding

                        self.hex_packets.append(full_packet_data)
                        self.parsed_packets.append(packet_dict)

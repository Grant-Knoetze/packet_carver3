#!/usr/bin/env python3

# Carve IPv4 packets from memory dump.
import socket
import struct
import binascii


def carve_ipv4(self, hex_data, match_start, match_end):
    """Carve IPv4 packets from hex data"""
    packet_dict = dict()

    # Ethernet layer
    packet_dict['ethernet_header'] = hex_data[match_start - 24:match_end]
    packet_dict['ethernet_dst_mac'] = hex_data[match_start - 24:match_start - 12]
    packet_dict['ethernet_dst_mac_str'] = format_mac_address(packet_dict['ethernet_dst_mac'])
    packet_dict['ethernet_src_mac'] = hex_data[match_start - 12:match_start]
    packet_dict['ethernet_src_mac_str'] = format_mac_address(packet_dict['ethernet_src_mac'])
    packet_dict['ethernet_type'] = hex_data[match_start:match_start + 4]

    # IPv4 layer
    ip_header_begin = match_end

    packet_dict['ip_version'] = hex_data[match_end:ip_header_begin + 1]

    # Validate potential packet as an IPv4 packet

    if packet_dict['ip_version'] == '4':

        # Calculate offsets for IPv4 header length
        packet_dict['ip_header_len_int'] = int(hex_data[ip_header_begin + 1:ip_header_begin + 2], 16) * 4 * 2
        packet_dict['ip_header'] = hex_data[ip_header_begin:ip_header_begin + packet_dict['ip_header_len_int']]

        # Check that IPv4 header is above minimum lenght of 20 bytes
        if len(packet_dict['ip_header']) >= 40:

            # Verify checksum
            if verify_ipv4_header(packet_dict['ip_header']) is True:

                packet_dict['ip_service_field'] = hex_data[ip_header_begin + 2:ip_header_begin + 4]

                packet_dict['ip_total_lenght'] = int(hex_data[ip_header_begin + 4:ip_header_begin + 8], 16)

                packet_dict['ip_layer'] = hex_data[match_end:ip_header_begin + packet_dict['ip_total_lenght'] * 2]

                packet_dict['ip_identification'] = hex_data[ip_header_begin + 8:ip_header_begin + 12]

                packet_dict['ip_flags'] = hex_data[ip_header_begin + 12:ip_header_begin + 16]

                packet_dict['ip_ttl'] = hex_data[ip_header_begin + 16:ip_header_begin + 18]

                packet_dict['ip_protocol'] = hex_data[ip_header_begin + 18:ip_header_begin + 20]

                packet_dict['ip_header_checksum'] = hex_data[ip_header_begin + 20:ip_header_begin + 24]

                packet_dict['ip_src'] = hex_data[ip_header_begin + 24:ip_header_begin + 32]

                packet_dict['ip_src_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_src'], 16)))

                packet_dict['ip_dst'] = hex_data[ip_header_begin + 32:ip_header_begin + 40]

                packet_dict['ip_dst_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_dst'], 16)))

                full_packet_data = packet_dict['ethernet_header'] + packet_dict['ip_layer']

                self.hex_packets.append(full_packet_data)

                # Parse TCP layer for src and dst ports
                if packet_dict['ip_protocol'] == '06':

                    tcp_begin = ip_header_begin + packet_dict['ip_header_len_int']

                    packet_dict['src_port'] = hex_data[tcp_begin:tcp_begin + 4]

                    packet_dict['src_port_str'] = str(
                        struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])

                    packet_dict['dst_port'] = hex_data[tcp_begin + 4:tcp_begin + 8]

                    packet_dict['dst_port_str'] = str(
                        struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])

                    self.parsed_packets.append(packet_dict)

                    # Parse UDP layer for src and dst ports
                elif packet_dict['ip_protocol'] == '11':

                    udp_begin = ip_header_begin + packet_dict['ip_header_len_int']

                    packet_dict['src_port'] = hex_data[udp_begin:udp_begin + 4]

                    packet_dict['src_port_str'] = str(
                        struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])

                    packet_dict['dst_port'] = hex_data[udp_begin + 4:udp_begin + 8]

                    packet_dict['dst_port_str'] = str(
                        struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])

                    packet_dict['udp_len'] = hex_data[udp_begin + 8:udp_begin + 12]

                    packet_dict['udp_len_int'] = int(packet_dict['udp_len'], 16) * 2

                    packet_dict['udp_checksum'] = hex_data[udp_begin + 12:udp_begin + 16]

                    self.parsed_packets.append(packet_dict)

                else:
                    self.parsed_packets.append(packet_dict)

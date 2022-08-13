# packet_carver3
This project is an attempt at creating a tool for extracting a packet capture from a memory dump in Volatility3, and will be put forward as a community plugin for Volatility3 by the students of the Maltrak Master of Cybersecurity program 2022.

We have noticed that there is no community plugin for extracting a pcap file from a memory dump in Volatility3. We have decided to study the carve_packet.py community plugin from Volatility that is written in python 2, and create our own Python3 plugin for Volatility3 that will perform the same operation and extract a packet capture from the memory dump, which can then be analysed in a tool such as Wireshark.

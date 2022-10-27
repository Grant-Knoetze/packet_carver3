# packet_carver3

This project is an attempt at creating a tool for extracting a packet capture from a memory dump in Volatility3, and will be put forward as a community plugin for       Volatility3 by the students of the Maltrak Master of Cybersecurity program 2022.

We have noticed that there is no community plugin for extracting a pcap file from a memory dump in Volatility3. There is a Python 2 community plugin for Volatility written by Nichlas Holm https://github.com/Memoryforensics.

We have decided to create our own Python3 plugin for Volatility3 that will perform the operation, and extract a packet capture from the memory dump, which can then be analysed in a tool such as Wireshark.

The main challenge is writing the plugin according to the Volatility 3 framework, to create this plugin, the Volatility 3 framework is more object oriented. We have create our packet_carver class, and all functions within the script are classmethods of the packet_carver class.

Credit to Nichlas Holm https://github.com/volatilityfoundation/community/tree/master/NichlasHolm. We studied this code and implemented our own Python 3 code to
perform packet carving and analysis.

This is a work in progress by cybersecurity students, for the cybersecurity community, once it is ready, we will fork the Volatility repo and create a pull request.


* packet_carver3.py is our implementation of a packet carver plugin for Volatility3.

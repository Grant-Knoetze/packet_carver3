# packet_carver3

This project is an attempt at creating a tool for carving and analysing network packets from a memory dump in Volatility3, and will be put forward for acceptance as a community plugin for Volatility3 by the students of the Maltrak Master of Cybersecurity program for 2022.

We have noticed that there is no community plugin for carving and analysing IPV4 and ARP packets in  Volatility3. There is a Python 2 community plugin for Volatility written by Nichlas Holm https://github.com/Memoryforensics.

The main challenge is writing the plugin according to the Volatility 3 framework.

Credit to Nichlas Holm https://github.com/volatilityfoundation/community/tree/master/NichlasHolm. We studied this code and implemented our own Python 3 code to
perform packet carving and analysis.

This is a work in progress by cybersecurity students, for the cybersecurity community, once it is ready, we will fork the Volatility repo and create a pull request.


* packet_carver3.py is our implementation of a packet carver plugin for Volatility3.
* This repository contains test suites for the static functions found in the main script packet_carver3.py.
* This code is free and open source. We welcome contributions and feedback.

# -*- coding: utf-8 -*-
"""stream pcap file extractor

``jspcap`` is an independent open source library, using only
```jsformat`` <https://github.com/JarryShaw/jsformat>`__ as
its formatted output dumper.

    There is a project called
    ```jspcapy`` <https://github.com/JarryShaw/jspcapy>`__
    works on ``jspcap``, which is a command line tool for
    PCAP extraction.

Unlike popular PCAP file extractors, such as ``Scapy``,
``dkpt``, ``pyshark``, and etc, ``jspcap`` uses streaming
strategy to read input files. That is to read frame by
frame, decrease occupation on memory, as well as enhance
efficiency in some way.

In ``jspcap``, all files can be described as following five
parts.

-  Extraction (``jspcap.extractor``)
    synthesise file I/O and protocol analysis, coordinate
    information exchange in all network layers

-  Reassembly (``jspcap.reassembly``)
    base on algorithms described in
   ```RFC 815`` <https://tools.ietf.org/html/rfc815>`__,
   implement datagram reassembly of IP and TCP packets

-  Protocls (``jspcap.protocols``)
    collection of all protocol family, with detailed
    implementation and methods

-  Utilities (``jspcap.utilities``)
    collection of four utility functions and classes

-  Exceptions (``jspcap.exceptions``)
    collection of refined custom exceptions

"""
# Extraction
from jspcap.extractor import Extractor

# Analysis
from jspcap.analyser import analyse

# Reassembly
from jspcap.reassembly import *

# Protocols
from jspcap.protocols import *


__all__ = [
    'Extractor',                                        # Extraction
    'analyse',                                          # Analysis
    'Header', 'Frame',                                  # Headers
    'ARP', 'Ethernet', 'L2TP', 'OSPF', 'RARP', 'VLAN',  # Link Layer
    'AH', 'IP', 'IPX',                                  # Internet Layer
    'TCP', 'UDP',                                       # Transport Layer
    'HTTP',                                             # Application Layer
    'IPv4_Reassembly', 'IPv6_Reassembly',               # IP Reassembly
    'TCP_Reassembly',                                   # TCP Reassembly
]

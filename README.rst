.. _header-n0:

jspcap
======

 The ``jspcap`` project is an open source Python program focus on
`PCAP <https://en.wikipedia.org/wiki/Pcap>`__ parsing and analysis,
which works as a stream pcap file extractor. With support of
```jsformat`` <https://github.com/JarryShaw/jsformat>`__, it shall
support multiple output report formats.

    Note that the whole project only supports **Python 3.6** or later.

-  `About <#header-n34>`__

   -  Extraction

   -  Reassembly

   -  Protocols

   -  Utilities

   -  Exceptions

-  `Installation <#header-n64>`__

-  `Usage <#header-n71>`__

--------------

.. _header-n34:

About
-----

 ``jspcap`` is an independent open source library, using only
```jsformat`` <https://github.com/JarryShaw/jsformat>`__ as its
formatted output dumper.

    There is a project called
    ```jspcapy`` <https://github.com/JarryShaw/jspcapy>`__ works on
    ``jspcap``, which is a command line tool for PCAP extraction.

 Unlike popular PCAP file extractors, such as ``Scapy``, ``dkpt``,
``pyshark``, and etc, ``jspcap`` uses **streaming** strategy to read
input files. That is to read frame by frame, decrease occupation on
memory, as well as enhance efficiency in some way.

 In ``jspcap``, all files can be described as following five parts.

-  Extraction (``jspcap.extractor``) -- synthesise file I/O and protocol
   analysis, coordinate information exchange in all network layers

-  Reassembly (``jspcap.reassembly``) -- base on algorithms described in
   ```RFC 815`` <https://tools.ietf.org/html/rfc815>`__, implement
   datagram reassembly of IP and TCP packets

-  Protocls (``jspcap.protocols``) -- collection of all protocol family,
   with detailed implementation and methods

-  Utilities (``jspcap.utilities``) -- collection of four utility
   functions and classes

-  Exceptions (``jspcap.exceptions``) -- collection of refined custom
   exceptions

.. figure:: ./doc/jspcap.png
   :alt:

.. _header-n64:

Installation
------------

    Note that ``jspcap`` only supports Python verions **since 3.6**

.. code::

    pip install jspcap

.. _header-n71:

Usage
-----

 You may find usage sample in the
```test`` <https://github.com/JarryShaw/jspcap/tree/master/test>`__
folder. For further information, please refer to the source code -- the
docstrings should help you :)

**ps**: ``help`` function in Python should always help you out.

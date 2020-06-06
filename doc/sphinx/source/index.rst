.. PyPCAPKit documentation master file, created by
   sphinx-quickstart on Sat Mar 28 21:29:54 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PyPCAPKit's documentation!
=====================================

The :mod:`PyPCAPKit <pcapkit>` project is an open source Python program focus
on `PCAP`_ parsing and analysis, which works as a stream PCAP file extractor.
With support of :mod:`DictDumper <dictdumper>`, it shall support multiple
output report formats.

.. important::

   The whole project supports **Python 3.4** or later.

.. toctree::
   :maxdepth: 2

   pcapkit
   cli

-----
About
-----

:mod:`PyPCAPKit <pcapkit>` is an independent open source library, using only
:mod:`DictDumper <dictdumper>` as its formatted output dumper.

.. note::

   There is a project called |jspcapy|_ works on :mod:`pcapkit`, which is a
   command line tool for PCAP extraction but now ***DEPRECATED***.

   .. |jspcapy| replace:: ``jspcapy``
   .. _jspcapy: https://github.com/JarryShaw/jspcapy

Unlike popular PCAP file extractors, such as :mod:`Scapy <scapy>`,
:mod:`dpkt <dpkt>`, :mod:`PyShark <pyshark>`, and etc, :mod:`pcapkit` uses
**streaming** strategy to read input files. That is to read frame by frame,
decrease occupation on memory, as well as enhance efficiency in some way.

Module Structure
----------------

In :mod:`pcapkit`, all files can be described as following eight parts.

- Interface (:mod:`pcapkit.interface`)

  User interface for the :mod:`pcapkit` library, which standardise and
  simplify the usage of this library.

- Foundation (:mod:`pcapkit.foundation`)

  Synthesise file I/O and protocol analysis, coordinate information
  exchange in all network layers.

- Reassembly (:mod:`pcapkit.reassembly`)

  Based on algorithms described in :rfc:`815`, implement datagram reassembly
  of IP and TCP packets.

- Protocols (:mod:`pcapkit.protocols`)

  Collection of all protocol family, with detail implementation and methods,
  as well as constructors.

- CoreKit (:mod:`pcapkit.corekit`)

  Core utilities for :mod:`pcapkit` implementation.

- TookKit (:mod:`pcapkit.toolkit`)

  Compatibility tools for :mod:`pcapkit` implementation.

- DumpKit (:mod:`pcapkit.dumpkit`

  Dump utilities for :mod:`pcapkit` implementation.

- Utilities (:mod:`pcapkit.utilities`)

  Collection of four utility functions and classes.

Engine Comparison
-----------------

Besides, due to complexity of :mod:`pcapkit`, its extraction procedure takes
around *0.0009* seconds per packet, which is not ideal enough. Thus
:mod:`pcapkit` introduced alternative extractionengines to accelerate this
procedure. By now :mod:`pcapkit` supports `Scapy`_, `DPKT`_, and `PyShark`_.
Plus, :mod:`pcapkit` supports two strategies of multiprocessing (``server`` &
``pipeline``). For more information, please refer to the documentation.

Test Environment
~~~~~~~~~~~~~~~~

.. list-table::

   * - Operating System
     - macOS Mojave
   * - Processor Name
     - Intel Core i7
   * - Processor Speed
     - 2.6 GHz
   * - Total Number of Cores
     - 6
   * - Memory
     - 16 GB

Test Results
~~~~~~~~~~~~

============= =================================
Engine        Performance (seconds per packet)
============= =================================
``dpkt``      0.00017389218012491862
``scapy``     0.00036091208457946774
``default``   0.0009537641207377116
``pipeline``  0.0009694552421569824
``server``    0.018088217973709107
``pyshark``   0.04200994372367859
============= =================================

.. raw:: html

   <br />

------------
Installation
------------

.. note::

   :mod:`pcapkit` supports Python versions **since 3.4**.

Simply run the following to install the current version from PyPI:

.. code:: shell

   pip install pypcapkit

Or install the latest version from the gi repository:

.. code:: shell

   git clone https://github.com/JarryShaw/PyPCAPKit.git
   cd pypcapkit
   pip install -e .
   # and to update at any time
   git pull

And since :mod:`pcapkit` supports various extraction engines, and extensive
plug-in functions, you may want to install the optional ones:

.. code:: shell

   # for DPKT only
   pip install pypcapkit[DPKT]
   # for Scapy only
   pip install pypcapkit[Scapy]
   # for PyShark only
   pip install pypcapkit[PyShark]
   # and to install all the optional packages
   pip install pypcapkit[all]
   # or to do this explicitly
   pip install pypcapkit dpkt scapy pyshark

-------
Samples
-------

Usage Samples
-------------

As described above, :mo:d`pcapkit` is quite easy to use, with simply three
verbs as its main interface. Several scenarios are shown as below.

1. extract a PCAP file and dump the result to a specific file
   (with no reassembly)

   .. code:: python

      import pcapkit
      # dump to a PLIST file with no frame storage (property frame disabled)
      plist = pcapkit.extract(fin='in.pcap', fout='out.plist', format='plist', store=False)
      # dump to a JSON file with no extension auto-complete
      json = pcapkit.extract(fin='in.cap', fout='out.json', format='json', extension=False)
      # dump to a folder with each tree-view text file per frame
      tree = pcapkit.extract(fin='in.pcap', fout='out', format='tree', files=True)

2. extract a PCAP file and fetch IP packet (both IPv4 and IPv6) from a frame
   (with no output file)

   .. code:: python

      >>> import pcapkit
      >>> extraction = pcapkit.extract(fin='in.pcap', nofile=True)
      >>> frame0 = extraction.frame[0]
      # check if IP in this frame, otherwise ProtocolNotFound will be raised
      >>> flag = pcapkit.IP in frame0
      >>> tcp = frame0[pcapkit.IP] if flag else None

3. extract a PCAP file and reassemble TCP payload
   (with no output file nor frame storage)

   .. code:: python

      import pcapkit
      # set strict to make sure full reassembly
      extraction = pcapkit.extract(fin='in.pcap', store=False, nofile=True, tcp=True, strict=True)
      # print extracted packet if HTTP in reassembled payloads
      for packet in extraction.reassembly.tcp:
          for reassembly in packet.packets:
              if pcapkit.HTTP in reassembly.protochain:
                  print(reassembly.info)

CLI Samples
-----------

The CLI (command line interface) of :mod:`pcapkit` has two different access.

* through console scripts

  Use command name ``pcapkit [...]`` directly (as shown in samples).

* through Python module

  ``python -m pypcapkit [...]`` works exactly the same as above.

Here are some usage samples:

1. export to a macOS Property List
   (`Xcode`_ has special support for this format)

   .. code:: shell

      $ pcapkit in --format plist --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out.plist'

2. export to a JSON file (with no format specified)

   .. code:: shell

      $ pcapkit in --output out.json --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out.json'

3. export to a text tree view file (without extension autocorrect)

   .. code:: shell

      $ pcapkit in --output out --format tree --verbose
      🚨Loading file 'in.pcap'
       - Frame   1: Ethernet:IPv6:ICMPv6
       - Frame   2: Ethernet:IPv6:ICMPv6
       - Frame   3: Ethernet:IPv4:TCP
       - Frame   4: Ethernet:IPv4:TCP
       - Frame   5: Ethernet:IPv4:TCP
       - Frame   6: Ethernet:IPv4:UDP
      🍺Report file stored in 'out'

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _PCAP: https://en.wikipedia.org/wiki/Pcap
.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _Xcode: https://developer.apple.com/xcode

PyPCAPKit - Comprehensive Network Packet Analysis Library
=========================================================

   For any technical and/or maintenance information,
   please kindly refer to the |docs|_.

.. |docs| replace:: **Official Documentation**
.. _docs: https://jarryshaw.github.io/PyPCAPKit/

The PyPCAPKit project is an open source Python program focus on network packet
parsing and analysis, which works as a comprehensive `PCAP`_ file extraction,
construction and analysis library.

   The whole project supports **Python 3.6** or later.

-----
About
-----

PyPCAPKit is a comprehensive Python-native network packet analysis library,
with `DictDumper`_ as its formatted output dumper.

Unlike popular PCAP file extractors, such as `Scapy`_, `DPKT`_, `PyShark`_,
and etc, ``pcapkit`` is designed to be much more comprehensive, which means
it is able to provide more detailed information about the packet, as well as
a more *Pythonic* interface for users to interact with.

Module Structure
----------------

In ``pcapkit``, all files can be described as following eight parts.

- Interface (``pcapkit.interface``)

  User interface for the ``pcapkit`` library, which
  standardises and simplifies the usage of this library.

- Foundation (``pcapkit.foundation``)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, as well as
  provides the foundamental functions for ``pcapkit``.

- Protocols (``pcapkit.protocols``)

  Collection of all protocol family, with detailed
  implementation and methods.

- Utilities (``pcapkit.utilities``)

  Auxiliary functions and tools for ``pcapkit``.

- CoreKit (``pcapkit.corekit``)

  Core utilities for ``pcapkit`` implementation, mainly
  for internal data structure and processing.

- ToolKit (``pcapkit.toolkit``)

  Auxiliary tools for ``pcapkit`` to support the multiple
  extraction engines with a unified interface.

- DumpKit (``pcapkit.dumpkit``)

  File output formatters for ``pcapkit``.

- Constants (``pcapkit.const``)

  Constant enumerations used in ``pcapkit`` for protocol
  family extraction and representation.

Engine Comparison
-----------------

Due to the general overhead of ``pcapkit``, its extraction procedure takes
around *0.2* milliseconds per packet, which is already impressive but not enough
comparing to other popular extration engines availbale on the market, given the
fact that ``pcapkit`` is a **comprehensive** packet processing module.

Additionally, ``pcapkit`` introduced alternative extractionengines to accelerate
this procedure. By now ``pcapkit`` supports `Scapy`_, `DPKT`_, and `PyShark`_.

Test Environment
~~~~~~~~~~~~~~~~

.. list-table::

   * - Operating System
     - macOS Ventura 13.4.1
   * - Chip
     - Apple M2 Pro
   * - Memory
     - 16 GB

Test Results
~~~~~~~~~~~~

============= ===========================
Engine        Performance (ms per packet)
============= ===========================
``dpkt``       0.010390_056723
``scapy``      0.091690_233567
``pcapkit``    0.200390_390390
``pyshark``   24.682185_018351
============= ===========================

------------
Installation
------------

.. note::

   ``pcapkit`` supports Python versions **since 3.6**.

Simply run the following to install the current version from PyPI:

.. code-block:: shell

   pip install pypcapkit

Or install the latest version from the gi repository:

.. code-block:: shell

   git clone https://github.com/JarryShaw/PyPCAPKit.git
   cd pypcapkit
   pip install -e .
   # and to update at any time
   git pull

And since ``pcapkit`` supports various extraction engines, and extensive
plug-in functions, you may want to install the optional ones:

.. code-block:: shell

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

For CLI usage, you will need to install the optional packages:

.. code-block:: shell

   pip install pypcapkit[cli]
   # or explicitly...
   pip install pypcapkit emoji

.. _PCAP: https://en.wikipedia.org/wiki/Pcap
.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _DictDumper: https://github.com/JarryShaw/DictDumper

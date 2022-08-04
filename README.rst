PyPCAPKit - Stream PCAP File Extractor
======================================

   For any technical and/or maintenance information,
   please kindly refer to the |docs|_.

.. |docs| replace:: **Official Documentation**
.. _docs: https://jarryshaw.github.io/PyPCAPKit/

The PyPCAPKit project is an open source Python program focus
on `PCAP`_ parsing and analysis, which works as a stream PCAP file extractor.
With support of `DictDumper`_, it shall support multiple
output report formats.

   The whole project supports **Python 3.6** or later.

-----
About
-----

PyPCAPKit is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

   There is a project called |jspcapy|_ works on ``pcapkit``, which is a
   command line tool for PCAP extraction.

   .. |jspcapy| replace:: ``jspcapy``
   .. _jspcapy: https://github.com/JarryShaw/jspcapy

   .. note::

      The |jspcapy|_ project is deprecated and has been merged into the
      PyPCAPKit project as its CLI support since PyPCAPKit v0.8.0.

Unlike popular PCAP file extractors, such as `Scapy`_, `DPKT`_, `PyShark`_,
and etc, ``pcapkit`` uses **streaming** strategy to read input files. That
is to read frame by frame, decrease occupation on memory, as well as enhance
efficiency in some way.

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
around *0.0008* seconds per packet, which is already impressive but not enough
comparing to other popular extration engines availbale on the market. Thus
``pcapkit`` introduced alternative extractionengines to accelerate this
procedure. By now ``pcapkit`` supports `Scapy`_, `DPKT`_, and `PyShark`_.

Test Environment
~~~~~~~~~~~~~~~~

.. list-table::

   * - Operating System
     - macOS Monterey
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
``dpkt``      0.00006832083066304525
``scapy``     0.0002489296595255534
``pcapkit``   0.0008274253209431966
``pyshark``   0.039607704480489093
============= =================================

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

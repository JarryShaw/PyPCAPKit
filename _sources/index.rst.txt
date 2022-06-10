.. PyPCAPKit documentation master file, created by
   sphinx-quickstart on Sat Mar 28 21:29:54 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

PyPCAPKit - Stream PCAP File Extractor
======================================

The :mod:`PyPCAPKit <pcapkit>` project is an open source Python program focus
on `PCAP`_ parsing and analysis, which works as a stream PCAP file extractor.
With support of :mod:`DictDumper <dictdumper>`, it shall support multiple
output report formats.

.. important::

   The whole project supports **Python 3.6** or later.

.. toctree::
   :maxdepth: 3

   pcapkit/index
   demo
   pep

-----
About
-----

:mod:`PyPCAPKit <pcapkit>` is an independent open source library, using only
:mod:`DictDumper <dictdumper>` as its formatted output dumper.

.. note::

   There is a project called |jspcapy|_ works on :mod:`pcapkit`, which is a
   command line tool for PCAP extraction.

   .. |jspcapy| replace:: ``jspcapy``
   .. _jspcapy: https://github.com/JarryShaw/jspcapy

   .. deprecated:: 0.8.0

      The |jspcapy|_ project is deprecated and has been merged into the
      :mod:`PyPCAPKit <pcapkit>` project as its CLI support.

Unlike popular PCAP file extractors, such as :mod:`Scapy <scapy>`,
:mod:`dpkt <dpkt>`, :mod:`PyShark <pyshark>`, and etc, :mod:`pcapkit` uses
**streaming** strategy to read input files. That is to read frame by frame,
decrease occupation on memory, as well as enhance efficiency in some way.

Module Structure
----------------

In :mod:`pcapkit`, all files can be described as following eight parts.

- Interface (:mod:`pcapkit.interface`)

  User interface for the :mod:`pcapkit` library, which
  standardises and simplifies the usage of this library.

- Foundation (:mod:`pcapkit.foundation`)

  Synthesises file I/O and protocol analysis, coordinates
  information exchange in all network layers, as well as
  provides the foundamental functions for :mod:`pcapkit`.

- Protocols (:mod:`pcapkit.protocols`)

  Collection of all protocol family, with detailed
  implementation and methods.

- Utilities (:mod:`pcapkit.utilities`)

  Auxiliary functions and tools for :mod:`pcapkit`.

- CoreKit (:mod:`pcapkit.corekit`)

  Core utilities for :mod:`pcapkit` implementation, mainly
  for internal data structure and processing.

- ToolKit (:mod:`pcapkit.toolkit`)

  Auxiliary tools for :mod:`pcapkit` to support the multiple
  extraction engines with a unified interface.

- DumpKit (:mod:`pcapkit.dumpkit`)

  File output formatters for :mod:`pcapkit`.

- Constants (:mod:`pcapkit.const`)

  Constant enumerations used in :mod:`pcapkit` for protocol
  family extraction and representation.

Engine Comparison
-----------------

Due to the general overhead of :mod:`pcapkit`, its extraction procedure takes
around *0.0008* seconds per packet, which is already impressive but not enough
comparing to other popular extration engines availbale on the market. Thus
:mod:`pcapkit` introduced alternative extractionengines to accelerate this
procedure. By now :mod:`pcapkit` supports `Scapy`_, `DPKT`_, and `PyShark`_.

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

.. raw:: html

   <br />

------------
Installation
------------

.. note::

   :mod:`pcapkit` supports Python versions **since 3.6**.

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

And since :mod:`pcapkit` supports various extraction engines, and extensive
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

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _PCAP: https://en.wikipedia.org/wiki/Pcap
.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

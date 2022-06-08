Stream PCAP File Extractor
==========================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

    There is a project called |jspcapy|_ works on :mod:`pcapkit`,
    which is a command line tool for PCAP extraction.

Unlike popular PCAP file extractors, such as `Scapy`_,
`DPKT`_, `PyShark`_, and etc, :mod:`pcapkit` uses streaming
strategy to read input files. That is to read frame by
frame, decrease occupation on memory, as well as enhance
efficiency in some way.

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

.. toctree::
   :maxdepth: 2

   foundation/index
   interface/index
   protocols/index
   reassembly/index
   corekit/index
   dumpkit/index
   toolkit/index
   utilities/index
   const/index
   vendor/index

In :mod:`pcapkit`, all files can be described as following eight
different components.

- Interface (:mod:`pcapkit.interface`)

  user interface for the :mod:`pcapkit` library, which
  standardise and simplify the usage of this library

- Foundation (:mod:`pcapkit.foundation`)

  synthesise file I/O and protocol analysis, coordinate
  information exchange in all network layers

- Reassembly (:mod:`pcapkit.reassembly`)

  base on algorithms described in :rfc:`815`,
  implement datagram reassembly of IP and TCP packets

- Protocols (:mod:`pcapkit.protocols`)

  collection of all protocol family, with detailed
  implementation and methods

- Utilities (:mod:`pcapkit.utilities`)

  collection of utility functions and classes

- CoreKit (:mod:`pcapkit.corekit`)

  core utilities for :mod:`pcapkit` implementation

- ToolKit (:mod:`pcapkit.toolkit`)

  utility tools for :mod:`pcapkit` implementation

- DumpKit (:mod:`pcapkit.dumpkit`)

  dump utilities for :mod:`pcapkit` implementation

.. |jspcapy| replace:: ``jspcapy``
.. _jspcapy: https://github.com/JarryShaw/jspcapy

Library Index
-------------

.. module:: pcapkit.all

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

.. module:: pcapkit

Stream PCAP File Extractor
==========================

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

    There is a project called |jspcapy|_ works on :mod:`pcapkit`,
    which is a command line tool for PCAP extraction.

    .. |jspcapy| replace:: ``jspcapy``
    .. _jspcapy: https://github.com/JarryShaw/jspcapy

Unlike popular PCAP file extractors, such as `Scapy`_,
`DPKT`_, `PyShark`_, and etc, :mod:`pcapkit` uses streaming
strategy to read input files. That is to read frame by
frame, decrease occupation on memory, as well as enhance
efficiency in some way.

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

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

- IPSuite (:mod:`pcapkit.ipsuite`)

  collection of constructors for Internet Protocol Suite

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

Subpackages
-----------

.. toctree::
   :maxdepth: 4

   pcapkit.const
   pcapkit.corekit
   pcapkit.dumpkit
   pcapkit.foundation
   pcapkit.interface
   pcapkit.ipsuite
   pcapkit.protocols
   pcapkit.reassembly
   pcapkit.toolkit
   utilities/index
   vendor/index

Library Index
-------------

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

Command Line Interface
----------------------

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is now deprecated and merged with :mod:`pcapkit`.

.. |jspcapy| replace:: ``jspcapy``
.. _jspcapy: https://github.com/JarryShaw/jspcapy

.. code:: text

   usage: pcapkit-cli [-h] [-V] [-o file-name] [-f format] [-j] [-p] [-t] [-a]
                      [-v] [-F] [-E PKG] [-P PROTOCOL] [-L LAYER]
                      input-file-name

   PCAP file extractor and formatted dumper

   positional arguments:
     input-file-name       The name of input pcap file. If ".pcap" omits, it will
                           be automatically appended.

   optional arguments:
     -h, --help            show this help message and exit
     -V, --version         show program's version number and exit
     -o file-name, --output file-name
                           The name of input pcap file. If format extension
                           omits, it will be automatically appended.
     -f format, --format format
                           Print a extraction report in the specified output
                           format. Available are all formats supported by
                           dictdumper, e.g.: json, plist, and tree.
     -j, --json            Display extraction report as json. This will yield
                           "raw" output that may be used by external tools. This
                           option overrides all other options.
     -p, --plist           Display extraction report as macOS Property List
                           (plist). This will yield "raw" output that may be used
                           by external tools. This option overrides all other
                           options.
     -t, --tree            Display extraction report as tree view text. This will
                           yield "raw" output that may be used by external tools.
                           This option overrides all other options.
     -a, --auto-extension  If output file extension omits, append automatically.
     -v, --verbose         Show more information.
     -F, --files           Split each frame into different files.
     -E PKG, --engine PKG  Indicate extraction engine. Note that except default
                           or pcapkit engine, all other engines need support of
                           corresponding packages.
     -P PROTOCOL, --protocol PROTOCOL
                           Indicate extraction stops after which protocol.
     -L LAYER, --layer LAYER
                           Indicate extract frames until which layer.

.. automodule:: pcapkit.__main__
   :members:
   :undoc-members:
   :show-inheritance:

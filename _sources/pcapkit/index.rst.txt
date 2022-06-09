====================
Module Documentation
====================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

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

   interface/index
   foundation/index
   protocols/index
   corekit/index
   toolkit/index
   dumpkit/index
   utilities/index
   const/index
   vendor/index

.. automodule:: pcapkit.__main__
   :no-members:

.. code-block:: text

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

.. automodule:: pcapkit.all
   :no-members:

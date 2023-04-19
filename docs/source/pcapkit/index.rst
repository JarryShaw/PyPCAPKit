====================
Module Documentation
====================

.. module:: pcapkit

:mod:`pcapkit` is an independent open source library, using only
`DictDumper`_ as its formatted output dumper.

.. _DictDumper: https://dictdumper.jarryshaw.me

Unlike popular PCAP file extractors, such as `Scapy`_, `DPKT`_,
`PyShark`_, and etc, :mod:`pcapkit` tends to provide comprehensive
support to all protocols, including but not limited to their
parameters and/or options, etc. Therefore, :mod:`pcapkit` contains
enumeration registries used by protocols, independent protocol
schema definitions as well as various customisable interfaces.

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

Command Line Tool
=================

.. module:: pcapkit.__main__

.. important::

   This module requires ``emoji`` package to be installed.

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is now deprecated and merged with :mod:`pcapkit`.

.. |jspcapy| replace:: ``jspcapy``
.. _jspcapy: https://github.com/JarryShaw/jspcapy

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

Library Index
=============

.. module:: pcapkit.all

:mod:`pcapkit` has defined various and numerous functions
and classes, which have different features and purposes.
To make a simple index for this library, :mod:`pcapkit.all`
contains all things from :mod:`pcapkit`.

Environment Variables
=====================

.. envvar:: PCAPKIT_DEVMODE

   If set to ``1``, :mod:`pcapkit` will run in development mode.

   .. seealso::

      :data:`pcapkit.utilities.logging.DEVMODE`

.. envvar:: PCAPKIT_VERBOSE

   If set to ``1``, :mod:`pcapkit` will run with verbose output.

   .. seealso::

      :data:`pcapkit.utilities.logging.VERBOSE`

.. envvar:: PCAPKIT_HTTP_PROXY

   HTTP proxy address for :mod:`pcapkit.vendor` crawlers.

.. envvar:: PCAPKIT_HTTPS_PROXY

   HTTPS proxy address for :mod:`pcapkit.vendor` crawlers.

.. envvar:: PCAPKIT_SPHINX

   If set to ``1``, :mod:`pcapkit` will run with Sphinx additional
   typing hints and docstrings support.

   .. seealso::

      :data:`pcapkit.utilities.logging.SPHINX_TYPE_CHECKING`

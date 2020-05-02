Command Line Interface
----------------------

.. module:: pcapkit.__main__

:mod:`pcapkit.__main__` was originally the module file of
|jspcapy|_, which is now deprecated and merged with :mod:`pcapkit`.

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
   :private-members:
   :show-inheritance:

.. |jspcapy| replace:: ``jspcapy``
.. _jspcapy: https://github.com/JarryShaw/jspcapy

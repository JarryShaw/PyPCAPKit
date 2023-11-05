User Interface
==============

.. module:: pcapkit.interface

:mod:`pcapkit.interface` defines several user-oriented
interfaces, variables, and etc. These interfaces are
designed to help and simplify the usage of :mod:`pcapkit`.

.. toctree::

   core
   misc

For wrapper interface functions and constants, please
refer to the documentation of :mod:`pcapkit.interface.core`
module, where the core interfaces are defined. And for the
auxiliary interfaces, please refer to the documentation
of :mod:`pcapkit.interface.misc` module.

.. note::

   Should you would like to have additional interfaces defined,
   please feel free to open an issue on GitHub, or even better,
   submit a pull request. Your contribution is highly appreciated.

Following is a table of all interfaces defined in this module:

+------------------+---------------------+----------------------------------------+
| Category         | Interface                                                    |
+==================+=====================+========================================+
|                  | :func:`pcapkit.interface.core.extract`                       |
+                  +---------------------+----------------------------------------+
|                  | :func:`pcapkit.interface.core.reassemble`                    |
+                  +---------------------+----------------------------------------+
|                  | :func:`pcapkit.interface.core.trace`                         |
+                  +---------------------+----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.TREE`    |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.JSON`    |
+                  + Output File Formats +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PLIST`   |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAP`    |
+                  +---------------------+----------------------------------------+
| Core Interfaces  |                     | :data:`pcapkit.interface.core.RAW`     |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.LINK`    |
+                  +                     +----------------------------------------+
|                  | Layer Thresholds    | :data:`pcapkit.interface.core.INET`    |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.TRANS`   |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.APP`     |
+                  +---------------------+----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.DPKT`    |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.Scapy`   |
+                  + Extraction Engines  +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAPKit` |
+                  +                     +----------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PyShark` |
+------------------+---------------------+----------------------------------------+
| Miscellaneous    | :func:`pcapkit.interface.misc.follow_tcp_stream`             |
+------------------+---------------------+----------------------------------------+

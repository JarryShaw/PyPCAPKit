User Interface
==============

.. module:: pcapkit.interface

:mod:`pcapkit.interface` defines the user-facing functions and constants that
simplify the use of :mod:`pcapkit`.

.. toctree::

   core
   misc

:mod:`pcapkit.interface.core` defines the core functions and constants, and
:mod:`pcapkit.interface.misc` the auxiliary ones.

.. versionremoved:: 1.7.0

   ``pcapkit.interface.registry``, whose helpers moved to
   :mod:`pcapkit.corekit.registry` (:issue:`2838`).

.. note::

   To ask for another interface, open an issue on GitHub, or submit a pull
   request.

The public interfaces, by category:

+------------------+---------------------+--------------------------------------------+
| Category         | Interface                                                        |
+==================+=====================+============================================+
|                  | :func:`pcapkit.interface.core.extract`                           |
+                  +---------------------+--------------------------------------------+
|                  | :func:`pcapkit.interface.core.reassemble`                        |
+                  +---------------------+--------------------------------------------+
|                  | :func:`pcapkit.interface.core.trace`                             |
+                  +---------------------+--------------------------------------------+
|                  | :class:`pcapkit.foundation.options.DumpOptions`                  |
+                  +---------------------+--------------------------------------------+
|                  | :class:`pcapkit.foundation.options.ReassemblyOptions`            |
+                  +---------------------+--------------------------------------------+
|                  | :class:`pcapkit.foundation.options.TraceFlowOptions`             |
+                  +---------------------+--------------------------------------------+
|                  | :class:`pcapkit.foundation.options.StreamOptions`                |
+                  +---------------------+--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.TREE`        |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.JSON`        |
+                  +                     +--------------------------------------------+
|                  | Output File Formats | :data:`pcapkit.interface.core.PLIST`       |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAP`        |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAP_NG`     |
+                  +---------------------+--------------------------------------------+
| Core Interfaces  |                     | :data:`pcapkit.interface.core.RAW`         |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.LINK`        |
+                  +                     +--------------------------------------------+
|                  | Layer Thresholds    | :data:`pcapkit.interface.core.INET`        |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.TRANS`       |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.APP`         |
+                  +---------------------+--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.DPKT`        |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.Scapy`       |
+                  + Extraction Engines  +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAPKit`     |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PyShark`     |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PyPCAP`      |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PCAP_CT`     |
+                  +                     +--------------------------------------------+
|                  |                     | :data:`pcapkit.interface.core.PyPCAPFile`  |
+------------------+---------------------+--------------------------------------------+
| Miscellaneous    | :func:`pcapkit.interface.misc.follow_tcp_stream`                 |
+------------------+---------------------+--------------------------------------------+

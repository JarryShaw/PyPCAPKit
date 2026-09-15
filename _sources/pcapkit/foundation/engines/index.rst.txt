Engine Support
==============

.. module:: pcapkit.foundation.engines

:mod:`pcapkit.foundation.engines` is a collection of engines
support for :mod:`pcapkit`, including but not limited to the
built-in PCAP and `PCAP-NG`_ file support, `Scapy`_, `PyShark`_,
`DPKT`_, `PyPCAP`_ and `PyPCAPFile`_ 3rd party engine support.

.. seealso::

   For more information on customisation and extension, please
   refer to :doc:`../../../ext`.

.. toctree::
   :maxdepth: 2

   engine
   builtin
   3rdparty

All engines are implemented as :class:`~pcapkit.foundation.engines.engine.Engine`
subclasses, which are responsible for parsing the input files and extracting
the network packets for further processing. Below is a brief diagram of the
class hierarchy of :mod:`pcapkit.foundation.engines`:

.. mermaid::

   flowchart LR
       A{{EngineMeta}} -.->|metaclass| B(EngineBase)

       subgraph built-in [Built-in Engines]
           %% direction TD

           PCAP
           PCAPNG
       end
       B --> built-in

       subgraph third-party [3rd Party Engines]
           %% direction TD

           Scapy
           DPKT
           PyShark
           PyPCAP
           PyPCAPFile
       end
       B --> third-party

       B --> C(Engine)
       C --> D([user customisation ...])

       click A "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.EngineMeta"
       click B "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.EngineBase"
       click C "/pcapkit/foundation/engines/engine.html#pcapkit.foundation.engines.engine.Engine"
       click D "/ext.html#extractor-engines"

       click PCAP "/pcapkit/foundation/engines/builtin.html#pcapkit.foundation.engines.pcap.PCAP"
       click PCAPNG "/pcapkit/foundation/engines/builtin.html#pcapkit.foundation.engines.pcapng.PCAPNG"

       click Scapy "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.scapy.Scapy"
       click DPKT "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.dpkt.DPKT"
       click PyShark "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pyshark.PyShark"
       click PyPCAP "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pypcap.PyPCAP"
       click PyPCAPFile "/pcapkit/foundation/engines/3rdparty.html#pcapkit.foundation.engines.pypcapfile.PyPCAPFile"

Not every engine can do everything :class:`~pcapkit.foundation.extraction.Extractor`
offers, and the ones that cannot say so rather than quietly doing less:

+-----------------------------------------------------------------+---------------------------------------------------------------+
| Engine                                                          | Gap, and how it is surfaced                                   |
+=================================================================+===============================================================+
| :class:`~pcapkit.foundation.engines.pyshark.PyShark`            | no reassembly -- disabled with an                             |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`         |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`              | no protocol dissection at all, hence no reassembly and no     |
|                                                                 | flow tracing -- both disabled with an                         |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`; PCAP   |
|                                                                 | savefiles on disk only, otherwise                             |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.FormatError` /            |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`          |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`      | no IPv6 decoder, hence no IPv6 reassembly -- disabled with an |
|                                                                 | :class:`~pcapkit.utilities.warnings.AttributeWarning`, and    |
|                                                                 | :func:`~pcapkit.toolkit.pypcapfile.ipv6_reassembly` raises;   |
|                                                                 | PCAP savefiles only, otherwise                                |
|                                                                 | :exc:`~pcapkit.utilities.exceptions.FormatError`              |
+-----------------------------------------------------------------+---------------------------------------------------------------+

Availability
------------

A third-party engine is only usable where its backing package is, and three of
them are harder to obtain than a plain :program:`pip install` suggests. Asking
for an engine whose package is missing is not fatal -- :mod:`pcapkit` emits an
:class:`~pcapkit.utilities.warnings.EngineWarning` and falls back to its own
parser -- but the extraction then has nothing to do with the engine requested,
so it is worth knowing in advance.

+-----------------------------------------------------------------+---------------------------------------------------------------+
| Engine                                                          | What it needs beyond ``pip install``                          |
+=================================================================+===============================================================+
| :class:`~pcapkit.foundation.engines.pcap.PCAP`,                 | nothing -- built in                                           |
| :class:`~pcapkit.foundation.engines.pcapng.PCAPNG`              |                                                               |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.dpkt.DPKT`,                 | nothing -- both ship pure-Python wheels                       |
| :class:`~pcapkit.foundation.engines.scapy.Scapy`                |                                                               |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pyshark.PyShark`            | Wireshark's :program:`tshark` binary on ``PATH``              |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcap.PyPCAP`              | `libpcap`_ headers and library, a C compiler, and Python      |
|                                                                 | **3.11 or older** -- ``pypcap`` 1.3.0 publishes no wheel and  |
|                                                                 | its pre-generated :file:`pcap.c` does not compile on 3.12+    |
+-----------------------------------------------------------------+---------------------------------------------------------------+
| :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile`      | Python **3.11 or older** -- ``pypcapfile`` 0.12.0 imports the |
|                                                                 | ``imp`` module, removed in Python 3.12                        |
+-----------------------------------------------------------------+---------------------------------------------------------------+

.. seealso::

   :doc:`../../../index` covers the installation prerequisites in full,
   including how ``pypcap``'s :file:`setup.py` looks for :file:`pcap.h` and why
   a Homebrew ``libpcap`` is not always found.

.. _PCAP-NG: https://wiki.wireshark.org/Development/PcapNg

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark
.. _PyPCAP: https://github.com/pynetwork/pypcap
.. _PyPCAPFile: https://github.com/kisom/pypcapfile
.. _libpcap: https://www.tcpdump.org

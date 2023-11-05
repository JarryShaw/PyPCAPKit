Engine Support
==============

.. module:: pcapkit.foundation.engines

:mod:`pcapkit.foundation.engines` is a collection of engines
support for :mod:`pcapkit`, including but not limited to the
built-in PCAP and `PCAP-NG`_ file support, `Scapy`_, `PyShark`_,
and `DPKT`_ 3rd party engine support.

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

.. _PCAP-NG: https://wiki.wireshark.org/Development/PcapNg

.. _Scapy: https://scapy.net
.. _DPKT: https://dpkt.readthedocs.io
.. _PyShark: https://kiminewt.github.io/pyshark

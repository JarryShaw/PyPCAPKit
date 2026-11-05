==================
Packets Reassembly
==================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly` implements datagram reassembly
of IP packets, TCP segments and DTLS handshake messages, based on the
algorithms described in :rfc:`791`, :rfc:`815` and :rfc:`6347`.

.. seealso::

   :doc:`../../../ext`, on customisation and extension.

.. toctree::
   :maxdepth: 2

   reassembly
   ip/index
   tcp
   dtls

Every reassembly class subclasses
:class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase`, reassembling
extracted fragments into whole datagrams:

.. mermaid::

   flowchart TD
       A{{ReassemblyMeta}} -.->|metaclass| B(ReassemblyBase)

       B --> IP & TCP & DTLS
       IP --> IPv4 & IPv6

       B --> C(Reassembly)
       C --> D([user customisation ...])
       IPv4 ~~~ C

       click A "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyMeta"
       click B "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyBase"
       click C "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly"
       click D "../../../ext.html#reassembly-and-flow-tracing"

       click IP "ip/ip.html#pcapkit.foundation.reassembly.ip.IP"
       click IPv4 "ip/ipv4.html#pcapkit.foundation.reassembly.ipv4.IPv4"
       click IPv6 "ip/ipv6.html#pcapkit.foundation.reassembly.ipv6.IPv6"
       click TCP "tcp.html#pcapkit.foundation.reassembly.tcp.TCP"
       click DTLS "dtls.html#pcapkit.foundation.reassembly.dtls.DTLS"

Auxiliary Data
==============

.. autoclass:: pcapkit.foundation.reassembly.ReassemblyManager
   :members:
   :show-inheritance:

.. module:: pcapkit.foundation.reassembly.data
.. module:: pcapkit.foundation.reassembly.data.data
.. currentmodule:: pcapkit.foundation.reassembly

.. autoclass:: pcapkit.foundation.reassembly.data.data.ReassemblyData
   :members:
   :show-inheritance:

.. _reassembly-submissions:

What submits a buffer, and how its holes at that point pick the
:class:`~pcapkit.foundation.reassembly.data.data.Completion` it reports:

.. mermaid::

   flowchart TD
       subgraph trig ["What submits a buffer"]
           direction TB
           T1["IP: every octet received<br/>TCP: a FIN and every octet below it"]
           T2["a session torn down: a TCP RST,<br/>a TCP SYN on a buffered 4-tuple,<br/>an unfragmented IPv4 datagram reusing the BUFID"]
           T3["a TCP segment farther than TCP\_GAP\_LIMIT<br/>from its buffer: the stream splits"]
           T4["a DTLS fragment whose length or type disagrees<br/>with the message held under its message\_seq"]
           T5["an IPv6 fragment overlapping another,<br/>not an exact duplicate: overlap=True"]
           T6["Reassembly.expire, as each packet reaches<br/>IP or TCP reassembly: the timeout passed<br/>since a buffer's first fragment, timeout=True"]
           T7[".datagram or fetch() read<br/>while buffers are outstanding"]
           T1 ~~~ T2 ~~~ T3 ~~~ T4 ~~~ T5 ~~~ T6 ~~~ T7
       end
       T1D["DTLS: a message whole"]
       SUB["submit(buffer)"]
       Q1{"overlap?"}
       Q2{"no holes left?"}
       Q3{"submitted by expire?"}
       OV["OVERLAP"]
       CO["COMPLETE"]
       TO["TIMEOUT"]
       PA["PARTIAL"]
       CB["datagrams reported<br/>each \_\_callback\_fn\_\_ called with them"]

       trig --> SUB
       T1D --> CO
       SUB --> Q1
       Q1 -->|yes| OV
       Q1 -->|no| Q2
       Q2 -->|yes| CO
       Q2 -->|no| Q3
       Q3 -->|yes| TO
       Q3 -->|no| PA
       OV & CO & TO & PA --> CB

       click SUB "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly.submit"
       click T6 "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly.expire"
       click T7 "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly.fetch"
       click OV "index.html#pcapkit.foundation.reassembly.data.data.Completion.OVERLAP"
       click CO "index.html#pcapkit.foundation.reassembly.data.data.Completion.COMPLETE"
       click TO "index.html#pcapkit.foundation.reassembly.data.data.Completion.TIMEOUT"
       click PA "index.html#pcapkit.foundation.reassembly.data.data.Completion.PARTIAL"

.. autoclass:: pcapkit.foundation.reassembly.data.data.Completion
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.data.Deferred
   :members:
   :show-inheritance:

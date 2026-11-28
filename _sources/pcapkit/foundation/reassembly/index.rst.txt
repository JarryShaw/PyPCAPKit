==================
Packets Reassembly
==================

.. module:: pcapkit.foundation.reassembly

:mod:`pcapkit.foundation.reassembly` implements datagram reassembly
of IP packets, TCP segments, DTLS handshake messages, SCTP user messages and TLS
records, based on the algorithms described in :rfc:`791`, :rfc:`815`, :rfc:`6347`,
:rfc:`9260`, :rfc:`8260` and :rfc:`9846`.

.. seealso::

   :doc:`../../../ext`, on customisation and extension.

.. toctree::
   :maxdepth: 2

   reassembly
   ip/index
   tcp
   dtls
   sctp
   tls

Every reassembly class subclasses
:class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase`, reassembling
extracted fragments into whole datagrams:

.. mermaid::

   flowchart TD
       A{{ReassemblyMeta}} -.->|metaclass| B(ReassemblyBase)

       B --> IP & TCP & DTLS & SCTP & TLS
       IP --> IPv4 & IPv6

       B --> C(Reassembly)
       C --> D([user customisation ...])
       IPv4 ~~~ C

       click A "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyMeta"
       click B "reassembly.html#pcapkit.foundation.reassembly.reassembly.ReassemblyBase"
       click C "reassembly.html#pcapkit.foundation.reassembly.reassembly.Reassembly"
       click D "../../../ext.html#reassembly-and-flow-tracing"

       click IP "ip/ip.html#pcapkit.foundation.reassembly.ip.reassembly.IP"
       click IPv4 "ip/ipv4.html#pcapkit.foundation.reassembly.ipv4.reassembly.IPv4"
       click IPv6 "ip/ipv6.html#pcapkit.foundation.reassembly.ipv6.reassembly.IPv6"
       click TCP "tcp.html#pcapkit.foundation.reassembly.tcp.reassembly.TCP"
       click DTLS "dtls.html#pcapkit.foundation.reassembly.dtls.reassembly.DTLS"
       click SCTP "sctp.html#pcapkit.foundation.reassembly.sctp.reassembly.SCTP"
       click TLS "tls.html#pcapkit.foundation.reassembly.tls.reassembly.TLS"

Auxiliary Data
==============

.. autoclass:: pcapkit.foundation.reassembly.ReassemblyManager
   :members:
   :show-inheritance:

.. module:: pcapkit.foundation.reassembly.data

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.reassembly.data.data``, with no alias: the module moved here.
   The ``IP_*``, ``TCP_*`` and ``DTLS_*`` data models
   ``pcapkit.foundation.reassembly.data`` collected, with no alias: each reassembly
   class's are in the ``data`` module of its own package, such as
   :mod:`pcapkit.foundation.reassembly.tcp.data` (:issue:`2882`).

.. currentmodule:: pcapkit.foundation.reassembly

.. autoclass:: pcapkit.foundation.reassembly.data.ReassemblyData
   :members:
   :show-inheritance:

.. _reassembly-submissions:

What submits a buffer, and how its holes at that point pick the
:class:`~pcapkit.foundation.reassembly.data.Completion` it reports:

.. mermaid::

   flowchart TD
       subgraph trig ["What submits a buffer"]
           direction TB
           T1["IP: every octet received<br/>TCP, TLS: a FIN and every octet below it"]
           T2["a session torn down: a TCP RST,<br/>a TCP SYN on a buffered 4-tuple,<br/>an unfragmented IPv4 datagram reusing the BUFID"]
           T3["a TCP segment farther than TCP\_GAP\_LIMIT<br/>from its buffer: the stream splits"]
           T4["a DTLS fragment whose length or type disagrees<br/>with the message held under its message\_seq"]
           T5["an IPv6 fragment overlapping another,<br/>not an exact duplicate: overlap=True"]
           T6["Reassembly.expire, as the Extractor advances<br/>every reassembler to each frame's timestamp:<br/>the timeout passed since a buffer's<br/>first fragment, expired=True"]
           T7[".datagram or fetch() read outside a callback<br/>while buffers are outstanding"]
           T1 ~~~ T2 ~~~ T3 ~~~ T4 ~~~ T5 ~~~ T6 ~~~ T7
       end
       T1D["DTLS, SCTP: a message whole<br/>TLS: a record whole at the boundary"]
       SUB["submit(buffer)"]
       Q1{"overlap?"}
       Q2{"no holes left?"}
       Q3{"submitted by expire?"}
       OV["OVERLAP"]
       CO["COMPLETE"]
       TO["TIMEOUT"]
       PA["PARTIAL"]
       CB["datagrams stored, unless submitted for a read,<br/>then each \_\_callback\_fn\_\_ called with them"]

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
       click OV "index.html#pcapkit.foundation.reassembly.data.Completion.OVERLAP"
       click CO "index.html#pcapkit.foundation.reassembly.data.Completion.COMPLETE"
       click TO "index.html#pcapkit.foundation.reassembly.data.Completion.TIMEOUT"
       click PA "index.html#pcapkit.foundation.reassembly.data.Completion.PARTIAL"

.. autoclass:: pcapkit.foundation.reassembly.data.Completion
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.Deferred
   :members:
   :show-inheritance:

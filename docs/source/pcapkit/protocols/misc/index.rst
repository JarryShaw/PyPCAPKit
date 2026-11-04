Auxiliary Protocols
===================

.. module:: pcapkit.protocols.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
These include the PCAP header classes, the PCAP-NG
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` class, the
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` class for not-supported protocols, and
the :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` class for indication of
empty payload.

.. toctree::
   :maxdepth: 1

   pcap
   pcapng
   raw
   no_payload
   checksum

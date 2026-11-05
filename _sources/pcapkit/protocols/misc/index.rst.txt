Auxiliary Protocols
===================

.. module:: pcapkit.protocols.misc

:mod:`pcapkit.protocols.misc` holds the auxiliary protocols: the PCAP header
classes, :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`,
:class:`~pcapkit.protocols.misc.raw.protocol.Raw` for unsupported protocols,
:class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` for an empty
payload, and the checksum pseudo-headers.

.. toctree::
   :maxdepth: 1

   pcap
   pcapng
   raw
   no_payload
   checksum

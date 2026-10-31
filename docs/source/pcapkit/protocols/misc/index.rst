Auxiliary Protocols
===================

.. module:: pcapkit.protocols.misc
.. module:: pcapkit.protocols.data.misc
.. module:: pcapkit.protocols.schema.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
These include the PCAP header classes, the PCAP-NG
:class:`~pcapkit.protocols.misc.pcapng.PCAPNG` class, the
:class:`~pcapkit.protocols.misc.raw.Raw` class for not-supported protocols, and
the :class:`~pcapkit.protocols.misc.null.NoPayload` class for indication of
empty payload.

.. toctree::
   :maxdepth: 1

   pcap
   pcapng
   raw
   null
   checksum

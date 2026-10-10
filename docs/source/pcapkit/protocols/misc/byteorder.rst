Byte Order - Shared Byte-Order Helpers
======================================

.. module:: pcapkit.protocols.schema.misc.byteorder

:mod:`pcapkit.protocols.schema.misc.byteorder` contains the field callback that
reads a capture file's byte order out of the packet data. It is shared by the
PCAP frame header (:mod:`~pcapkit.protocols.schema.misc.pcap.frame`) and the
PCAP-NG blocks (:mod:`~pcapkit.protocols.schema.misc.pcapng`).

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.protocols.schema.misc.byteorder.byteorder_callback
.. autofunction:: pcapkit.protocols.schema.misc.byteorder.packet_byteorder

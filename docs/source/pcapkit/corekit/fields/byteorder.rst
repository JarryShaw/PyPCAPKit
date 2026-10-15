Byte-Order Helpers
==================

.. module:: pcapkit.corekit.fields.byteorder

:mod:`pcapkit.corekit.fields.byteorder` contains the field callback that reads
a capture file's byte order out of the packet data. It is shared by the PCAP
frame header (:mod:`~pcapkit.protocols.schema.misc.pcap.frame`) and the PCAP-NG
blocks (:mod:`~pcapkit.protocols.schema.misc.pcapng`).

.. versionadded:: 1.5.0

   :func:`byteorder_callback` moves here from
   :mod:`pcapkit.protocols.schema.misc.pcap.frame` (:issue:`1711`).

Auxiliary Functions
-------------------

.. autofunction:: pcapkit.corekit.fields.byteorder.byteorder_callback
.. autofunction:: pcapkit.corekit.fields.byteorder.packet_byteorder

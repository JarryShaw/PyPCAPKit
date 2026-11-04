Byte-Order Helpers
==================

.. module:: pcapkit.corekit.schema.byteorder

:mod:`pcapkit.corekit.schema.byteorder` reads the byte order a capture file or
section declares out of the packet data: :func:`byteorder_callback` sets it on a
:class:`~pcapkit.corekit.fields.numbers.NumberField` for the record header of a
classic PCAP file (:mod:`~pcapkit.protocols.misc.pcap.frame.schema`) and the
blocks of a PCAP-NG file (:mod:`~pcapkit.protocols.misc.pcapng.schema`), and
:func:`packet_byteorder` is what the callback and the PCAP-NG makers
(:mod:`pcapkit.protocols.misc.pcapng.protocol`) read it with. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.corekit.fields.byteorder``, with both its helpers
   (:issue:`2674`).

.. versionremoved:: 1.6.0

   ``pcapkit.corekit.fields.byteorder``, with no alias (:issue:`2674`).

.. autofunction:: pcapkit.corekit.schema.byteorder.byteorder_callback

.. autofunction:: pcapkit.corekit.schema.byteorder.packet_byteorder

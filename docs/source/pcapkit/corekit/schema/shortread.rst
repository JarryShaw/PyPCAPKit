Short-Read Replay
=================

.. module:: pcapkit.corekit.schema.shortread

:mod:`pcapkit.corekit.schema.shortread` carries a header cut short by the end of the
capture through to the protocol's info, by which a protocol rebuilt from that info
is cut back to the octets its header had (:issue:`1458`), for the layer base classes
and the PCAP global header alike. It names the protocol and schema classes for type
checking only, since those import it. It is one of the :mod:`pcapkit.corekit.schema`
helpers shared across the schema layer, not part of the header schema framework in
:mod:`pcapkit.protocols.schema`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.schema`` (:issue:`2674`).

.. autofunction:: pcapkit.corekit.schema.shortread.keep_short_read

.. autofunction:: pcapkit.corekit.schema.shortread.replay_short_read

Short-Read Replay
=================

.. module:: pcapkit.corekit.schema.short_read

:mod:`pcapkit.corekit.schema.short_read` carries a header cut short by the end of the
capture through to the protocol's info, by which a protocol rebuilt from that info
is cut back to the octets its header had (:issue:`1458`), for the layer base classes
and the PCAP global header alike, and tells a protocol's checks of a header parsed on
its own where the cut fell (:issue:`2880`). It names the protocol and schema classes
for type checking only, since those import it.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.schema`` (:issue:`2674`).

.. versionchanged:: 1.9.0

   Renamed from ``pcapkit.corekit.schema.shortread`` (:issue:`3153`).

.. versionremoved:: 1.9.0

   ``pcapkit.corekit.schema.shortread``, now
   :mod:`pcapkit.corekit.schema.short_read` (:issue:`3153`).

.. autofunction:: pcapkit.corekit.schema.short_read.keep_short_read

.. autofunction:: pcapkit.corekit.schema.short_read.replay_short_read

.. autofunction:: pcapkit.corekit.schema.short_read.hoist_short_read

.. autofunction:: pcapkit.corekit.schema.short_read.cut_on_its_own

.. autofunction:: pcapkit.corekit.schema.short_read.fill_short_options

.. autofunction:: pcapkit.corekit.schema.short_read.ends_inside_option

Short-Read Replay
=================

.. module:: pcapkit.corekit.schema.shortread

:mod:`pcapkit.corekit.schema.shortread` carries a header cut short by the end of the
capture through to the protocol's info, by which a protocol rebuilt from that info
is cut back to the octets its header had (:issue:`1458`), for the layer base classes
and the PCAP global header alike, and tells a protocol's checks of a header parsed on
its own where the cut fell (:issue:`2880`). It names the protocol and schema classes
for type checking only, since those import it.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.schema`` (:issue:`2674`).

.. autofunction:: pcapkit.corekit.schema.shortread.keep_short_read

.. autofunction:: pcapkit.corekit.schema.shortread.replay_short_read

.. autofunction:: pcapkit.corekit.schema.shortread.hoist_short_read

.. autofunction:: pcapkit.corekit.schema.shortread.cut_on_its_own

.. autofunction:: pcapkit.corekit.schema.shortread.fill_short_options

.. autofunction:: pcapkit.corekit.schema.shortread.ends_inside_option

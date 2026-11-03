Jumbo Payload Lookup
====================

.. module:: pcapkit.corekit.schema.jumbogram

:mod:`pcapkit.corekit.schema.jumbogram` finds the Jumbo Payload Length an IPv6
jumbogram declares in its Hop-by-Hop Options header [:rfc:`2675`], which is what
sizes a payload longer than the 16-bit Payload Length holds, for the IPv6 header
schema, the IPv6 pseudo-header and the Scapy toolkit alike. It is one of the
:mod:`pcapkit.corekit.schema` helpers shared across the schema layer, not part of
the header schema framework in :mod:`pcapkit.protocols.schema`; see
:ref:`utilities-or-corekit`.

.. versionadded:: 1.6.0

   Moved here from ``pcapkit.protocols.schema.internet.ipv6`` (:issue:`2674`).

.. autofunction:: pcapkit.corekit.schema.jumbogram.jumbo_payload_length

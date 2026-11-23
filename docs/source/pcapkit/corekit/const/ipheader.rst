IP Header Constants
===================

.. module:: pcapkit.corekit.const.ipheader

:mod:`pcapkit.corekit.const.ipheader` holds the IPv4, IPv6 and IP
Authentication Header lengths and offsets the RFCs fix and that code beyond their
own protocols reads: other protocols, IP reassembly and the toolkit. Each is the
one home of its value (:issue:`1739`), and none is configurable.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.internet.ipv4.schema``,
   ``pcapkit.protocols.internet.ipv6.protocol``,
   ``pcapkit.protocols.internet.ipv6.schema`` and
   ``pcapkit.protocols.internet.ah.schema`` (:issue:`2883`).

.. autodata:: pcapkit.corekit.const.ipheader.IP_MAX_LENGTH

.. autodata:: pcapkit.corekit.const.ipheader.IPV4_HEADER_LEN

.. autodata:: pcapkit.corekit.const.ipheader.IPV6_HEADER_LEN

.. autodata:: pcapkit.corekit.const.ipheader.IPV6_NEXT_HEADER_OFFSET

.. autodata:: pcapkit.corekit.const.ipheader.AH_HEADER_LEN

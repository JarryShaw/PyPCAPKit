TCP Header Constants
====================

.. module:: pcapkit.corekit.const.tcp_header

:mod:`pcapkit.corekit.const.tcp_header` holds the TCP header length and
offset the RFC fixes and that code beyond TCP itself reads: the toolkit. Each is
the one home of its value (:issue:`1739`), and none is configurable.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.transport.tcp.schema`` (:issue:`2883`).

.. versionchanged:: 1.9.0

   Renamed from ``pcapkit.corekit.const.tcpheader`` (:issue:`3153`).

.. versionremoved:: 1.9.0

   ``pcapkit.corekit.const.tcpheader``, now
   :mod:`pcapkit.corekit.const.tcp_header` (:issue:`3153`).

.. autodata:: pcapkit.corekit.const.tcp_header.TCP_MIN_HEADER_LEN

.. autodata:: pcapkit.corekit.const.tcp_header.TCP_DATA_OFFSET_OCTET

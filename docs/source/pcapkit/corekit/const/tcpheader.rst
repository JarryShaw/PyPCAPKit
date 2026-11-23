TCP Header Constants
====================

.. module:: pcapkit.corekit.const.tcpheader

:mod:`pcapkit.corekit.const.tcpheader` holds the TCP header length and
offset the RFC fixes and that code beyond TCP itself reads: the toolkit. Each is
the one home of its value (:issue:`1739`), and none is configurable.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.transport.tcp.schema`` (:issue:`2883`).

.. autodata:: pcapkit.corekit.const.tcpheader.TCP_MIN_HEADER_LEN

.. autodata:: pcapkit.corekit.const.tcpheader.TCP_DATA_OFFSET_OCTET

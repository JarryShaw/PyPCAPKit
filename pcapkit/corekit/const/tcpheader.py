# -*- coding: utf-8 -*-
"""TCP Header Constants
==========================

.. module:: pcapkit.corekit.const.tcpheader

:mod:`pcapkit.corekit.const.tcpheader` holds the TCP header length and
offset the RFC fixes and that code beyond TCP itself reads: the toolkit. Each is
the one home of its value (:issue:`1739`), and none is configurable. It is one
topic of :mod:`pcapkit.corekit.const`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.transport.tcp.schema`` (:issue:`2883`).

"""

__all__ = ['TCP_MIN_HEADER_LEN', 'TCP_DATA_OFFSET_OCTET']

#: Minimum length of a TCP header, i.e. the fixed part with no options,
#: :rfc:`9293#section-3.1`.
TCP_MIN_HEADER_LEN = 20

#: Offset of the octet whose high four bits are the Data Offset field -- the
#: header length in 32-bit words -- within a TCP header, :rfc:`9293#section-3.1`.
TCP_DATA_OFFSET_OCTET = 12

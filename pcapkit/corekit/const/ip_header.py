# -*- coding: utf-8 -*-
"""IP Header Constants
=========================

.. module:: pcapkit.corekit.const.ip_header

:mod:`pcapkit.corekit.const.ip_header` holds the IPv4, IPv6 and IP
Authentication Header lengths and offsets the RFCs fix and that code beyond their
own protocols reads: other protocols, IP reassembly and the toolkit. Each is the
one home of its value (:issue:`1739`), and none is configurable. It is one topic
of :mod:`pcapkit.corekit.const`; see :ref:`utilities-or-corekit`.

.. versionadded:: 1.7.0

   Moved here from ``pcapkit.protocols.internet.ipv4.schema``,
   ``pcapkit.protocols.internet.ipv6.protocol``,
   ``pcapkit.protocols.internet.ipv6.schema`` and
   ``pcapkit.protocols.internet.ah.schema`` (:issue:`2883`).

.. versionchanged:: 1.9.0

   Renamed from ``pcapkit.corekit.const.ipheader`` (:issue:`3153`).

.. versionremoved:: 1.9.0

   ``pcapkit.corekit.const.ipheader``, now
   :mod:`pcapkit.corekit.const.ip_header` (:issue:`3153`).

"""

__all__ = [
    'IP_MAX_LENGTH', 'IPV4_HEADER_LEN', 'IPV6_HEADER_LEN', 'IPV6_NEXT_HEADER_OFFSET',
    'AH_HEADER_LEN',
]

#: The most octets a 16-bit IP length field declares, for IPv4's Total Length
#: the header included (:rfc:`791#section-3.1`) and for IPv6's Payload Length
#: the fixed header excluded (:rfc:`8200#section-3`); a longer IPv6 payload is
#: a jumbogram, whose Jumbo Payload Length must exceed it (:rfc:`2675#section-2`).
IP_MAX_LENGTH = 65535

#: Length of the fixed IPv4 header, i.e. with no options, :rfc:`791#section-3.1`.
IPV4_HEADER_LEN = 20

#: Length of the fixed IPv6 header, i.e. the offset of the first extension
#: header, :rfc:`8200#section-3`.
IPV6_HEADER_LEN = 40

#: Offset of the Next Header field within the fixed IPv6 header,
#: :rfc:`8200#section-3`.
IPV6_NEXT_HEADER_OFFSET = 6

#: Length of the fixed part of an IP Authentication Header (AH), before its
#: Integrity Check Value, :rfc:`4302#section-2`.
AH_HEADER_LEN = 12

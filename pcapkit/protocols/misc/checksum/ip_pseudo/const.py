# -*- coding: utf-8 -*-
"""constants for the IP pseudo-header

.. versionadded:: 1.7.0

"""
import ipaddress

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader

__all__ = ['IPV4_PSEUDO_LEN', 'IPV6_PSEUDO_LEN']

#: Length of the IPv4 pseudo-header, :rfc:`793#section-3.1` -- source, destination,
#: zero, protocol and length.
#:
#: .. versionadded:: 1.6.0
IPV4_PSEUDO_LEN = 2 * (ipaddress.IPV4LENGTH // 8) + 1 + 1 + 2

#: Length of the IPv6 pseudo-header, :rfc:`8200#section-8.1` -- source, destination,
#: length, zero and next header.
#:
#: .. versionadded:: 1.6.0
IPV6_PSEUDO_LEN = 2 * (ipaddress.IPV6LENGTH // 8) + 4 + 3 + 1

#: Extension headers that end the chain, as the upper layer -- the Mobility Header
#: (:rfc:`6275#section-6.1.1`) and HIP (:rfc:`7401#section-5.1.1`).
_TERMINAL_HEADERS = (Enum_ExtensionHeader.Mobility_Header, Enum_ExtensionHeader.HIP)

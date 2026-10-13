# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv6 Extension Header Types
=================================

.. module:: pcapkit.const.ipv6.extension_header

This module contains the constant enumeration for **IPv6 Extension Header Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.extension_header.ExtensionHeader`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ExtensionHeader']


class ExtensionHeader(EnumRegistry, IntEnum):
    """[ExtensionHeader] IPv6 Extension Header Types"""

    #: HOPOPT, IPv6 Hop-by-Hop Option [RFC 8200]
    HOPOPT = 0

    #: IPv6-Route, Routing Header for IPv6 [RFC 8200][; ][RFC 5095]
    IPv6_Route = 43

    #: IPv6-Frag, Fragment Header for IPv6 [RFC 8200]
    IPv6_Frag = 44

    #: ESP, Encapsulating Security Payload [RFC 4303]
    ESP = 50

    #: AH, Authentication Header [RFC 4302]
    AH = 51

    #: IPv6-Opts, Destination Options for IPv6 [RFC 8200]
    IPv6_Opts = 60

    #: Mobility Header [RFC 6275]
    Mobility_Header = 135

    #: HIP, Host Identity Protocol [RFC 7401]
    HIP = 139

    #: Shim6, Shim6 Protocol [RFC 5533]
    Shim6 = 140

    #: Use for experimentation and testing [RFC 3692][; ][RFC 4727]
    Use_for_experimentation_and_testing_253 = 253

    #: Use for experimentation and testing [RFC 3692][; ][RFC 4727]
    Use_for_experimentation_and_testing_254 = 254

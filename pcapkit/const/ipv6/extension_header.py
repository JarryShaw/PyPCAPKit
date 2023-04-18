# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPv6 Extension Header Types
=================================

.. module:: pcapkit.const.ipv6.extension_header

This module contains the constant enumeration for **IPv6 Extension Header Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.extension_header.ExtensionHeader`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ExtensionHeader']


class ExtensionHeader(IntEnum):
    """[ExtensionHeader] IPv6 Extension Header Types"""

    #: HOPOPT, IPv6 Hop-by-Hop Option [:rfc:`8200`]
    HOPOPT = 0

    #: IPv6-Route, Routing Header for IPv6 [Steve Deering]
    IPv6_Route = 43

    #: IPv6-Frag, Fragment Header for IPv6 [Steve Deering]
    IPv6_Frag = 44

    #: ESP, Encap Security Payload [:rfc:`4303`]
    ESP = 50

    #: AH, Authentication Header [:rfc:`4302`]
    AH = 51

    #: IPv6-Opts, Destination Options for IPv6 [:rfc:`8200`]
    IPv6_Opts = 60

    #: Mobility Header [:rfc:`6275`]
    Mobility_Header = 135

    #: HIP, Host Identity Protocol [:rfc:`7401`]
    HIP = 139

    #: Shim6, Shim6 Protocol [:rfc:`5533`]
    Shim6 = 140

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_253 = 253

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_254 = 254

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ExtensionHeader':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ExtensionHeader(key)
        return ExtensionHeader[key]  # type: ignore[misc]

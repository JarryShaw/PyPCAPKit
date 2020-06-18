# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv6 Extension Header Types"""

from aenum import IntEnum, extend_enum

__all__ = ['ExtensionHeader']


class ExtensionHeader(IntEnum):
    """[ExtensionHeader] IPv6 Extension Header Types"""

    #: HOPOPT [:rfc:`8200`] IPv6 Hop-by-Hop Option
    HOPOPT = 0

    #: IPv6-Route [Steve Deering] Routing Header for IPv6
    IPv6_Route = 43

    #: IPv6-Frag [Steve Deering] Fragment Header for IPv6
    IPv6_Frag = 44

    #: ESP [:rfc:`4303`] Encap Security Payload
    ESP = 50

    #: AH [:rfc:`4302`] Authentication Header
    AH = 51

    #: IPv6-Opts [:rfc:`8200`] Destination Options for IPv6
    IPv6_Opts = 60

    #: Mobility Header [:rfc:`6275`]
    Mobility_Header = 135

    #: HIP [:rfc:`7401`] Host Identity Protocol
    HIP = 139

    #: Shim6 [:rfc:`5533`] Shim6 Protocol
    Shim6 = 140

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_253 = 253

    #: Use for experimentation and testing [:rfc:`3692`]
    Use_for_experimentation_and_testing_254 = 254

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ExtensionHeader(key)
        if key not in ExtensionHeader._member_map_:  # pylint: disable=no-member
            extend_enum(ExtensionHeader, key, default)
        return ExtensionHeader[key]

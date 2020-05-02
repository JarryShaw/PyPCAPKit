# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IPv6 Extension Header Types"""

from aenum import IntEnum, extend_enum

__all__ = ['ExtensionHeader']


class ExtensionHeader(IntEnum):
    """[ExtensionHeader] IPv6 Extension Header Types"""

    _ignore_ = 'ExtensionHeader _'
    ExtensionHeader = vars()

    #: [:rfc:`8200`] IPv6 Hop-by-Hop Option
    ExtensionHeader['HOPOPT'] = 0

    #: [Steve Deering] Routing Header for IPv6
    ExtensionHeader['IPv6_Route'] = 43

    #: [Steve Deering] Fragment Header for IPv6
    ExtensionHeader['IPv6_Frag'] = 44

    #: [:rfc:`4303`] Encap Security Payload
    ExtensionHeader['ESP'] = 50

    #: [:rfc:`4302`] Authentication Header
    ExtensionHeader['AH'] = 51

    #: [:rfc:`8200`] Destination Options for IPv6
    ExtensionHeader['IPv6_Opts'] = 60

    #: [:rfc:`6275`]
    ExtensionHeader['Mobility_Header'] = 135

    #: [:rfc:`7401`] Host Identity Protocol
    ExtensionHeader['HIP'] = 139

    #: [:rfc:`5533`] Shim6 Protocol
    ExtensionHeader['Shim6'] = 140

    #: [:rfc:`3692`]
    ExtensionHeader['Use_For_Experimentation_And_Testing_253'] = 253

    #: [:rfc:`3692`]
    ExtensionHeader['Use_For_Experimentation_And_Testing_254'] = 254

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ExtensionHeader(key)
        if key not in ExtensionHeader._member_map_:  # pylint: disable=no-member
            extend_enum(ExtensionHeader, key, default)
        return ExtensionHeader[key]

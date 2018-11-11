# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class ExtensionHeader(IntEnum):
    """Enumeration class for ExtensionHeader."""
    _ignore_ = 'ExtensionHeader _'
    ExtensionHeader = vars()

    # IPv6 Extension Header Types
    ExtensionHeader['HOPOPT'] = 0                                               # [RFC 8200] IPv6 Hop-by-Hop Option
    ExtensionHeader['IPv6-Route'] = 43                                          # [Steve_Deering] Routing Header for IPv6
    ExtensionHeader['IPv6-Frag'] = 44                                           # [Steve_Deering] Fragment Header for IPv6
    ExtensionHeader['ESP'] = 50                                                 # [RFC 4303] Encap Security Payload
    ExtensionHeader['AH'] = 51                                                  # [RFC 4302] Authentication Header
    ExtensionHeader['IPv6-Opts'] = 60                                           # [RFC 8200] Destination Options for IPv6
    ExtensionHeader['Mobility Header'] = 135                                    # [RFC 6275]
    ExtensionHeader['HIP'] = 139                                                # [RFC 7401] Host Identity Protocol
    ExtensionHeader['Shim6'] = 140                                              # [RFC 5533] Shim6 Protocol
    ExtensionHeader['Use for experimentation and testing [253]'] = 253          # [RFC 3692]
    ExtensionHeader['Use for experimentation and testing [254]'] = 254          # [RFC 3692]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ExtensionHeader(key)
        if key not in ExtensionHeader._member_map_:
            extend_enum(ExtensionHeader, key, default)
        return ExtensionHeader[key]

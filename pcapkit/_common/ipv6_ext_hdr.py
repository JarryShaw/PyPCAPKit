# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class EXT_HDR(IntEnum):
    """Enumeration class for EXT_HDR."""
    _ignore_ = 'EXT_HDR _'
    EXT_HDR = vars()

    # IPv6 Extension Header Types
    EXT_HDR['HOPOPT'] = 0                                                       # [RFC 8200] IPv6 Hop-by-Hop Option
    EXT_HDR['IPv6-Route'] = 43                                                  # [Steve_Deering] Routing Header for IPv6
    EXT_HDR['IPv6-Frag'] = 44                                                   # [Steve_Deering] Fragment Header for IPv6
    EXT_HDR['ESP'] = 50                                                         # [RFC 4303] Encap Security Payload
    EXT_HDR['AH'] = 51                                                          # [RFC 4302] Authentication Header
    EXT_HDR['IPv6-Opts'] = 60                                                   # [RFC 8200] Destination Options for IPv6
    EXT_HDR['Mobility Header'] = 135                                            # [RFC 6275]
    EXT_HDR['HIP'] = 139                                                        # [RFC 7401] Host Identity Protocol
    EXT_HDR['Shim6'] = 140                                                      # [RFC 5533] Shim6 Protocol
    EXT_HDR['Use for experimentation and testing [253]'] = 253                  # [RFC 3692]
    EXT_HDR['Use for experimentation and testing [254]'] = 254                  # [RFC 3692]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return EXT_HDR(key)
        if key not in EXT_HDR._member_map_:
            extend_enum(EXT_HDR, key, default)
        return EXT_HDR[key]

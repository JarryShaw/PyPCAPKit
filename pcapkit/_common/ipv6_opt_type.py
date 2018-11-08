# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Options(IntEnum):
    """Enumeration class for Options."""
    _ignore_ = 'Options _'
    Options = vars()

    # Destination Options and Hop-by-Hop Options
    Options['PAD'] = 0x00                                                       # [IPV6]
    Options['PADN'] = 0x01                                                      # [IPV6]
    Options['JUMBO'] = 0xC2                                                     # [RFC 2675]
    Options['RPL'] = 0x63                                                       # [RFC 6553]
    Options['TUN'] = 0x04                                                       # [RFC 2473]
    Options['RA'] = 0x05                                                        # [RFC 2711]
    Options['QS'] = 0x26                                                        # [RFC 4782][RFC  Errata            2034]
    Options['CALIPSO'] = 0x07                                                   # [RFC 5570]
    Options['SMF_DPD'] = 0x08                                                   # [RFC 6621]
    Options['HOME'] = 0xC9                                                      # [RFC 6275]
    Options['DEPRECATED'] = 0x8A                                                # [CHARLES LYNN]
    Options['ILNP'] = 0x8B                                                      # [RFC 6744]
    Options['LIO'] = 0x8C                                                       # [RFC 6788]
    Options['Deprecated'] = 0x4D                                                # [RFC 7731]
    Options['MPL'] = 0x6D                                                       # [RFC 7731]
    Options['IP_DFF'] = 0xEE                                                    # [RFC 6971]
    Options['PDM'] = 0x0F                                                       # [RFC 8250]
    Options['RFC3692-style Experiment [0x1E]'] = 0x1E                           # [RFC 4727]
    Options['RFC3692-style Experiment [0x3E]'] = 0x3E                           # [RFC 4727]
    Options['RFC3692-style Experiment [0x5E]'] = 0x5E                           # [RFC 4727]
    Options['RFC3692-style Experiment [0x7E]'] = 0x7E                           # [RFC 4727]
    Options['RFC3692-style Experiment [0x9E]'] = 0x9E                           # [RFC 4727]
    Options['RFC3692-style Experiment [0xBE]'] = 0xBE                           # [RFC 4727]
    Options['RFC3692-style Experiment [0xDE]'] = 0xDE                           # [RFC 4727]
    Options['RFC3692-style Experiment [0xFE]'] = 0xFE                           # [RFC 4727]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Options(key)
        if key not in Options._member_map_:
            extend_enum(Options, key, default)
        return Options[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(2), value)
        return cls(value)

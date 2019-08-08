# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Option(IntEnum):
    """Enumeration class for Option."""
    _ignore_ = 'Option _'
    Option = vars()

    # TCP Option Kind Numbers
    Option['EOOL'] = 0                                                          # [RFC 793]
    Option['NOP'] = 1                                                           # [RFC 793]
    Option['MSS'] = 2                                                           # [RFC 793]
    Option['WS'] = 3                                                            # [RFC 7323]
    Option['SACKPMT'] = 4                                                       # [RFC 2018]
    Option['SACK'] = 5                                                          # [RFC 2018]
    Option['ECHO'] = 6                                                          # [RFC 1072][RFC 6247]
    Option['ECHORE'] = 7                                                        # [RFC 1072][RFC 6247]
    Option['TS'] = 8                                                            # [RFC 7323]
    Option['POC'] = 9                                                           # [RFC 1693][RFC 6247]
    Option['POCSP'] = 10                                                        # [RFC 1693][RFC 6247]
    Option['CC'] = 11                                                           # [RFC 1644][RFC 6247]
    Option['CCNEW'] = 12                                                        # [RFC 1644][RFC 6247]
    Option['CCECHO'] = 13                                                       # [RFC 1644][RFC 6247]
    Option['CHKREQ'] = 14                                                       # [RFC 1146][RFC 6247]
    Option['CHKSUM'] = 15                                                       # [RFC 1146][RFC 6247]
    Option['Skeeter'] = 16                                                      # [Stev_Knowles]
    Option['Bubba'] = 17                                                        # [Stev_Knowles]
    Option['Trailer Checksum Option'] = 18                                      # [Subbu_Subramaniam][Monroe_Bridges]
    Option['SIG'] = 19                                                          # [RFC 2385]
    Option['SCPS Capabilities'] = 20                                            # [Keith_Scott]
    Option['Selective Negative Acknowledgements'] = 21                          # [Keith_Scott]
    Option['Record Boundaries'] = 22                                            # [Keith_Scott]
    Option['Corruption experienced'] = 23                                       # [Keith_Scott]
    Option['SNAP'] = 24                                                         # [Vladimir_Sukonnik]
    Option['Unassigned'] = 25
    Option['TCP Compression Filter'] = 26                                       # [Steve_Bellovin]
    Option['QS'] = 27                                                           # [RFC 4782]
    Option['TIMEOUT'] = 28                                                      # [RFC 5482]
    Option['AO'] = 29                                                           # [RFC 5925]
    Option['MP'] = 30                                                           # [RFC -ietf-mptcp-rfc6824bis-18]
    Option['Reserved [31]'] = 31
    Option['Reserved [32]'] = 32
    Option['Reserved [33]'] = 33
    Option['FASTOPEN'] = 34                                                     # [RFC 7413]
    Option['Encryption Negotiation'] = 69                                       # [RFC 8547]
    Option['Reserved [70]'] = 70
    Option['Reserved [76]'] = 76
    Option['Reserved [77]'] = 77
    Option['Reserved [78]'] = 78
    Option['RFC3692-style Experiment 1'] = 253                                  # [RFC 4727]
    Option['RFC3692-style Experiment 2'] = 254                                  # [RFC 4727]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Option(key)
        if key not in Option._member_map_:
            extend_enum(Option, key, default)
        return Option[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        if 35 <= value <= 68:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        if 71 <= value <= 75:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        if 79 <= value <= 252:
            extend_enum(cls, 'Reserved [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

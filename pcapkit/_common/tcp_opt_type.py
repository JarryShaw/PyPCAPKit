# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Options(IntEnum):
    """Enumeration class for Options."""
    _ignore_ = 'Options _'
    Options = vars()

    # TCP Option Kind Numbers
    Options['EOOL'] = 0                                                         # [RFC 793]
    Options['NOP'] = 1                                                          # [RFC 793]
    Options['MSS'] = 2                                                          # [RFC 793]
    Options['WS'] = 3                                                           # [RFC 7323]
    Options['SACKPMT'] = 4                                                      # [RFC 2018]
    Options['SACK'] = 5                                                         # [RFC 2018]
    Options['ECHO'] = 6                                                         # [RFC 1072][RFC 6247]
    Options['ECHORE'] = 7                                                       # [RFC 1072][RFC 6247]
    Options['TS'] = 8                                                           # [RFC 7323]
    Options['POC'] = 9                                                          # [RFC 1693][RFC 6247]
    Options['POCSP'] = 10                                                       # [RFC 1693][RFC 6247]
    Options['CC'] = 11                                                          # [RFC 1644][RFC 6247]
    Options['CCNEW'] = 12                                                       # [RFC 1644][RFC 6247]
    Options['CCECHO'] = 13                                                      # [RFC 1644][RFC 6247]
    Options['CHKREQ'] = 14                                                      # [RFC 1146][RFC 6247]
    Options['CHKSUM'] = 15                                                      # [RFC 1146][RFC 6247]
    Options['Skeeter'] = 16                                                     # [Stev_Knowles]
    Options['Bubba'] = 17                                                       # [Stev_Knowles]
    Options['Trailer Checksum Option'] = 18                                     # [Subbu_Subramaniam][Monroe_Bridges]
    Options['SIG'] = 19                                                         # [RFC 2385]
    Options['SCPS Capabilities'] = 20                                           # [Keith_Scott]
    Options['Selective Negative Acknowledgements'] = 21                         # [Keith_Scott]
    Options['Record Boundaries'] = 22                                           # [Keith_Scott]
    Options['Corruption experienced'] = 23                                      # [Keith_Scott]
    Options['SNAP'] = 24                                                        # [Vladimir_Sukonnik]
    Options['Unassigned'] = 25
    Options['TCP Compression Filter'] = 26                                      # [Steve_Bellovin]
    Options['QS'] = 27                                                          # [RFC 4782]
    Options['TIMEOUT'] = 28                                                     # [RFC 5482]
    Options['AO'] = 29                                                          # [RFC 5925]
    Options['MP'] = 30                                                          # [RFC 6824]
    Options['Reserved [31]'] = 31
    Options['Reserved [32]'] = 32
    Options['Reserved [33]'] = 33
    Options['FASTOPEN'] = 34                                                    # [RFC 7413]
    Options['Reserved [69]'] = 69
    Options['Reserved [70]'] = 70
    Options['Reserved [76]'] = 76
    Options['Reserved [77]'] = 77
    Options['Reserved [78]'] = 78
    Options['RFC3692-style Experiment 1'] = 253                                 # [RFC 4727]
    Options['RFC3692-style Experiment 2'] = 254                                 # [RFC 4727]

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

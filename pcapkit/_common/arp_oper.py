# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class OperType(IntEnum):
    """Enumeration class for OperType."""
    _ignore_ = 'OperType _'
    OperType = vars()

    # Operation Codes [RFC 826][RFC 5494]
    OperType['Reserved [0]'] = 0                                                # [RFC 5494]
    OperType['REQUEST'] = 1                                                     # [RFC 826][RFC 5227]
    OperType['REPLY'] = 2                                                       # [RFC 826][RFC 5227]
    OperType['request Reverse'] = 3                                             # [RFC 903]
    OperType['reply Reverse'] = 4                                               # [RFC 903]
    OperType['DRARP-Request'] = 5                                               # [RFC 1931]
    OperType['DRARP-Reply'] = 6                                                 # [RFC 1931]
    OperType['DRARP-Error'] = 7                                                 # [RFC 1931]
    OperType['InARP-Request'] = 8                                               # [RFC 2390]
    OperType['InARP-Reply'] = 9                                                 # [RFC 2390]
    OperType['ARP-NAK'] = 10                                                    # [RFC 1577]
    OperType['MARS-Request'] = 11                                               # [Grenville_Armitage]
    OperType['MARS-Multi'] = 12                                                 # [Grenville_Armitage]
    OperType['MARS-MServ'] = 13                                                 # [Grenville_Armitage]
    OperType['MARS-Join'] = 14                                                  # [Grenville_Armitage]
    OperType['MARS-Leave'] = 15                                                 # [Grenville_Armitage]
    OperType['MARS-NAK'] = 16                                                   # [Grenville_Armitage]
    OperType['MARS-Unserv'] = 17                                                # [Grenville_Armitage]
    OperType['MARS-SJoin'] = 18                                                 # [Grenville_Armitage]
    OperType['MARS-SLeave'] = 19                                                # [Grenville_Armitage]
    OperType['MARS-Grouplist-Request'] = 20                                     # [Grenville_Armitage]
    OperType['MARS-Grouplist-Reply'] = 21                                       # [Grenville_Armitage]
    OperType['MARS-Redirect-Map'] = 22                                          # [Grenville_Armitage]
    OperType['MAPOS-UNARP'] = 23                                                # [Mitsuru_Maruyama][RFC 2176]
    OperType['OP_EXP1'] = 24                                                    # [RFC 5494]
    OperType['OP_EXP2'] = 25                                                    # [RFC 5494]
    OperType['Reserved [65535]'] = 65535                                        # [RFC 5494]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OperType(key)
        if key not in OperType._member_map_:
            extend_enum(OperType, key, default)
        return OperType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 26 <= value <= 65534:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

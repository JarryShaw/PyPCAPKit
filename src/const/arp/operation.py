# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Operation(IntEnum):
    """Enumeration class for Operation."""
    _ignore_ = 'Operation _'
    Operation = vars()

    # Operation Codes [RFC 826][RFC 5494]
    Operation['Reserved [0]'] = 0                                               # [RFC 5494]
    Operation['REQUEST'] = 1                                                    # [RFC 826][RFC 5227]
    Operation['REPLY'] = 2                                                      # [RFC 826][RFC 5227]
    Operation['request Reverse'] = 3                                            # [RFC 903]
    Operation['reply Reverse'] = 4                                              # [RFC 903]
    Operation['DRARP-Request'] = 5                                              # [RFC 1931]
    Operation['DRARP-Reply'] = 6                                                # [RFC 1931]
    Operation['DRARP-Error'] = 7                                                # [RFC 1931]
    Operation['InARP-Request'] = 8                                              # [RFC 2390]
    Operation['InARP-Reply'] = 9                                                # [RFC 2390]
    Operation['ARP-NAK'] = 10                                                   # [RFC 1577]
    Operation['MARS-Request'] = 11                                              # [Grenville_Armitage]
    Operation['MARS-Multi'] = 12                                                # [Grenville_Armitage]
    Operation['MARS-MServ'] = 13                                                # [Grenville_Armitage]
    Operation['MARS-Join'] = 14                                                 # [Grenville_Armitage]
    Operation['MARS-Leave'] = 15                                                # [Grenville_Armitage]
    Operation['MARS-NAK'] = 16                                                  # [Grenville_Armitage]
    Operation['MARS-Unserv'] = 17                                               # [Grenville_Armitage]
    Operation['MARS-SJoin'] = 18                                                # [Grenville_Armitage]
    Operation['MARS-SLeave'] = 19                                               # [Grenville_Armitage]
    Operation['MARS-Grouplist-Request'] = 20                                    # [Grenville_Armitage]
    Operation['MARS-Grouplist-Reply'] = 21                                      # [Grenville_Armitage]
    Operation['MARS-Redirect-Map'] = 22                                         # [Grenville_Armitage]
    Operation['MAPOS-UNARP'] = 23                                               # [Mitsuru_Maruyama][RFC 2176]
    Operation['OP_EXP1'] = 24                                                   # [RFC 5494]
    Operation['OP_EXP2'] = 25                                                   # [RFC 5494]
    Operation['Reserved [65535]'] = 65535                                       # [RFC 5494]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Operation(key)
        if key not in Operation._member_map_:
            extend_enum(Operation, key, default)
        return Operation[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 26 <= value <= 65534:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

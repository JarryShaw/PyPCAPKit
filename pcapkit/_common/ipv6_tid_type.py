# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class TaggerId(IntEnum):
    """Enumeration class for TaggerId."""
    _ignore_ = 'TaggerId _'
    TaggerId = vars()

    # TaggerId Types
    TaggerId['NULL'] = 0                                                        # [RFC 6621]
    TaggerId['DEFAULT'] = 1                                                     # [RFC 6621]
    TaggerId['IPv4'] = 2                                                        # [RFC 6621]
    TaggerId['IPv6'] = 3                                                        # [RFC 6621]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TaggerId(key)
        if key not in TaggerId._member_map_:
            extend_enum(TaggerId, key, default)
        return TaggerId[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 7:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

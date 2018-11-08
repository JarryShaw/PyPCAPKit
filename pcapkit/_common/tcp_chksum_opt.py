# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ChksumOpt(IntEnum):
    """Enumeration class for ChksumOpt."""
    _ignore_ = 'ChksumOpt _'
    ChksumOpt = vars()

    # [RFC 1146]
    ChksumOpt['TCP checksum'] = 0
    ChksumOpt["8-bit Fletcher's algorithm"] = 1
    ChksumOpt["16-bit Fletcher's algorithm"] = 2
    ChksumOpt['Redundant Checksum Avoidance'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ChksumOpt(key)
        if key not in ChksumOpt._member_map_:
            extend_enum(ChksumOpt, key, default)
        return ChksumOpt[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)

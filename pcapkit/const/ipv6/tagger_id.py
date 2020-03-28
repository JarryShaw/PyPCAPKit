# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""TaggerID Types"""

from aenum import IntEnum, extend_enum


class TaggerID(IntEnum):
    """Enumeration class for TaggerID."""
    _ignore_ = 'TaggerID _'
    TaggerID = vars()

    # TaggerID Types
    TaggerID['NULL'] = 0                                                        # [RFC 6621]
    TaggerID['DEFAULT'] = 1                                                     # [RFC 6621]
    TaggerID['IPv4'] = 2                                                        # [RFC 6621]
    TaggerID['IPv6'] = 3                                                        # [RFC 6621]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return TaggerID(key)
        if key not in TaggerID._member_map_:  # pylint: disable=no-member
            extend_enum(TaggerID, key, default)
        return TaggerID[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 7:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        return super()._missing_(value)

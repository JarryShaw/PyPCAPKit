# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class DI(IntEnum):
    """Enumeration class for DI."""
    _ignore_ = 'DI _'
    DI = vars()

    # DI-Types
    DI['none included'] = 0                                                     # [RFC 7401]
    DI['FQDN'] = 1                                                              # [RFC 7401]
    DI['NAI'] = 2                                                               # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return DI(key)
        if key not in DI._member_map_:
            extend_enum(DI, key, default)
        return DI[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 15:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

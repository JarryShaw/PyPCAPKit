# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Group(IntEnum):
    """Enumeration class for Group."""
    _ignore_ = 'Group _'
    Group = vars()

    # Group IDs
    Group['Reserved'] = 0                                                       # [RFC 7401]
    Group['384-bit group'] = 1                                                  # [RFC 5201] DEPRECATED
    Group['OAKLEY well known group 1'] = 2                                      # [RFC 5201] DEPRECATED
    Group['1536-bit MODP group'] = 3                                            # [RFC 7401]
    Group['3072-bit MODP group'] = 4                                            # [RFC 7401]
    Group['6144-bit MODP group'] = 5                                            # [RFC 5201] DEPRECATED
    Group['8192-bit MODP group'] = 6                                            # [RFC 5201] DEPRECATED
    Group['NIST P-256'] = 7                                                     # [RFC 7401]
    Group['NIST P-384'] = 8                                                     # [RFC 7401]
    Group['NIST P-521'] = 9                                                     # [RFC 7401]
    Group['SECP160R1'] = 10                                                     # [RFC 7401]
    Group['2048-bit MODP group'] = 11                                           # [RFC 7401]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Group(key)
        if key not in Group._member_map_:
            extend_enum(Group, key, default)
        return Group[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 12 <= value <= 255:
            extend_enum(cls, 'Unassigned [%d]' % value, value)
            return cls(value)
        super()._missing_(value)

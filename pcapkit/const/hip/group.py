# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Group IDs"""

from aenum import IntEnum, extend_enum

__all__ = ['Group']


class Group(IntEnum):
    """[Group] Group IDs"""

    _ignore_ = 'Group _'
    Group = vars()

    #: [:rfc:`7401`]
    Group['Reserved'] = 0

    #: [:rfc:`5201`] DEPRECATED
    Group['384-bit group'] = 1

    #: [:rfc:`5201`] DEPRECATED
    Group['OAKLEY well known group 1'] = 2

    #: [:rfc:`7401`]
    Group['1536-bit MODP group'] = 3

    #: [:rfc:`7401`]
    Group['3072-bit MODP group'] = 4

    #: [:rfc:`5201`] DEPRECATED
    Group['6144-bit MODP group'] = 5

    #: [:rfc:`5201`] DEPRECATED
    Group['8192-bit MODP group'] = 6

    #: [:rfc:`7401`]
    Group['NIST P-256'] = 7

    #: [:rfc:`7401`]
    Group['NIST P-384'] = 8

    #: [:rfc:`7401`]
    Group['NIST P-521'] = 9

    #: [:rfc:`7401`]
    Group['SECP160R1'] = 10

    #: [:rfc:`7401`]
    Group['2048-bit MODP group'] = 11

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Group(key)
        if key not in Group._member_map_:  # pylint: disable=no-member
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
        return super()._missing_(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""DI-Types"""

from aenum import IntEnum, extend_enum

__all__ = ['DITypes']


class DITypes(IntEnum):
    """[DITypes] DI-Types"""

    #: none included [:rfc:`7401`]
    none_included = 0

    #: FQDN [:rfc:`7401`]
    FQDN = 1

    #: NAI [:rfc:`7401`]
    NAI = 2

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return DITypes(key)
        if key not in DITypes._member_map_:  # pylint: disable=no-member
            extend_enum(DITypes, key, default)
        return DITypes[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 15:
            #: Unassigned
            extend_enum(cls, 'Unassigned_%d' % value, value)
            return cls(value)
        return super()._missing_(value)

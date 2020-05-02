# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Transport Modes"""

from aenum import IntEnum, extend_enum

__all__ = ['Transport']


class Transport(IntEnum):
    """[Transport] HIP Transport Modes"""

    _ignore_ = 'Transport _'
    Transport = vars()

    #: [:rfc:`6261`]
    Transport['RESERVED'] = 0

    #: [:rfc:`6261`]
    Transport['DEFAULT'] = 1

    #: [:rfc:`6261`]
    Transport['ESP'] = 2

    #: [:rfc:`6261`]
    Transport['ESP_TCP'] = 3

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Transport(key)
        if key not in Transport._member_map_:  # pylint: disable=no-member
            extend_enum(Transport, key, default)
        return Transport[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)

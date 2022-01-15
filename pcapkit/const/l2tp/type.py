# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Layer 2 Tunneling Protocol (L2TP) Header Types"""

from aenum import IntEnum, extend_enum

__all__ = ['Type']


class Type(IntEnum):
    """[Type] Layer 2 Tunneling Protocol (L2TP) Header Types"""

    #: Control.
    Control = 1

    #: Data.
    Data = 0

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Type(key)
        if key not in Type._member_map_:  # pylint: disable=no-member
            extend_enum(Type, key, default)
        return Type[key]

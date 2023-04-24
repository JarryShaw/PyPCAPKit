# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Option Types
==================

.. module:: pcapkit.const.pcapng.option_type

This module contains the constant enumeration for **Option Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.option_type.OptionType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionType']


class OptionType(IntEnum):
    """[OptionType] Option Types"""

    #: opt_endofopt
    endofopt = 0

    #: opt_comment
    comment = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OptionType(key)
        if key not in OptionType._member_map_:  # pylint: disable=no-member
            extend_enum(OptionType, key, default)
        return OptionType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if value in (2988, 2989, 19372, 19373):
            #: opt_custom
            extend_enum(cls, 'custom_%d' % value, value)
            return cls(value)
        return super()._missing_(value)

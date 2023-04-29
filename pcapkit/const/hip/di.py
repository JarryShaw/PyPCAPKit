# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DI-Types
==============

.. module:: pcapkit.const.hip.di

This module contains the constant enumeration for **DI-Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.di.DITypes`.

"""

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
    def get(key: 'int | str', default: 'int' = -1) -> 'DITypes':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return DITypes(key)
        if key not in DITypes._member_map_:  # pylint: disable=no-member
            return extend_enum(DITypes, key, default)
        return DITypes[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'DITypes':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 15:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TaggerID Types
====================

.. module:: pcapkit.const.ipv6.tagger_id

This module contains the constant enumeration for **TaggerID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.tagger_id.TaggerID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['TaggerID']


class TaggerID(IntEnum):
    """[TaggerID] TaggerID Types"""

    #: NULL [:rfc:`6621`]
    NULL = 0

    #: DEFAULT [:rfc:`6621`]
    DEFAULT = 1

    #: IPv4 [:rfc:`6621`]
    IPv4 = 2

    #: IPv6 [:rfc:`6621`]
    IPv6 = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'TaggerID':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return TaggerID(key)
        if key not in TaggerID._member_map_:  # pylint: disable=no-member
            return extend_enum(TaggerID, key, default)
        return TaggerID[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'TaggerID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 7):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 4 <= value <= 7:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

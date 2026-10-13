# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TaggerID Types
====================

.. module:: pcapkit.const.ipv6.tagger_id

This module contains the constant enumeration for **TaggerID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.tagger_id.TaggerID`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['TaggerID']


class TaggerID(EnumRegistry, IntEnum):
    """[TaggerID] TaggerID Types"""

    #: NULL [:rfc:`6621`]
    NULL = 0

    #: DEFAULT [:rfc:`6621`]
    DEFAULT = 1

    #: IPv4 [:rfc:`6621`]
    IPv4 = 2

    #: IPv6 [:rfc:`6621`]
    IPv6 = 3

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

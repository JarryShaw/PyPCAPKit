# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobile Node Identifier Option Subtypes
============================================

.. module:: pcapkit.const.mh.mn_id_subtype

This module contains the constant enumeration for **Mobile Node Identifier Option Subtypes**,
which is automatically generated from :class:`pcapkit.vendor.mh.mn_id_subtype.MNIDSubtype`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['MNIDSubtype']


class MNIDSubtype(IntEnum):
    """[MNIDSubtype] Mobile Node Identifier Option Subtypes"""

    #: NAI [:rfc:`4283`]
    NAI = 1

    #: IPv6 Address [:rfc:`8371`]
    IPv6_Address = 2

    #: IMSI [:rfc:`8371`]
    IMSI = 3

    #: P-TMSI [:rfc:`8371`]
    P_TMSI = 4

    #: EUI-48 address [:rfc:`8371`]
    EUI_48_address = 5

    #: EUI-64 address [:rfc:`8371`]
    EUI_64_address = 6

    #: GUTI [:rfc:`8371`]
    GUTI = 7

    #: DUID [:rfc:`8371`]
    DUID = 8

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'MNIDSubtype':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return MNIDSubtype(key)
        if key not in MNIDSubtype._member_map_:  # pylint: disable=no-member
            return extend_enum(MNIDSubtype, key, default)
        return MNIDSubtype[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'MNIDSubtype':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 9 <= value <= 15:
            #: Reserved [:rfc:`8371`]
            return extend_enum(cls, 'Reserved_%d' % value, value)
        if 16 <= value <= 255:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ToS ECN Field
===================

.. module:: pcapkit.const.ipv4.tos_ecn

This module contains the constant enumeration for **ToS ECN Field**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.tos_ecn.ToSECN`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ToSECN']


class ToSECN(IntEnum):
    """[ToSECN] ToS ECN Field"""

    Not_ECT = 0b00

    ECT_0b01 = 0b01

    ECT_0b10 = 0b10

    CE = 0b11

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ToSECN':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ToSECN(key)
        if key not in ToSECN._member_map_:  # pylint: disable=no-member
            return extend_enum(ToSECN, key, default)
        return ToSECN[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ToSECN':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0b00 <= value <= 0b11):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_0b%s' % bin(value)[2:].zfill(2), value)

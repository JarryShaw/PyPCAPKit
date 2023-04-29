# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Operator-Identifier Type Registry
=======================================

.. module:: pcapkit.const.mh.operator_id

This module contains the constant enumeration for **Operator-Identifier Type Registry**,
which is automatically generated from :class:`pcapkit.vendor.mh.operator_id.OperatorID`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OperatorID']


class OperatorID(IntEnum):
    """[OperatorID] Operator-Identifier Type Registry"""

    #: Reserved [:rfc:`6757`]
    Reserved_0 = 0

    #: Operator-Identifier as a variable-length Private Enterprise Number (PEN)
    #: [:rfc:`6757`]
    Operator_Identifier_as_a_variable_length_Private_Enterprise_Number = 1

    #: Realm of the Operator [:rfc:`6757`]
    Realm_of_the_Operator = 2

    #: Reserved [:rfc:`6757`]
    Reserved_255 = 255

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OperatorID':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OperatorID(key)
        if key not in OperatorID._member_map_:  # pylint: disable=no-member
            return extend_enum(OperatorID, key, default)
        return OperatorID[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OperatorID':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 254:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

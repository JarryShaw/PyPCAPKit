# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Error Status Code
===============================

.. module:: pcapkit.const.mh.binding_error

This module contains the constant enumeration for **Binding Error Status Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_error.BindingError`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['BindingError']


class BindingError(IntEnum):
    """[BindingError] Binding Error Status Code"""

    Unknown_binding_for_Home_Address_destination_option = 1

    Unrecognized_MH_Type_value = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'BindingError':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return BindingError(key)
        if key not in BindingError._member_map_:  # pylint: disable=no-member
            return extend_enum(BindingError, key, default)
        return BindingError[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingError':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

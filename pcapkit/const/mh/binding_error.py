# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Error Status Code
===============================

.. module:: pcapkit.const.mh.binding_error

This module contains the constant enumeration for **Binding Error Status Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_error.BindingError`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['BindingError']


class BindingError(EnumRegistry, IntEnum):
    """[BindingError] Binding Error Status Code"""

    Unknown_binding_for_Home_Address_destination_option = 1

    Unrecognized_MH_Type_value = 2

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingError':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Binding Revocation Type
=============================

.. module:: pcapkit.const.mh.binding_revocation

This module contains the constant enumeration for **Binding Revocation Type**,
which is automatically generated from :class:`pcapkit.vendor.mh.binding_revocation.BindingRevocation`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['BindingRevocation']


class BindingRevocation(EnumRegistry, IntEnum):
    """[BindingRevocation] Binding Revocation Type"""

    #: Reserved [:rfc:`5846`]
    Reserved_0 = 0

    #: Binding Revocation Indication [:rfc:`5846`]
    Binding_Revocation_Indication = 1

    #: Binding Revocation Acknowledgement [:rfc:`5846`]
    Binding_Revocation_Acknowledgement = 2

    @classmethod
    def _missing_(cls, value: 'int') -> 'BindingRevocation':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 255:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

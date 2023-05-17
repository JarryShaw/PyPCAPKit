# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""CGA Extension Type Values
===============================

.. module:: pcapkit.const.mh.cga_extension

This module contains the constant enumeration for **CGA Extension Type Values**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_extension.CGAExtension`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['CGAExtension']


class CGAExtension(IntEnum):
    """[CGAExtension] CGA Extension Type Values"""

    #: Multi-Prefix [:rfc:`5535`]
    Multi_Prefix = 0x0012

    #: Exp_FFFD (experimental) [:rfc:`4581`]
    Exp_FFFD = 0xFFFD

    #: Exp_FFFE (experimental) [:rfc:`4581`]
    Exp_FFFE = 0xFFFE

    #: Exp_FFFF (experimental) [:rfc:`4581`]
    Exp_FFFF = 0xFFFF

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'CGAExtension':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return CGAExtension(key)
        if key not in CGAExtension._member_map_:  # pylint: disable=no-member
            return extend_enum(CGAExtension, key, default)
        return CGAExtension[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'CGAExtension':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000 <= value <= 0x0011:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%04x' % value, value)
        if 0x0013 <= value <= 0xFFFC:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%04x' % value, value)
        #: Unspecified in the IANA registry
        return extend_enum(cls, 'Unassigned_%04x' % value, value)

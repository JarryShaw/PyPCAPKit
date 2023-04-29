# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Cipher IDs
================

.. module:: pcapkit.const.hip.cipher

This module contains the constant enumeration for **Cipher IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.cipher.Cipher`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Cipher']


class Cipher(IntEnum):
    """[Cipher] Cipher IDs"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NULL-ENCRYPT [:rfc:`7401`]
    NULL_ENCRYPT = 1

    #: AES-128-CBC [:rfc:`7401`]
    AES_128_CBC = 2

    #: RESERVED [:rfc:`7401`]
    RESERVED_3 = 3

    #: AES-256-CBC [:rfc:`7401`]
    AES_256_CBC = 4

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Cipher':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Cipher(key)
        if key not in Cipher._member_map_:  # pylint: disable=no-member
            return extend_enum(Cipher, key, default)
        return Cipher[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Cipher':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

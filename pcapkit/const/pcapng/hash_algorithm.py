# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Hash Algorithms
=====================

.. module:: pcapkit.const.pcapng.hash_algorithm

This module contains the constant enumeration for **Hash Algorithms**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HashAlgorithm']


class HashAlgorithm(IntEnum):
    """[HashAlgorithm] Hash Algorithms"""

    two_s_complement = 0

    XOR = 1

    CRC32 = 2

    MD_5 = 3

    SHA_1 = 4

    Toeplitz = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HashAlgorithm':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HashAlgorithm(key)
        if key not in HashAlgorithm._member_map_:  # pylint: disable=no-member
            return extend_enum(HashAlgorithm, key, default)
        return HashAlgorithm[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HashAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Hash Algorithms
=====================

.. module:: pcapkit.const.pcapng.hash_algorithm

This module contains the constant enumeration for **Hash Algorithms**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.hash_algorithm.HashAlgorithm`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['HashAlgorithm']


class HashAlgorithm(EnumRegistry, IntEnum):
    """[HashAlgorithm] Hash Algorithms"""

    two_s_complement = 0

    XOR = 1

    CRC32 = 2

    MD_5 = 3

    SHA_1 = 4

    Toeplitz = 5

    @classmethod
    def _missing_(cls, value: 'int') -> 'HashAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

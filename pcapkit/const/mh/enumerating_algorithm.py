# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Enumerating Algorithms
============================

.. module:: pcapkit.const.mh.enumerating_algorithm

This module contains the constant enumeration for **Enumerating Algorithms**,
which is automatically generated from :class:`pcapkit.vendor.mh.enumerating_algorithm.EnumeratingAlgorithm`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['EnumeratingAlgorithm']


class EnumeratingAlgorithm(IntEnum):
    """[EnumeratingAlgorithm] Enumerating Algorithms"""

    #: Reserved (not available for assignment) [:rfc:`4285`]
    Reserved_0 = 0

    #: HMAC_SHA1_SPI [:rfc:`4285`]
    HMAC_SHA1_SPI = 3

    #: Reserved for use by 3GPP2 [:rfc:`4285`]
    Reserved_for_use_by_3GPP2 = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'EnumeratingAlgorithm':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return EnumeratingAlgorithm(key)
        if key not in EnumeratingAlgorithm._member_map_:  # pylint: disable=no-member
            return extend_enum(EnumeratingAlgorithm, key, default)
        return EnumeratingAlgorithm[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'EnumeratingAlgorithm':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

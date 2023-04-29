# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TCP Checksum
==================

.. module:: pcapkit.const.tcp.checksum

This module contains the constant enumeration for **TCP Checksum**,
which is automatically generated from :class:`pcapkit.vendor.tcp.checksum.Checksum`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Checksum']


class Checksum(IntEnum):
    """[Checksum] TCP Checksum [:rfc:`1146`]"""

    TCP_checksum = 0

    Checksum_8_bit_Fletcher_s_algorithm = 1

    Checksum_16_bit_Fletcher_s_algorithm = 2

    Redundant_Checksum_Avoidance = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Checksum':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Checksum(key)
        if key not in Checksum._member_map_:  # pylint: disable=no-member
            return extend_enum(Checksum, key, default)
        return Checksum[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Checksum':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

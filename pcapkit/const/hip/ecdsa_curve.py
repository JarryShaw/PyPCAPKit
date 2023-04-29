# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ECDSA Curve Label
=======================

.. module:: pcapkit.const.hip.ecdsa_curve

This module contains the constant enumeration for **ECDSA Curve Label**,
which is automatically generated from :class:`pcapkit.vendor.hip.ecdsa_curve.ECDSACurve`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ECDSACurve']


class ECDSACurve(IntEnum):
    """[ECDSACurve] ECDSA Curve Label"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NIST P-256 [:rfc:`7401`]
    NIST_P_256 = 1

    #: NIST P-384 [:rfc:`7401`]
    NIST_P_384 = 2

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ECDSACurve':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ECDSACurve(key)
        if key not in ECDSACurve._member_map_:  # pylint: disable=no-member
            return extend_enum(ECDSACurve, key, default)
        return ECDSACurve[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ECDSACurve':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 3 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

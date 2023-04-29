# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ECDSA_LOW Curve Label
===========================

.. module:: pcapkit.const.hip.ecdsa_low_curve

This module contains the constant enumeration for **ECDSA_LOW Curve Label**,
which is automatically generated from :class:`pcapkit.vendor.hip.ecdsa_low_curve.ECDSALowCurve`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ECDSALowCurve']


class ECDSALowCurve(IntEnum):
    """[ECDSALowCurve] ECDSA_LOW Curve Label"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: SECP160R1 [:rfc:`7401`]
    SECP160R1 = 1

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ECDSALowCurve':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ECDSALowCurve(key)
        if key not in ECDSALowCurve._member_map_:  # pylint: disable=no-member
            return extend_enum(ECDSALowCurve, key, default)
        return ECDSALowCurve[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ECDSALowCurve':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 2 <= value <= 65535:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

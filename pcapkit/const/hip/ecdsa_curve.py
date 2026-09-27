# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ECDSA Curve Label
=======================

.. module:: pcapkit.const.hip.ecdsa_curve

This module contains the constant enumeration for **ECDSA Curve Label**,
which is automatically generated from :class:`pcapkit.vendor.hip.ecdsa_curve.ECDSACurve`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['ECDSACurve']


class ECDSACurve(EnumRegistry, IntEnum):
    """[ECDSACurve] ECDSA Curve Label"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: NIST P-256 [:rfc:`7401`]
    NIST_P_256 = 1

    #: NIST P-384 [:rfc:`7401`]
    NIST_P_384 = 2

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
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

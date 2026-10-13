# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""EdDSA Curve Label
=======================

.. module:: pcapkit.const.hip.eddsa_curve

This module contains the constant enumeration for **EdDSA Curve Label**,
which is automatically generated from :class:`pcapkit.vendor.hip.eddsa_curve.EdDSACurve`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['EdDSACurve']


class EdDSACurve(EnumRegistry, IntEnum):
    """[EdDSACurve] EdDSA Curve Label"""

    #: RESERVED [:rfc:`9374`]
    RESERVED_0 = 0

    #: EdDSA25519 [:rfc:`8032`]
    EdDSA25519 = 1

    #: EdDSA25519ph [:rfc:`8032`]
    EdDSA25519ph = 2

    #: EdDSA448 [:rfc:`8032`]
    EdDSA448 = 3

    #: EdDSA448ph [:rfc:`8032`]
    EdDSA448ph = 4

    @classmethod
    def _missing_(cls, value: 'int') -> 'EdDSACurve':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIT Suite ID
==================

.. module:: pcapkit.const.hip.hit_suite

This module contains the constant enumeration for **HIT Suite ID**,
which is automatically generated from :class:`pcapkit.vendor.hip.hit_suite.HITSuite`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['HITSuite']


class HITSuite(IntEnum):
    """[HITSuite] HIT Suite ID"""

    #: RESERVED [:rfc:`7401`]
    RESERVED_0 = 0

    #: RSA,DSA/SHA-256 [:rfc:`7401`]
    RSA_DSA_SHA_256 = 1

    #: ECDSA/SHA-384 [:rfc:`7401`]
    ECDSA_SHA_384 = 2

    #: ECDSA_LOW/SHA-1 [:rfc:`7401`]
    ECDSA_LOW_SHA_1 = 3

    #: Unassigned
    Unassigned_4 = 4

    #: EdDSA/cSHAKE128 [:rfc:`9374`]
    EdDSA_cSHAKE128 = 5

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'HITSuite':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return HITSuite(key)
        if key not in HITSuite._member_map_:  # pylint: disable=no-member
            return extend_enum(HITSuite, key, default)
        return HITSuite[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'HITSuite':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 15:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        return super()._missing_(value)

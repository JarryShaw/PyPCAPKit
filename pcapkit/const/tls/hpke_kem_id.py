# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HPKE KEM Identifiers
==========================

.. module:: pcapkit.const.tls.hpke_kem_id

This module contains the constant enumeration for **HPKE KEM Identifiers**,
which is automatically generated from :class:`pcapkit.vendor.tls.hpke_kem_id.HpkeKemId`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HpkeKemId']


class HpkeKemId(EnumRegistry, IntEnum):
    """[HpkeKemId] HPKE KEM Identifiers"""

    #: Reserved [RFC-ietf-hpke-hpke-06]
    Reserved_0x0000 = 0x0000

    #: DHKEM(P-256, HKDF-SHA256) [NISTCurves][:rfc:`5869`]
    DHKEM_P_256_HKDF_SHA256 = 0x0010

    #: DHKEM(P-384, HKDF-SHA384) [NISTCurves][:rfc:`5869`]
    DHKEM_P_384_HKDF_SHA384 = 0x0011

    #: DHKEM(P-521, HKDF-SHA512) [NISTCurves][:rfc:`5869`]
    DHKEM_P_521_HKDF_SHA512 = 0x0012

    #: DHKEM(CP-256, HKDF-SHA256)
    #: [NISTCurves][:rfc:`6090`][draft-irtf-cfrg-dnhpke-01]
    DHKEM_CP_256_HKDF_SHA256 = 0x0013

    #: DHKEM(CP-384, HKDF-SHA384)
    #: [NISTCurves][:rfc:`6090`][draft-irtf-cfrg-dnhpke-01]
    DHKEM_CP_384_HKDF_SHA384 = 0x0014

    #: DHKEM(CP-521, HKDF-SHA512)
    #: [NISTCurves][:rfc:`6090`][draft-irtf-cfrg-dnhpke-01]
    DHKEM_CP_521_HKDF_SHA512 = 0x0015

    #: DHKEM(secp256k1, HKDF-SHA256) [Standards for Efficient Cryptography 2 (SEC
    #: 2)][draft-wahby-cfrg-hpke-kem-secp256k1-01]
    DHKEM_secp256k1_HKDF_SHA256 = 0x0016

    #: DHKEM(X25519, HKDF-SHA256) [:rfc:`5869`][:rfc:`7748`]
    DHKEM_X25519_HKDF_SHA256 = 0x0020

    #: DHKEM(X448, HKDF-SHA512) [:rfc:`5869`][:rfc:`7748`]
    DHKEM_X448_HKDF_SHA512 = 0x0021

    #: DHKEM(X25519+Elligator, HKDF-SHA256) [https://lsd.gnunet.org/lsd0011/]
    #: [draft-schanzen-hpke-elligator-kem-01]
    DHKEM_X25519_Elligator_HKDF_SHA256 = 0x0022

    #: X25519Kyber768Draft00 [draft-westerbaan-cfrg-hpke-xyber768d00-02]
    X25519Kyber768Draft00 = 0x0030

    #: ML-KEM-512 [draft-connolly-cfrg-hpke-mlkem-04]
    ML_KEM_512 = 0x0040

    #: ML-KEM-768 [draft-connolly-cfrg-hpke-mlkem-04]
    ML_KEM_768 = 0x0041

    #: ML-KEM-1024 [draft-connolly-cfrg-hpke-mlkem-04]
    ML_KEM_1024 = 0x0042

    #: MLKEM768-P256 [draft-ietf-hpke-pq-04]
    MLKEM768_P256 = 0x0050

    #: MLKEM1024-P384 [draft-ietf-hpke-pq-04]
    MLKEM1024_P384 = 0x0051

    #: X-Wing [draft-connolly-cfrg-xwing-kem-06]
    X_Wing = 0x647A

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'HpkeKemId':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0001 <= value <= 0x000F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0017 <= value <= 0x001F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0023 <= value <= 0x002F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0031 <= value <= 0x003F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0043 <= value <= 0x004F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0052 <= value <= 0x6479:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x647B <= value <= 0xFFFF:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

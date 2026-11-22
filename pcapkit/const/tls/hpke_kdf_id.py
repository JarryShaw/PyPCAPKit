# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HPKE KDF Identifiers
==========================

.. module:: pcapkit.const.tls.hpke_kdf_id

This module contains the constant enumeration for **HPKE KDF Identifiers**,
which is automatically generated from :class:`pcapkit.vendor.tls.hpke_kdf_id.HpkeKdfId`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HpkeKdfId']


class HpkeKdfId(EnumRegistry, IntEnum):
    """[HpkeKdfId] HPKE KDF Identifiers"""

    #: Reserved [RFC-ietf-hpke-hpke-06]
    Reserved_0x0000 = 0x0000

    #: HKDF-SHA256 [:rfc:`5869`]
    HKDF_SHA256 = 0x0001

    #: HKDF-SHA384 [:rfc:`5869`]
    HKDF_SHA384 = 0x0002

    #: HKDF-SHA512 [:rfc:`5869`]
    HKDF_SHA512 = 0x0003

    #: SHAKE128 [draft-ietf-hpke-pq-04]
    SHAKE128 = 0x0010

    #: SHAKE256 [draft-ietf-hpke-pq-04]
    SHAKE256 = 0x0011

    #: TurboSHAKE128 [draft-ietf-hpke-pq-04]
    TurboSHAKE128 = 0x0012

    #: TurboSHAKE256 [draft-ietf-hpke-pq-04]
    TurboSHAKE256 = 0x0013

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
    def _missing_(cls, value: 'int') -> 'HpkeKdfId':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0004 <= value <= 0x000F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0014 <= value <= 0xFFFF:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

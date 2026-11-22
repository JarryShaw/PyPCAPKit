# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HPKE AEAD Identifiers
===========================

.. module:: pcapkit.const.tls.hpke_aead_id

This module contains the constant enumeration for **HPKE AEAD Identifiers**,
which is automatically generated from :class:`pcapkit.vendor.tls.hpke_aead_id.HpkeAeadId`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HpkeAeadId']


class HpkeAeadId(EnumRegistry, IntEnum):
    """[HpkeAeadId] HPKE AEAD Identifiers"""

    #: Reserved [RFC-ietf-hpke-hpke-06]
    Reserved_0x0000 = 0x0000

    #: AES-128-GCM [GCM]
    AES_128_GCM = 0x0001

    #: AES-256-GCM [GCM]
    AES_256_GCM = 0x0002

    #: ChaCha20Poly1305 [:rfc:`8439`]
    ChaCha20Poly1305 = 0x0003

    #: Export-only [RFC-ietf-hpke-hpke-06]
    Export_only = 0xFFFF

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
    def _missing_(cls, value: 'int') -> 'HpkeAeadId':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0004 <= value <= 0xFFFE:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

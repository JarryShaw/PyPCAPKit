# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Radiotap VHT Known Flags
==============================

.. module:: pcapkit.const.radiotap.vht_known

This module contains the constant enumeration for **Radiotap VHT Known Flags**,
which is automatically generated from :class:`pcapkit.vendor.radiotap.vht_known.VHTKnown`.

"""

from typing import TYPE_CHECKING

from aenum import IntFlag

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['VHTKnown']


class VHTKnown(EnumRegistry, IntFlag):
    """[VHTKnown] Radiotap VHT Known Flags"""

    #: STBC known -- In flags part of the field.
    VHT_KNOWN_STBC = 1 << 0

    #: TXOP_PS_NOT_ALLOWED known -- In flags part of the field.
    VHT_KNOWN_TXOP_PS_NA = 1 << 1

    #: Guard interval -- In flags part of the field.
    VHT_KNOWN_GI = 1 << 2

    #: Short GI NSYM disambiguation known -- In flags part of the field.
    VHT_KNOWN_SGI_NSYM_DIS = 1 << 3

    #: LDPC extra OFDM symbol known -- In flags part of the field.
    VHT_KNOWN_LDPC_EXTRA_OFDM_SYM = 1 << 4

    #: Beamformed known/applicable -- In flags part of the field. This flag should
    #: be set to zero for MU PPDUs.
    VHT_KNOWN_BEAMFORMED = 1 << 5

    #: Bandwidth known -- In bandwidth part of the field.
    VHT_KNOWN_BANDWIDTH = 1 << 6

    #: Group ID known -- In group_id part of the field.
    VHT_KNOWN_GROUP_ID = 1 << 7

    #: Partial AID known/applicable -- In partial_aid part of the field. This flag
    #: should be set to zero for MU PPDUs.
    VHT_KNOWN_PARTIAL_AID = 1 << 8

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
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'VHTKnown':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)

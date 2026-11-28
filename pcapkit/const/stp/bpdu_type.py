# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""STP BPDU Types
====================

.. module:: pcapkit.const.stp.bpdu_type

This module contains the constant enumeration for **STP BPDU Types**,
which is automatically generated from :class:`pcapkit.vendor.stp.bpdu_type.BPDUType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['BPDUType']


class BPDUType(EnumRegistry, IntEnum):
    """[BPDUType] STP BPDU Types [:ieee:`802.1D-2004`; :ieee:`802.1Q-2022`]"""

    #: Configuration BPDU [:ieee:`802.1D-2004`]
    Configuration = 0x00

    #: RST BPDU, and the MST and SPT BPDUs [:ieee:`802.1D-2004`;
    #: :ieee:`802.1Q-2022`]
    RST = 0x02

    #: Topology Change Notification BPDU [:ieee:`802.1D-2004`]
    TCN = 0x80

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
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'BPDUType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

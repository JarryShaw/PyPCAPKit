# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""STP Protocol Version Identifiers
======================================

.. module:: pcapkit.const.stp.protocol_version

This module contains the constant enumeration for **STP Protocol Version Identifiers**,
which is automatically generated from :class:`pcapkit.vendor.stp.protocol_version.ProtocolVersion`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ProtocolVersion']


class ProtocolVersion(EnumRegistry, IntEnum):
    """[ProtocolVersion] STP Protocol Version Identifiers [:ieee:`802.1D-2004`; :ieee:`802.1Q-2022`]"""

    #: Spanning Tree Protocol: Configuration and TCN BPDUs [:ieee:`802.1D-2004`]
    STP = 0x00

    #: Rapid Spanning Tree Protocol: RST BPDUs [:ieee:`802.1D-2004`]
    RSTP = 0x02

    #: Multiple Spanning Tree Protocol: MST BPDUs [:ieee:`802.1Q-2022`]
    MSTP = 0x03

    #: Shortest Path Tree: SPT BPDUs [:ieee:`802.1Q-2022`]
    SPT = 0x04

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
    def _missing_(cls, value: 'int') -> 'ProtocolVersion':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

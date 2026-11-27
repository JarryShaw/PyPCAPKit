# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""LLC Modifier Functions
============================

.. module:: pcapkit.const.llc.modifier_function

This module contains the constant enumeration for **LLC Modifier Functions**,
which is automatically generated from :class:`pcapkit.vendor.llc.modifier_function.ModifierFunction`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ModifierFunction']


class ModifierFunction(EnumRegistry, IntEnum):
    """[ModifierFunction] LLC Modifier Functions [IEEE Std 802.2]"""

    #: Unnumbered Information (command)
    UI = 0x00

    #: Disconnected Mode (response)
    DM = 0x0C

    #: Disconnect (command)
    DISC = 0x40

    #: Unnumbered Acknowledgment (response)
    UA = 0x60

    #: Acknowledged Connectionless Information, sequence 0 (command and response)
    AC0 = 0x64

    #: Set Asynchronous Balanced Mode Extended (command)
    SABME = 0x6C

    #: Frame Reject (response)
    FRMR = 0x84

    #: Exchange Identification (command and response)
    XID = 0xAC

    #: Test (command and response)
    TEST = 0xE0

    #: Acknowledged Connectionless Information, sequence 1 (command and response)
    AC1 = 0xE4

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
        if not (isinstance(value, int) and 0x00 <= value <= 0xEC and not value & 0x13):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ModifierFunction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xEC and not value & 0x13):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

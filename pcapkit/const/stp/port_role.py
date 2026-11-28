# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""STP Port Roles
====================

.. module:: pcapkit.const.stp.port_role

This module contains the constant enumeration for **STP Port Roles**,
which is automatically generated from :class:`pcapkit.vendor.stp.port_role.PortRole`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['PortRole']


class PortRole(EnumRegistry, IntEnum):
    """[PortRole] STP Port Roles [:ieee:`802.1Q-2022`]"""

    #: Master Port in the MSTI Flags; Unknown in the CIST Flags, as
    #: :ieee:`802.1D-2004` names it [:ieee:`802.1Q-2022`]
    Master = 0x00

    #: Alternate or Backup Port [:ieee:`802.1Q-2022`]
    Alternate_or_Backup = 0x01

    #: Root Port [:ieee:`802.1Q-2022`]
    Root = 0x02

    #: Designated Port [:ieee:`802.1Q-2022`]
    Designated = 0x03

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
        if not (isinstance(value, int) and 0x00 <= value <= 0x03):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'PortRole':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0x03):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

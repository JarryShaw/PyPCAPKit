# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IPX Packet Types
======================

.. module:: pcapkit.const.ipx.packet

This module contains the constant enumeration for **IPX Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ipx.packet.Packet`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Packet']


class Packet(EnumRegistry, IntEnum):
    """[Packet] IPX Packet Types"""

    #: Unknown
    Unknown = 0

    #: ``RIP``, Routing Information Protocol ([:rfc:`1582`], [:rfc:`2091`])
    RIP = 1

    #: Echo Packet
    Echo_Packet = 2

    #: Error Packet
    Error_Packet = 3

    #: ``PEP``, Packet Exchange Protocol, used for SAP (Service Advertising
    #: Protocol)
    PEP = 4

    #: ``SPX``, Sequenced Packet Exchange
    SPX = 5

    #: ``NCP``, NetWare Core Protocol
    NCP = 17

    #: Broadcast[4]
    Broadcast_4 = 20

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
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

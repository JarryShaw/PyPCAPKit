# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""OSPF Packet Types
=======================

.. module:: pcapkit.const.ospf.packet

This module contains the constant enumeration for **OSPF Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ospf.packet.Packet`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Packet']


class Packet(EnumRegistry, IntEnum):
    """[Packet] OSPF Packet Types"""

    #: Reserved
    Reserved_0 = 0

    #: Hello [:rfc:`2328`]
    Hello = 1

    #: Database Description [:rfc:`2328`]
    Database_Description = 2

    #: Link State Request [:rfc:`2328`]
    Link_State_Request = 3

    #: Link State Update [:rfc:`2328`]
    Link_State_Update = 4

    #: Link State Ack [:rfc:`2328`]
    Link_State_Ack = 5

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
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 6 <= value <= 127:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 128 <= value <= 255:
            #: Reserved
            return cls._unregistered_member(value, 'Reserved')
        return super()._missing_(value)

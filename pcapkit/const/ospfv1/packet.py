# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""OSPFv1 Packet Types
=========================

.. module:: pcapkit.const.ospfv1.packet

This module contains the constant enumeration for **OSPFv1 Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.ospfv1.packet.Packet`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Packet']


class Packet(EnumRegistry, IntEnum):
    """[Packet] OSPFv1 Packet Types"""

    #: Hello [:rfc:`1131`]
    Hello = 1

    #: Database Description [:rfc:`1131`]
    Database_Description = 2

    #: Link State Request [:rfc:`1131`]
    Link_State_Request = 3

    #: Link State Update [:rfc:`1131`]
    Link_State_Update = 4

    #: Link State Ack [:rfc:`1131`]
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

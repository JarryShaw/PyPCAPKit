# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""DCCP Packet Types
=======================

.. module:: pcapkit.const.dccp.packet_type

This module contains the constant enumeration for **DCCP Packet Types**,
which is automatically generated from :class:`pcapkit.vendor.dccp.packet_type.PacketType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['PacketType']


class PacketType(EnumRegistry, IntEnum):
    """[PacketType] DCCP Packet Types"""

    #: DCCP-Request [:rfc:`4340`]
    DCCP_Request = 0

    #: DCCP-Response [:rfc:`4340`]
    DCCP_Response = 1

    #: DCCP-Data [:rfc:`4340`]
    DCCP_Data = 2

    #: DCCP-Ack [:rfc:`4340`]
    DCCP_Ack = 3

    #: DCCP-DataAck [:rfc:`4340`]
    DCCP_DataAck = 4

    #: DCCP-CloseReq [:rfc:`4340`]
    DCCP_CloseReq = 5

    #: DCCP-Close [:rfc:`4340`]
    DCCP_Close = 6

    #: DCCP-Reset [:rfc:`4340`]
    DCCP_Reset = 7

    #: DCCP-Sync [:rfc:`4340`]
    DCCP_Sync = 8

    #: DCCP-SyncAck [:rfc:`4340`]
    DCCP_SyncAck = 9

    #: DCCP-Listen [:rfc:`5596`]
    DCCP_Listen = 10

    #: Reserved for experimental and testing use [:rfc:`4340`]
    Reserved_for_experimental_and_testing_use = 14

    #: Unassigned [:rfc:`4340`]
    Unassigned_15 = 15

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
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'PacketType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 15):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 11 <= value <= 13:
            #: Unassigned [:rfc:`4340`]
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

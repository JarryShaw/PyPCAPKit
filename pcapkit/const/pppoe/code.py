# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""PPPoE Active Discovery Code Fields
========================================

.. module:: pcapkit.const.pppoe.code

This module contains the constant enumeration for **PPPoE Active Discovery Code Fields**,
which is automatically generated from :class:`pcapkit.vendor.pppoe.code.Code`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Code']


class Code(EnumRegistry, IntEnum):
    """[Code] PPPoE Active Discovery Code Fields"""

    #: PPP Session Stage [:rfc:`2516`]
    PPP_Session_Stage = 0x00

    #: PADO, Offer [:rfc:`2516`]
    PADO_Offer = 0x07

    #: Unassigned
    Unassigned_0x08 = 0x08

    #: PADI, Initiation [:rfc:`2516`]
    PADI_Initiation = 0x09

    #: PADG, Session-Grant [:rfc:`5578`]
    PADG_Session_Grant = 0x0A

    #: PADC, Session-Credit Response [:rfc:`5578`]
    PADC_Session_Credit_Response = 0x0B

    #: PADQ, Quality [:rfc:`5578`]
    PADQ_Quality = 0x0C

    #: PADR, Request [:rfc:`2516`]
    PADR_Request = 0x19

    #: PADS, Session-confirmation [:rfc:`2516`]
    PADS_Session_confirmation = 0x65

    #: PADT, Terminate [:rfc:`2516`]
    PADT_Terminate = 0xA7

    #: PADM, Message [Carrel D., Simone D., Ho C., Stoner T., "Extensions to a
    #: Method for Transmitting PPP Over Ethernet (PPPoE)", work in progress.]
    PADM_Message = 0xD3

    #: PADN, Network [Carrel D., Simone D., Ho C., Stoner T., "Extensions to a
    #: Method for Transmitting PPP Over Ethernet (PPPoE)", work in progress.]
    PADN_Network = 0xD4

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
    def _missing_(cls, value: 'int') -> 'Code':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x01 <= value <= 0x06:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0D <= value <= 0x18:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x1A <= value <= 0x64:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x66 <= value <= 0xA6:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0xA8 <= value <= 0xD2:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0xD5 <= value <= 0xFF:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""PPPoE TAG Values
======================

.. module:: pcapkit.const.pppoe.tag

This module contains the constant enumeration for **PPPoE TAG Values**,
which is automatically generated from :class:`pcapkit.vendor.pppoe.tag.Tag`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Tag']


class Tag(EnumRegistry, IntEnum):
    """[Tag] PPPoE TAG Values"""

    #: End-Of-List [:rfc:`2516`]
    End_Of_List = 0x0000

    #: Service-Name [:rfc:`2516`]
    Service_Name = 0x0101

    #: AC-Name [:rfc:`2516`]
    AC_Name = 0x0102

    #: Host-Uniq [:rfc:`2516`]
    Host_Uniq = 0x0103

    #: AC-Cookie [:rfc:`2516`]
    AC_Cookie = 0x0104

    #: Vendor-Specific [:rfc:`2516`]
    Vendor_Specific = 0x0105

    #: Credits [:rfc:`5578`]
    Credits = 0x0106

    #: Metrics [:rfc:`5578`]
    Metrics = 0x0107

    #: Sequence Number [:rfc:`5578`]
    Sequence_Number = 0x0108

    #: Credit Scale Factor [:rfc:`5578`]
    Credit_Scale_Factor = 0x0109

    #: Relay-Session-Id [:rfc:`2516`]
    Relay_Session_Id = 0x0110

    #: HURL [Carrel D., Simone D., Ho C., Stoner T., "Extensions to a Method for
    #: Transmitting PPP Over Ethernet (PPPoE)", work in progress.]
    HURL = 0x0111

    #: MOTM [Carrel D., Simone D., Ho C., Stoner T., "Extensions to a Method for
    #: Transmitting PPP Over Ethernet (PPPoE)", work in progress.]
    MOTM = 0x0112

    #: PPP-Max-Payload [:rfc:`4638`]
    PPP_Max_Payload = 0x0120

    #: IP_Route_Add [Carrel D., Simone D., Ho C., Stoner T., "Extensions to a
    #: Method for Transmitting PPP Over Ethernet (PPPoE)", work in progress.]
    IP_Route_Add = 0x0121

    #: Service-Name-Error [:rfc:`2516`]
    Service_Name_Error = 0x0201

    #: AC-System-Error [:rfc:`2516`]
    AC_System_Error = 0x0202

    #: Generic-Error [:rfc:`2516`]
    Generic_Error = 0x0203

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
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'Tag':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0001 <= value <= 0x0100:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x010A <= value <= 0x010F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0113 <= value <= 0x011F:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0122 <= value <= 0x0200:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 0x0204 <= value <= 0xFFFF:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)

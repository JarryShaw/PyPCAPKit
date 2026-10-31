# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IGMP Type Numbers
=======================

.. module:: pcapkit.const.igmp.type

This module contains the constant enumeration for **IGMP Type Numbers**,
which is automatically generated from :class:`pcapkit.vendor.igmp.type.Type`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Type']


class Type(EnumRegistry, IntEnum):
    """[Type] IGMP Type Numbers"""

    #: Reserved
    Reserved_0 = 0

    #: IGMP Membership Query [:rfc:`1112`]
    IGMP_Membership_Query = 17

    #: IGMPv1 Membership Report [:rfc:`1112`]
    IGMPv1_Membership_Report = 18

    #: DVMRP [draft-ietf-idmr-dvmrp-v3-11]
    DVMRP = 19

    #: PIM version 1 [draft-ietf-idmr-pim-spec-02]
    PIM_version_1 = 20

    #: Cisco Trace Messages
    Cisco_Trace_Messages = 21

    #: IGMPv2 Membership Report [:rfc:`2236`]
    IGMPv2_Membership_Report = 22

    #: IGMPv2 Leave Group [:rfc:`2236`]
    IGMPv2_Leave_Group = 23

    #: Multicast Traceroute Response [Bill Fenner]
    Multicast_Traceroute_Response = 30

    #: Multicast Traceroute [Bill Fenner]
    Multicast_Traceroute = 31

    #: IGMPv3 Membership Report [:rfc:`9776`]
    IGMPv3_Membership_Report = 34

    #: Multicast Router Advertisement [:rfc:`4286`]
    Multicast_Router_Advertisement = 48

    #: Multicast Router Solicitation [:rfc:`4286`]
    Multicast_Router_Solicitation = 49

    #: Multicast Router Termination [:rfc:`4286`]
    Multicast_Router_Termination = 50

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
    def _missing_(cls, value: 'int') -> 'Type':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 1 <= value <= 8:
            #: Reserved (Obsolete) [:rfc:`988`]
            return cls._unregistered_member(value, 'Reserved')
        if 9 <= value <= 16:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 240 <= value <= 255:
            #: Reserved for experimentation [:rfc:`9778`]
            return cls._unregistered_member(value, 'Reserved_for_experimentation')
        return super()._missing_(value)

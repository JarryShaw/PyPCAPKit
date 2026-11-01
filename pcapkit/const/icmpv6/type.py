# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ICMPv6 Type Numbers
=========================

.. module:: pcapkit.const.icmpv6.type

This module contains the constant enumeration for **ICMPv6 Type Numbers**,
which is automatically generated from :class:`pcapkit.vendor.icmpv6.type.Type`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['Type']


class Type(EnumRegistry, IntEnum):
    """[Type] ICMPv6 Type Numbers [:rfc:`4443`]"""

    #: Reserved
    Reserved_0 = 0

    #: Destination Unreachable [:rfc:`4443`]
    Destination_Unreachable = 1

    #: Packet Too Big [:rfc:`4443`]
    Packet_Too_Big = 2

    #: Time Exceeded [:rfc:`4443`]
    Time_Exceeded = 3

    #: Parameter Problem [:rfc:`4443`]
    Parameter_Problem = 4

    #: Private experimentation [:rfc:`4443`]
    Private_experimentation_100 = 100

    #: Private experimentation [:rfc:`4443`]
    Private_experimentation_101 = 101

    #: Reserved for expansion of ICMPv6 error messages [:rfc:`4443`]
    Reserved_for_expansion_of_ICMPv6_error_messages = 127

    #: Echo Request [:rfc:`4443`]
    Echo_Request = 128

    #: Echo Reply [:rfc:`4443`]
    Echo_Reply = 129

    #: Multicast Listener Query [:rfc:`2710`]
    Multicast_Listener_Query = 130

    #: Multicast Listener Report [:rfc:`2710`]
    Multicast_Listener_Report = 131

    #: Multicast Listener Done [:rfc:`2710`]
    Multicast_Listener_Done = 132

    #: Router Solicitation [:rfc:`4861`]
    Router_Solicitation = 133

    #: Router Advertisement [:rfc:`4861`]
    Router_Advertisement = 134

    #: Neighbor Solicitation [:rfc:`4861`]
    Neighbor_Solicitation = 135

    #: Neighbor Advertisement [:rfc:`4861`]
    Neighbor_Advertisement = 136

    #: Redirect Message [:rfc:`4861`]
    Redirect_Message = 137

    #: Router Renumbering [:rfc:`2894`]
    Router_Renumbering = 138

    #: ICMP Node Information Query [:rfc:`4620`]
    ICMP_Node_Information_Query = 139

    #: ICMP Node Information Response [:rfc:`4620`]
    ICMP_Node_Information_Response = 140

    #: Inverse Neighbor Discovery Solicitation Message [:rfc:`3122`]
    Inverse_Neighbor_Discovery_Solicitation_Message = 141

    #: Inverse Neighbor Discovery Advertisement Message [:rfc:`3122`]
    Inverse_Neighbor_Discovery_Advertisement_Message = 142

    #: Version 2 Multicast Listener Report [:rfc:`9777`]
    Version_2_Multicast_Listener_Report = 143

    #: Home Agent Address Discovery Request Message [:rfc:`6275`]
    Home_Agent_Address_Discovery_Request_Message = 144

    #: Home Agent Address Discovery Reply Message [:rfc:`6275`]
    Home_Agent_Address_Discovery_Reply_Message = 145

    #: Mobile Prefix Solicitation [:rfc:`6275`]
    Mobile_Prefix_Solicitation = 146

    #: Mobile Prefix Advertisement [:rfc:`6275`]
    Mobile_Prefix_Advertisement = 147

    #: Certification Path Solicitation Message [:rfc:`3971`]
    Certification_Path_Solicitation_Message = 148

    #: Certification Path Advertisement Message [:rfc:`3971`]
    Certification_Path_Advertisement_Message = 149

    #: ICMP messages utilized by experimental            mobility protocols such as
    #: Seamoby [:rfc:`4065`]
    ICMP_messages_utilized_by_experimental_mobility_protocols_such_as_Seamoby = 150

    #: Multicast Router Advertisement [:rfc:`4286`]
    Multicast_Router_Advertisement = 151

    #: Multicast Router Solicitation [:rfc:`4286`]
    Multicast_Router_Solicitation = 152

    #: Multicast Router Termination [:rfc:`4286`]
    Multicast_Router_Termination = 153

    #: FMIPv6 Messages [:rfc:`5568`]
    FMIPv6_Messages = 154

    #: RPL Control Message [:rfc:`6550`]
    RPL_Control_Message = 155

    #: ILNPv6 Locator Update Message [:rfc:`6743`]
    ILNPv6_Locator_Update_Message = 156

    #: Duplicate Address Request [:rfc:`6775`]
    Duplicate_Address_Request = 157

    #: Duplicate Address Confirmation [:rfc:`6775`]
    Duplicate_Address_Confirmation = 158

    #: MPL Control Message [:rfc:`7731`]
    MPL_Control_Message = 159

    #: Extended Echo Request [:rfc:`8335`]
    Extended_Echo_Request = 160

    #: Extended Echo Reply [:rfc:`8335`]
    Extended_Echo_Reply = 161

    #: Private experimentation [:rfc:`4443`]
    Private_experimentation_200 = 200

    #: Private experimentation [:rfc:`4443`]
    Private_experimentation_201 = 201

    #: Reserved for expansion of ICMPv6 informational    messages [:rfc:`4443`]
    Reserved_for_expansion_of_ICMPv6_informational_messages = 255

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
        if 5 <= value <= 99:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 102 <= value <= 126:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 162 <= value <= 199:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 202 <= value <= 254:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return cls._unregistered_member(value, 'Unassigned')

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobility Header Types - for the MH Type field in the Mobility Header
==========================================================================

.. module:: pcapkit.const.mh.packet

This module contains the constant enumeration for **Mobility Header Types - for the MH Type field in the Mobility Header**,
which is automatically generated from :class:`pcapkit.vendor.mh.packet.Packet`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Packet']


class Packet(EnumRegistry, IntEnum):
    """[Packet] Mobility Header Types - for the MH Type field in the Mobility Header"""

    #: Binding Refresh Request [RFC 6275]
    Binding_Refresh_Request = 0

    #: Home Test Init [RFC 6275]
    Home_Test_Init = 1

    #: Care-of Test Init [RFC 6275]
    Care_of_Test_Init = 2

    #: Home Test [RFC 6275]
    Home_Test = 3

    #: Care-of Test [RFC 6275]
    Care_of_Test = 4

    #: Binding Update [RFC 6275]
    Binding_Update = 5

    #: Binding Acknowledgement [RFC 6275]
    Binding_Acknowledgement = 6

    #: Binding Error [RFC 6275]
    Binding_Error = 7

    #: Fast Binding Update [RFC 5568]
    Fast_Binding_Update = 8

    #: Fast Binding Acknowledgment [RFC 5568]
    Fast_Binding_Acknowledgment = 9

    #: Fast Neighbor Advertisement (Deprecated) [RFC 5568]
    Fast_Neighbor_Advertisement = 10

    #: Experimental Mobility Header [RFC 5096]
    Experimental_Mobility_Header = 11

    #: Home Agent Switch Message [RFC 5142]
    Home_Agent_Switch_Message = 12

    #: Heartbeat Message [RFC 5847]
    Heartbeat_Message = 13

    #: Handover Initiate Message [RFC 5568]
    Handover_Initiate_Message = 14

    #: Handover Acknowledge Message [RFC 5568]
    Handover_Acknowledge_Message = 15

    #: Binding Revocation Message [RFC 5846]
    Binding_Revocation_Message = 16

    #: Localized Routing Initiation [RFC 6705]
    Localized_Routing_Initiation = 17

    #: Localized Routing Acknowledgment [RFC 6705]
    Localized_Routing_Acknowledgment = 18

    #: Update Notification [RFC 7077]
    Update_Notification = 19

    #: Update Notification Acknowledgement [RFC 7077]
    Update_Notification_Acknowledgement = 20

    #: Flow Binding Message [RFC 7109]
    Flow_Binding_Message = 21

    #: Subscription Query [RFC 7161]
    Subscription_Query = 22

    #: Subscription Response [RFC 7161]
    Subscription_Response = 23

    @classmethod
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

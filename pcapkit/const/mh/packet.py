# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Mobility Header Types - for the MH Type field in the Mobility Header
==========================================================================

.. module:: pcapkit.const.mh.packet

This module contains the constant enumeration for **Mobility Header Types - for the MH Type field in the Mobility Header**,
which is automatically generated from :class:`pcapkit.vendor.mh.packet.Packet`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] Mobility Header Types - for the MH Type field in the Mobility Header"""

    #: Binding Refresh Request [:rfc:`6275`]
    Binding_Refresh_Request = 0

    #: Home Test Init [:rfc:`6275`]
    Home_Test_Init = 1

    #: Care-of Test Init [:rfc:`6275`]
    Care_of_Test_Init = 2

    #: Home Test [:rfc:`6275`]
    Home_Test = 3

    #: Care-of Test [:rfc:`6275`]
    Care_of_Test = 4

    #: Binding Update [:rfc:`6275`]
    Binding_Update = 5

    #: Binding Acknowledgement [:rfc:`6275`]
    Binding_Acknowledgement = 6

    #: Binding Error [:rfc:`6275`]
    Binding_Error = 7

    #: Fast Binding Update [:rfc:`5568`]
    Fast_Binding_Update = 8

    #: Fast Binding Acknowledgment [:rfc:`5568`]
    Fast_Binding_Acknowledgment = 9

    #: Fast Neighbor Advertisement (Deprecated) [:rfc:`5568`]
    Fast_Neighbor_Advertisement = 10

    #: Experimental Mobility Header [:rfc:`5096`]
    Experimental_Mobility_Header = 11

    #: Home Agent Switch Message [:rfc:`5142`]
    Home_Agent_Switch_Message = 12

    #: Heartbeat Message [:rfc:`5847`]
    Heartbeat_Message = 13

    #: Handover Initiate Message [:rfc:`5568`]
    Handover_Initiate_Message = 14

    #: Handover Acknowledge Message [:rfc:`5568`]
    Handover_Acknowledge_Message = 15

    #: Binding Revocation Message [:rfc:`5846`]
    Binding_Revocation_Message = 16

    #: Localized Routing Initiation [:rfc:`6705`]
    Localized_Routing_Initiation = 17

    #: Localized Routing Acknowledgment [:rfc:`6705`]
    Localized_Routing_Acknowledgment = 18

    #: Update Notification [:rfc:`7077`]
    Update_Notification = 19

    #: Update Notification Acknowledgement [:rfc:`7077`]
    Update_Notification_Acknowledgement = 20

    #: Flow Binding Message [:rfc:`7109`]
    Flow_Binding_Message = 21

    #: Subscription Query [:rfc:`7161`]
    Subscription_Query = 22

    #: Subscription Response [:rfc:`7161`]
    Subscription_Response = 23

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Packet':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:  # pylint: disable=no-member
            return extend_enum(Packet, key, default)
        return Packet[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Packet':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

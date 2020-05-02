# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Mobility Header Types - for the MH Type field in the Mobility Header"""

from aenum import IntEnum, extend_enum

__all__ = ['Packet']


class Packet(IntEnum):
    """[Packet] Mobility Header Types - for the MH Type field in the Mobility Header"""

    _ignore_ = 'Packet _'
    Packet = vars()

    #:  [:rfc:`6275`]
    Packet['Binding_Refresh_Request'] = 0

    #:  [:rfc:`6275`]
    Packet['Home_Test_Init'] = 1

    #:  [:rfc:`6275`]
    Packet['Care_of_Test_Init'] = 2

    #:  [:rfc:`6275`]
    Packet['Home_Test'] = 3

    #:  [:rfc:`6275`]
    Packet['Care_of_Test'] = 4

    #:  [:rfc:`6275`]
    Packet['Binding_Update'] = 5

    #:  [:rfc:`6275`]
    Packet['Binding_Acknowledgement'] = 6

    #:  [:rfc:`6275`]
    Packet['Binding_Error'] = 7

    #:  [:rfc:`5568`]
    Packet['Fast_Binding_Update'] = 8

    #:  [:rfc:`5568`]
    Packet['Fast_Binding_Acknowledgment'] = 9

    #:  [:rfc:`5568`] (Deprecated)
    Packet['Fast_Neighbor_Advertisement'] = 10

    #:  [:rfc:`5096`]
    Packet['Experimental_Mobility_Header'] = 11

    #:  [:rfc:`5142`]
    Packet['Home_Agent_Switch_Message'] = 12

    #:  [:rfc:`5847`]
    Packet['Heartbeat_Message'] = 13

    #:  [:rfc:`5568`]
    Packet['Handover_Initiate_Message'] = 14

    #:  [:rfc:`5568`]
    Packet['Handover_Acknowledge_Message'] = 15

    #:  [:rfc:`5846`]
    Packet['Binding_Revocation_Message'] = 16

    #:  [:rfc:`6705`]
    Packet['Localized_Routing_Initiation'] = 17

    #:  [:rfc:`6705`]
    Packet['Localized_Routing_Acknowledgment'] = 18

    #:  [:rfc:`7077`]
    Packet['Update_Notification'] = 19

    #:  [:rfc:`7077`]
    Packet['Update_Notification_Acknowledgement'] = 20

    #:  [:rfc:`7109`]
    Packet['Flow_Binding_Message'] = 21

    #:  [:rfc:`7161`]
    Packet['Subscription_Query'] = 22

    #:  [:rfc:`7161`]
    Packet['Subscription_Response'] = 23

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:  # pylint: disable=no-member
            extend_enum(Packet, key, default)
        return Packet[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)

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
    Packet['Binding Refresh Request'] = 0

    #:  [:rfc:`6275`]
    Packet['Home Test Init'] = 1

    #:  [:rfc:`6275`]
    Packet['Care-of Test Init'] = 2

    #:  [:rfc:`6275`]
    Packet['Home Test'] = 3

    #:  [:rfc:`6275`]
    Packet['Care-of Test'] = 4

    #:  [:rfc:`6275`]
    Packet['Binding Update'] = 5

    #:  [:rfc:`6275`]
    Packet['Binding Acknowledgement'] = 6

    #:  [:rfc:`6275`]
    Packet['Binding Error'] = 7

    #:  [:rfc:`5568`]
    Packet['Fast Binding Update'] = 8

    #:  [:rfc:`5568`]
    Packet['Fast Binding Acknowledgment'] = 9

    #:  [:rfc:`5568`] (Deprecated)
    Packet['Fast Neighbor Advertisement'] = 10

    #:  [:rfc:`5096`]
    Packet['Experimental Mobility Header'] = 11

    #:  [:rfc:`5142`]
    Packet['Home Agent Switch Message'] = 12

    #:  [:rfc:`5847`]
    Packet['Heartbeat Message'] = 13

    #:  [:rfc:`5568`]
    Packet['Handover Initiate Message'] = 14

    #:  [:rfc:`5568`]
    Packet['Handover Acknowledge Message'] = 15

    #:  [:rfc:`5846`]
    Packet['Binding Revocation Message'] = 16

    #:  [:rfc:`6705`]
    Packet['Localized Routing Initiation'] = 17

    #:  [:rfc:`6705`]
    Packet['Localized Routing Acknowledgment'] = 18

    #:  [:rfc:`7077`]
    Packet['Update Notification'] = 19

    #:  [:rfc:`7077`]
    Packet['Update Notification Acknowledgement'] = 20

    #:  [:rfc:`7109`]
    Packet['Flow Binding Message'] = 21

    #:  [:rfc:`7161`]
    Packet['Subscription Query'] = 22

    #:  [:rfc:`7161`]
    Packet['Subscription Response'] = 23

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

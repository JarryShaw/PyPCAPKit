# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Packet(IntEnum):
    """Enumeration class for Packet."""
    _ignore_ = 'Packet _'
    Packet = vars()

    # Mobility Header Types - for the MH Type field in the Mobility Header
    Packet['Binding Refresh Request'] = 0                                       #  [RFC 6275]
    Packet['Home Test Init'] = 1                                                #  [RFC 6275]
    Packet['Care-of Test Init'] = 2                                             #  [RFC 6275]
    Packet['Home Test'] = 3                                                     #  [RFC 6275]
    Packet['Care-of Test'] = 4                                                  #  [RFC 6275]
    Packet['Binding Update'] = 5                                                #  [RFC 6275]
    Packet['Binding Acknowledgement'] = 6                                       #  [RFC 6275]
    Packet['Binding Error'] = 7                                                 #  [RFC 6275]
    Packet['Fast Binding Update'] = 8                                           #  [RFC 5568]
    Packet['Fast Binding Acknowledgment'] = 9                                   #  [RFC 5568]
    Packet['Fast Neighbor Advertisement'] = 10                                  #  [RFC 5568] (Deprecated)
    Packet['Experimental Mobility Header'] = 11                                 #  [RFC 5096]
    Packet['Home Agent Switch Message'] = 12                                    #  [RFC 5142]
    Packet['Heartbeat Message'] = 13                                            #  [RFC 5847]
    Packet['Handover Initiate Message'] = 14                                    #  [RFC 5568]
    Packet['Handover Acknowledge Message'] = 15                                 #  [RFC 5568]
    Packet['Binding Revocation Message'] = 16                                   #  [RFC 5846]
    Packet['Localized Routing Initiation'] = 17                                 #  [RFC 6705]
    Packet['Localized Routing Acknowledgment'] = 18                             #  [RFC 6705]
    Packet['Update Notification'] = 19                                          #  [RFC 7077]
    Packet['Update Notification Acknowledgement'] = 20                          #  [RFC 7077]
    Packet['Flow Binding Message'] = 21                                         #  [RFC 7109]
    Packet['Subscription Query'] = 22                                           #  [RFC 7161]
    Packet['Subscription Response'] = 23                                        #  [RFC 7161]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Packet(key)
        if key not in Packet._member_map_:
            extend_enum(Packet, key, default)
        return Packet[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)

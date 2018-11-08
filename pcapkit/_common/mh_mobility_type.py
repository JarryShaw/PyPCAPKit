# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PktType(IntEnum):
    """Enumeration class for PktType."""
    _ignore_ = 'PktType _'
    PktType = vars()

    # Mobility Header Types - for the MH Type field in the Mobility Header
    PktType['Binding Refresh Request'] = 0                                      #  [RFC 6275]
    PktType['Home Test Init'] = 1                                               #  [RFC 6275]
    PktType['Care-of Test Init'] = 2                                            #  [RFC 6275]
    PktType['Home Test'] = 3                                                    #  [RFC 6275]
    PktType['Care-of Test'] = 4                                                 #  [RFC 6275]
    PktType['Binding Update'] = 5                                               #  [RFC 6275]
    PktType['Binding Acknowledgement'] = 6                                      #  [RFC 6275]
    PktType['Binding Error'] = 7                                                #  [RFC 6275]
    PktType['Fast Binding Update'] = 8                                          #  [RFC 5568]
    PktType['Fast Binding Acknowledgment'] = 9                                  #  [RFC 5568]
    PktType['Fast Neighbor Advertisement'] = 10                                 #  [RFC 5568] (Deprecated)
    PktType['Experimental Mobility Header'] = 11                                #  [RFC 5096]
    PktType['Home Agent Switch Message'] = 12                                   #  [RFC 5142]
    PktType['Heartbeat Message'] = 13                                           #  [RFC 5847]
    PktType['Handover Initiate Message'] = 14                                   #  [RFC 5568]
    PktType['Handover Acknowledge Message'] = 15                                #  [RFC 5568]
    PktType['Binding Revocation Message'] = 16                                  #  [RFC 5846]
    PktType['Localized Routing Initiation'] = 17                                #  [RFC 6705]
    PktType['Localized Routing Acknowledgment'] = 18                            #  [RFC 6705]
    PktType['Update Notification'] = 19                                         #  [RFC 7077]
    PktType['Update Notification Acknowledgement'] = 20                         #  [RFC 7077]
    PktType['Flow Binding Message'] = 21                                        #  [RFC 7109]
    PktType['Subscription Query'] = 22                                          #  [RFC 7161]
    PktType['Subscription Response'] = 23                                       #  [RFC 7161]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PktType(key)
        if key not in PktType._member_map_:
            extend_enum(PktType, key, default)
        return PktType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)

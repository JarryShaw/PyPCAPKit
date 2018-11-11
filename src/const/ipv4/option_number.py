# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class OptionNumber(IntEnum):
    """Enumeration class for OptionNumber."""
    _ignore_ = 'OptionNumber _'
    OptionNumber = vars()

    # IP Option Numbers
    OptionNumber['EOOL'] = 0                                                    # [RFC 791][Jon_Postel] End of Options List
    OptionNumber['NOP'] = 1                                                     # [RFC 791][Jon_Postel] No Operation
    OptionNumber['SEC'] = 130                                                   # [RFC 1108] Security
    OptionNumber['LSR'] = 131                                                   # [RFC 791][Jon_Postel] Loose Source Route
    OptionNumber['TS'] = 68                                                     # [RFC 791][Jon_Postel] Time Stamp
    OptionNumber['E-SEC'] = 133                                                 # [RFC 1108] Extended Security
    OptionNumber['CIPSO'] = 134                                                 # [draft-ietf-cipso-ipsecurity-01] Commercial Security
    OptionNumber['RR'] = 7                                                      # [RFC 791][Jon_Postel] Record Route
    OptionNumber['SID'] = 136                                                   # [RFC 791][Jon_Postel][RFC 6814] Stream ID
    OptionNumber['SSR'] = 137                                                   # [RFC 791][Jon_Postel] Strict Source Route
    OptionNumber['ZSU'] = 10                                                    # [ZSu] Experimental Measurement
    OptionNumber['MTUP'] = 11                                                   # [RFC 1063][RFC 1191] MTU Probe
    OptionNumber['MTUR'] = 12                                                   # [RFC 1063][RFC 1191] MTU Reply
    OptionNumber['FINN'] = 205                                                  # [Greg_Finn] Experimental Flow Control
    OptionNumber['VISA'] = 142                                                  # [Deborah_Estrin][RFC 6814] Experimental Access Control
    OptionNumber['ENCODE'] = 15                                                 # [VerSteeg][RFC 6814]
    OptionNumber['IMITD'] = 144                                                 # [Lee] IMI Traffic Descriptor
    OptionNumber['EIP'] = 145                                                   # [RFC 1385][RFC 6814] Extended Internet Protocol
    OptionNumber['TR'] = 82                                                     # [RFC 1393][RFC 6814] Traceroute
    OptionNumber['ADDEXT'] = 147                                                # [Ullmann IPv7][RFC 6814] Address Extension
    OptionNumber['RTRALT'] = 148                                                # [RFC 2113] Router Alert
    OptionNumber['SDB'] = 149                                                   # [Charles_Bud_Graff][RFC 6814] Selective Directed Broadcast
    OptionNumber['Unassigned [150]'] = 150                                      # Unassigned (Released 18 October 2005)
    OptionNumber['DPS'] = 151                                                   # [Andy_Malis][RFC 6814] Dynamic Packet State
    OptionNumber['UMP'] = 152                                                   # [Dino_Farinacci][RFC 6814] Upstream Multicast Pkt.
    OptionNumber['QS'] = 25                                                     # [RFC 4782] Quick-Start
    OptionNumber['EXP [30]'] = 30                                               # [RFC 4727] RFC3692-style Experiment
    OptionNumber['EXP [94]'] = 94                                               # [RFC 4727] RFC3692-style Experiment
    OptionNumber['EXP [158]'] = 158                                             # [RFC 4727] RFC3692-style Experiment
    OptionNumber['EXP [222]'] = 222                                             # [RFC 4727] RFC3692-style Experiment

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptionNumber(key)
        if key not in OptionNumber._member_map_:
            extend_enum(OptionNumber, key, default)
        return OptionNumber[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)
        super()._missing_(value)

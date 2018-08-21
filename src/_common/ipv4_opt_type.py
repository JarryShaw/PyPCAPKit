# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class Options(IntEnum):
    """Enumeration class for Options."""
    _ignore_ = 'Options _'
    Options = vars()

    # IP Option Numbers
    Options['EOOL'] = 0                                                         # [RFC 791][Jon_Postel] End of Options List
    Options['NOP'] = 1                                                          # [RFC 791][Jon_Postel] No Operation
    Options['SEC'] = 130                                                        # [RFC 1108] Security
    Options['LSR'] = 131                                                        # [RFC 791][Jon_Postel] Loose Source Route
    Options['TS'] = 68                                                          # [RFC 791][Jon_Postel] Time Stamp
    Options['E-SEC'] = 133                                                      # [RFC 1108] Extended Security
    Options['CIPSO'] = 134                                                      # [draft-ietf-cipso-ipsecurity-01] Commercial Security
    Options['RR'] = 7                                                           # [RFC 791][Jon_Postel] Record Route
    Options['SID'] = 136                                                        # [RFC 791][Jon_Postel][RFC 6814] Stream ID
    Options['SSR'] = 137                                                        # [RFC 791][Jon_Postel] Strict Source Route
    Options['ZSU'] = 10                                                         # [ZSu] Experimental Measurement
    Options['MTUP'] = 11                                                        # [RFC 1063][RFC 1191] MTU Probe
    Options['MTUR'] = 12                                                        # [RFC 1063][RFC 1191] MTU Reply
    Options['FINN'] = 205                                                       # [Greg_Finn] Experimental Flow Control
    Options['VISA'] = 142                                                       # [Deborah_Estrin][RFC 6814] Experimental Access Control
    Options['ENCODE'] = 15                                                      # [VerSteeg][RFC 6814]
    Options['IMITD'] = 144                                                      # [Lee] IMI Traffic Descriptor
    Options['EIP'] = 145                                                        # [RFC 1385][RFC 6814] Extended Internet Protocol
    Options['TR'] = 82                                                          # [RFC 1393][RFC 6814] Traceroute
    Options['ADDEXT'] = 147                                                     # [Ullmann IPv7][RFC 6814] Address Extension
    Options['RTRALT'] = 148                                                     # [RFC 2113] Router Alert
    Options['SDB'] = 149                                                        # [Charles_Bud_Graff][RFC 6814] Selective Directed Broadcast
    Options['Unassigned [150]'] = 150                                           # Unassigned (Released 18 October 2005)
    Options['DPS'] = 151                                                        # [Andy_Malis][RFC 6814] Dynamic Packet State
    Options['UMP'] = 152                                                        # [Dino_Farinacci][RFC 6814] Upstream Multicast Pkt.
    Options['QS'] = 25                                                          # [RFC 4782] Quick-Start
    Options['EXP [30]'] = 30                                                    # [RFC 4727] RFC3692-style Experiment
    Options['EXP [94]'] = 94                                                    # [RFC 4727] RFC3692-style Experiment
    Options['EXP [158]'] = 158                                                  # [RFC 4727] RFC3692-style Experiment
    Options['EXP [222]'] = 222                                                  # [RFC 4727] RFC3692-style Experiment

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Options(key)
        if key not in Options._member_map_:
            extend_enum(Options, key, default)
        return Options[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)

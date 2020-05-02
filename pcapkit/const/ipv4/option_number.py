# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""IP Option Numbers"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionNumber']


class OptionNumber(IntEnum):
    """[OptionNumber] IP Option Numbers"""

    _ignore_ = 'OptionNumber _'
    OptionNumber = vars()

    #: [:rfc:`791`][Jon Postel] End of Options List
    OptionNumber['EOOL'] = 0

    #: [:rfc:`791`][Jon Postel] No Operation
    OptionNumber['NOP'] = 1

    #: [:rfc:`1108`] Security
    OptionNumber['SEC'] = 130

    #: [:rfc:`791`][Jon Postel] Loose Source Route
    OptionNumber['LSR'] = 131

    #: [:rfc:`791`][Jon Postel] Time Stamp
    OptionNumber['TS'] = 68

    #: [:rfc:`1108`] Extended Security
    OptionNumber['E_SEC'] = 133

    #: [draft-ietf-cipso-ipsecurity-01] Commercial Security
    OptionNumber['CIPSO'] = 134

    #: [:rfc:`791`][Jon Postel] Record Route
    OptionNumber['RR'] = 7

    #: [:rfc:`791`][Jon Postel][:rfc:`6814`] Stream ID
    OptionNumber['SID'] = 136

    #: [:rfc:`791`][Jon Postel] Strict Source Route
    OptionNumber['SSR'] = 137

    #: [ZSu] Experimental Measurement
    OptionNumber['ZSU'] = 10

    #: [:rfc:`1063`][:rfc:`1191`] MTU Probe
    OptionNumber['MTUP'] = 11

    #: [:rfc:`1063`][:rfc:`1191`] MTU Reply
    OptionNumber['MTUR'] = 12

    #: [Greg Finn] Experimental Flow Control
    OptionNumber['FINN'] = 205

    #: [Deborah Estrin][:rfc:`6814`] Experimental Access Control
    OptionNumber['VISA'] = 142

    #: [VerSteeg][:rfc:`6814`]
    OptionNumber['ENCODE'] = 15

    #: [Lee] IMI Traffic Descriptor
    OptionNumber['IMITD'] = 144

    #: [:rfc:`1385`][:rfc:`6814`] Extended Internet Protocol
    OptionNumber['EIP'] = 145

    #: [:rfc:`1393`][:rfc:`6814`] Traceroute
    OptionNumber['TR'] = 82

    #: [Ullmann IPv7][:rfc:`6814`] Address Extension
    OptionNumber['ADDEXT'] = 147

    #: [:rfc:`2113`] Router Alert
    OptionNumber['RTRALT'] = 148

    #: [Charles Bud Graff][:rfc:`6814`] Selective Directed Broadcast
    OptionNumber['SDB'] = 149

    #: Unassigned (Released 18 October 2005)
    OptionNumber['Unassigned_150'] = 150

    #: [Andy Malis][:rfc:`6814`] Dynamic Packet State
    OptionNumber['DPS'] = 151

    #: [Dino Farinacci][:rfc:`6814`] Upstream Multicast Pkt.
    OptionNumber['UMP'] = 152

    #: [:rfc:`4782`] Quick-Start
    OptionNumber['QS'] = 25

    #: [:rfc:`4727`] RFC3692-style Experiment
    OptionNumber['EXP_30'] = 30

    #: [:rfc:`4727`] RFC3692-style Experiment
    OptionNumber['EXP_94'] = 94

    #: [:rfc:`4727`] RFC3692-style Experiment
    OptionNumber['EXP_158'] = 158

    #: [:rfc:`4727`] RFC3692-style Experiment
    OptionNumber['EXP_222'] = 222

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return OptionNumber(key)
        if key not in OptionNumber._member_map_:  # pylint: disable=no-member
            extend_enum(OptionNumber, key, default)
        return OptionNumber[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned [%d]' % value, value)
        return cls(value)

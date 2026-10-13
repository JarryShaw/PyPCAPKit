# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IP Option Numbers
=======================

.. module:: pcapkit.const.ipv4.option_number

This module contains the constant enumeration for **IP Option Numbers**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.option_number.OptionNumber`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['OptionNumber']


class OptionNumber(EnumRegistry, IntEnum):
    """[OptionNumber] IP Option Numbers"""

    #: ``EOOL``, End of Options List [RFC 791][; ][Jon Postel]
    EOOL = 0

    #: ``NOP``, No Operation [RFC 791][; ][Jon Postel]
    NOP = 1

    #: ``SEC``, Security [RFC 1108]
    SEC = 130

    #: ``LSR``, Loose Source Route [RFC 791][; ][Jon Postel]
    LSR = 131

    #: ``TS``, Time Stamp [RFC 791][; ][Jon Postel]
    TS = 68

    #: ``E-SEC``, Extended Security [RFC 1108]
    E_SEC = 133

    #: ``CIPSO``, Commercial Security [draft-ietf-cipso-ipsecurity-01]
    CIPSO = 134

    #: ``RR``, Record Route [RFC 791][; ][Jon Postel]
    RR = 7

    #: ``SID``, Stream ID [RFC 791][; ][Jon Postel][; ][RFC 6814]
    SID = 136

    #: ``SSR``, Strict Source Route [RFC 791][; ][Jon Postel]
    SSR = 137

    #: ``ZSU``, Experimental Measurement [ZSu]
    ZSU = 10

    #: ``MTUP``, MTU Probe [RFC 1063][; ][RFC 1191]
    MTUP = 11

    #: ``MTUR``, MTU Reply [RFC 1063][; ][RFC 1191]
    MTUR = 12

    #: ``FINN``, Experimental Flow Control [Greg Finn]
    FINN = 205

    #: ``VISA``, Experimental Access Control [Deborah Estrin][; ][RFC 6814]
    VISA = 142

    #: ``ENCODE``, ??? [VerSteeg][; ][RFC 6814]
    ENCODE = 15

    #: ``IMITD``, IMI Traffic Descriptor [Lee]
    IMITD = 144

    #: ``EIP``, Extended Internet Protocol [RFC 1385][; ][RFC 6814]
    EIP = 145

    #: ``TR``, Traceroute [RFC 1393][; ][RFC 6814]
    TR = 82

    #: ``ADDEXT``, Address Extension [Ullmann IPv7][; ][RFC 6814]
    ADDEXT = 147

    #: ``RTRALT``, Router Alert [RFC 2113]
    RTRALT = 148

    #: ``SDB``, Selective Directed Broadcast [Charles Bud Graff][; ][RFC 6814]
    SDB = 149

    #: Unassigned (Released 18 October 2005)
    Unassigned_150 = 150

    #: ``DPS``, Dynamic Packet State [Andy Malis][; ][RFC 6814]
    DPS = 151

    #: ``UMP``, Upstream Multicast Pkt. [Dino Farinacci][; ][RFC 6814]
    UMP = 152

    #: ``QS``, Quick-Start [RFC 4782]
    QS = 25

    #: ``EXP``, RFC3692-style Experiment [RFC 4727]
    EXP_30 = 30

    #: ``EXP``, RFC3692-style Experiment [RFC 4727]
    EXP_94 = 94

    #: ``EXP``, RFC3692-style Experiment [RFC 4727]
    EXP_158 = 158

    #: ``EXP``, RFC3692-style Experiment [RFC 4727]
    EXP_222 = 222

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionNumber':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

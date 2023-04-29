# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""IP Option Numbers
=======================

.. module:: pcapkit.const.ipv4.option_number

This module contains the constant enumeration for **IP Option Numbers**,
which is automatically generated from :class:`pcapkit.vendor.ipv4.option_number.OptionNumber`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionNumber']


class OptionNumber(IntEnum):
    """[OptionNumber] IP Option Numbers"""

    #: ``EOOL``, End of Options List [:rfc:`791`][Jon Postel]
    EOOL = 0

    #: ``NOP``, No Operation [:rfc:`791`][Jon Postel]
    NOP = 1

    #: ``SEC``, Security [:rfc:`1108`]
    SEC = 130

    #: ``LSR``, Loose Source Route [:rfc:`791`][Jon Postel]
    LSR = 131

    #: ``TS``, Time Stamp [:rfc:`791`][Jon Postel]
    TS = 68

    #: ``E-SEC``, Extended Security [:rfc:`1108`]
    E_SEC = 133

    #: ``CIPSO``, Commercial Security [draft-ietf-cipso-ipsecurity-01]
    CIPSO = 134

    #: ``RR``, Record Route [:rfc:`791`][Jon Postel]
    RR = 7

    #: ``SID``, Stream ID [:rfc:`791`][Jon Postel][:rfc:`6814`]
    SID = 136

    #: ``SSR``, Strict Source Route [:rfc:`791`][Jon Postel]
    SSR = 137

    #: ``ZSU``, Experimental Measurement [ZSu]
    ZSU = 10

    #: ``MTUP``, MTU Probe [:rfc:`1063`][:rfc:`1191`]
    MTUP = 11

    #: ``MTUR``, MTU Reply [:rfc:`1063`][:rfc:`1191`]
    MTUR = 12

    #: ``FINN``, Experimental Flow Control [Greg Finn]
    FINN = 205

    #: ``VISA``, Experimental Access Control [Deborah Estrin][:rfc:`6814`]
    VISA = 142

    #: ``ENCODE``, ??? [VerSteeg][:rfc:`6814`]
    ENCODE = 15

    #: ``IMITD``, IMI Traffic Descriptor [Lee]
    IMITD = 144

    #: ``EIP``, Extended Internet Protocol [:rfc:`1385`][:rfc:`6814`]
    EIP = 145

    #: ``TR``, Traceroute [:rfc:`1393`][:rfc:`6814`]
    TR = 82

    #: ``ADDEXT``, Address Extension [Ullmann IPv7][:rfc:`6814`]
    ADDEXT = 147

    #: ``RTRALT``, Router Alert [:rfc:`2113`]
    RTRALT = 148

    #: ``SDB``, Selective Directed Broadcast [Charles Bud Graff][:rfc:`6814`]
    SDB = 149

    #: Unassigned (Released 18 October 2005)
    Unassigned_150 = 150

    #: ``DPS``, Dynamic Packet State [Andy Malis][:rfc:`6814`]
    DPS = 151

    #: ``UMP``, Upstream Multicast Pkt. [Dino Farinacci][:rfc:`6814`]
    UMP = 152

    #: ``QS``, Quick-Start [:rfc:`4782`]
    QS = 25

    #: ``EXP``, RFC3692-style Experiment [:rfc:`4727`]
    EXP_30 = 30

    #: ``EXP``, RFC3692-style Experiment [:rfc:`4727`]
    EXP_94 = 94

    #: ``EXP``, RFC3692-style Experiment [:rfc:`4727`]
    EXP_158 = 158

    #: ``EXP``, RFC3692-style Experiment [:rfc:`4727`]
    EXP_222 = 222

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionNumber':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OptionNumber(key)
        if key not in OptionNumber._member_map_:  # pylint: disable=no-member
            return extend_enum(OptionNumber, key, default)
        return OptionNumber[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionNumber':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)

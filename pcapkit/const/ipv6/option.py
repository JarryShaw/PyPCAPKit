# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Destination Options and Hop-by-Hop Options"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] Destination Options and Hop-by-Hop Options"""

    #: PAD [IPV6]
    PAD = 0x00

    #: PADN [IPV6]
    PADN = 0x01

    #: JUMBO [:rfc:`2675`]
    JUMBO = 0xC2

    #: RPL Option [RFC-ietf-roll-useofrplinfo-31]
    RPL_Option_0x23 = 0x23

    #: RPL [:rfc:`6553`][RFC-ietf-roll-useofrplinfo-31]
    RPL_0x63 = 0x63

    #: TUN [:rfc:`2473`]
    TUN = 0x04

    #: RA [:rfc:`2711`]
    RA = 0x05

    #: QS [:rfc:`4782`][RFC Errata            2034]
    QS = 0x26

    #: CALIPSO [:rfc:`5570`]
    CALIPSO = 0x07

    #: SMF_DPD [:rfc:`6621`]
    SMF_DPD = 0x08

    #: HOME [:rfc:`6275`]
    HOME = 0xC9

    #: DEPRECATED [CHARLES LYNN]
    DEPRECATED = 0x8A

    #: ILNP [:rfc:`6744`]
    ILNP = 0x8B

    #: LIO [:rfc:`6788`]
    LIO = 0x8C

    #: Deprecated [:rfc:`7731`]
    Deprecated = 0x4D

    #: MPL [:rfc:`7731`]
    MPL = 0x6D

    #: IP_DFF [:rfc:`6971`]
    IP_DFF = 0xEE

    #: PDM [:rfc:`8250`]
    PDM = 0x0F

    #: Path MTU Record Option  TEMPORARY - registered 2019-09-03, expires
    #: 2020-09-03 [draft-ietf-6man-mtu-option]
    Path_MTU_Record_Option_TEMPORARY_registered_2019_09_03_expires_2020_09_03 = 0x30

    #: IOAM  TEMPORARY - registered 2020-04-16, expires 2021-04-16 [draft-ietf-
    #: ippm-ioam-ipv6-options]
    IOAM_TEMPORARY_registered_2020_04_16_expires_2021_04_16_0x11 = 0x11

    #: IOAM  TEMPORARY - registered 2020-04-16, expires 2021-04-16 [draft-ietf-
    #: ippm-ioam-ipv6-options]
    IOAM_TEMPORARY_registered_2020_04_16_expires_2021_04_16_0x31 = 0x31

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x1E = 0x1E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x3E = 0x3E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x5E = 0x5E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x7E = 0x7E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0x9E = 0x9E

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xBE = 0xBE

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xDE = 0xDE

    #: RFC3692-style Experiment [:rfc:`4727`]
    RFC3692_style_Experiment_0xFE = 0xFE

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Option(key)
        if key not in Option._member_map_:  # pylint: disable=no-member
            extend_enum(Option, key, default)
        return Option[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)
        return cls(value)

# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Destination Options and Hop-by-Hop Options"""

from aenum import IntEnum, extend_enum

__all__ = ['Option']


class Option(IntEnum):
    """[Option] Destination Options and Hop-by-Hop Options"""

    _ignore_ = 'Option _'
    Option = vars()

    #: [IPV6]
    Option['PAD'] = 0x00

    #: [IPV6]
    Option['PADN'] = 0x01

    #: [:rfc:`2675`]
    Option['JUMBO'] = 0xC2

    #: [RFC-ietf-roll-useofrplinfo-31]
    Option['RPL_Option_0x23'] = 0x23

    #: [:rfc:`6553`][RFC-ietf-roll-useofrplinfo-31]
    Option['RPL_0x63'] = 0x63

    #: [:rfc:`2473`]
    Option['TUN'] = 0x04

    #: [:rfc:`2711`]
    Option['RA'] = 0x05

    #: [:rfc:`4782`][RFC Errata            2034]
    Option['QS'] = 0x26

    #: [:rfc:`5570`]
    Option['CALIPSO'] = 0x07

    #: [:rfc:`6621`]
    Option['SMF_DPD'] = 0x08

    #: [:rfc:`6275`]
    Option['HOME'] = 0xC9

    #: [CHARLES LYNN]
    Option['DEPRECATED'] = 0x8A

    #: [:rfc:`6744`]
    Option['ILNP'] = 0x8B

    #: [:rfc:`6788`]
    Option['LIO'] = 0x8C

    #: [:rfc:`7731`]
    Option['Deprecated'] = 0x4D

    #: [:rfc:`7731`]
    Option['MPL'] = 0x6D

    #: [:rfc:`6971`]
    Option['IP_DFF'] = 0xEE

    #: [:rfc:`8250`]
    Option['PDM'] = 0x0F

    #: [draft-ietf-6man-mtu-option]
    Option['Path_MTU_Record_Option_TEMPORARY_Registered_2019_09_03_Expires_2020_09_03'] = 0x30

    #: [draft-ietf-ippm-ioam-ipv6-options]
    Option['IOAM_TEMPORARY_Registered_2020_04_16_Expires_2021_04_16_0x11'] = 0x11

    #: [draft-ietf-ippm-ioam-ipv6-options]
    Option['IOAM_TEMPORARY_Registered_2020_04_16_Expires_2021_04_16_0x31'] = 0x31

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0x1E'] = 0x1E

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0x3E'] = 0x3E

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0x5E'] = 0x5E

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0x7E'] = 0x7E

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0x9E'] = 0x9E

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0xBE'] = 0xBE

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0xDE'] = 0xDE

    #: [:rfc:`4727`]
    Option['RFC3692_style_Experiment_0xFE'] = 0xFE

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
        extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(2), value)
        return cls(value)

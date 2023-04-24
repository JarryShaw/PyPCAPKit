# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Option Types
==================

.. module:: pcapkit.const.pcapng.option_type

This module contains the constant enumeration for **Option Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.option_type.OptionType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionType']


class OptionType(IntEnum):
    """[OptionType] Option Types"""

    #: opt_endofopt
    opt_endofopt = 0

    #: opt_comment
    opt_comment = 1

    #: if_name
    if_name = 2

    #: if_description
    if_description = 3

    #: if_IPv4addr
    if_IPv4addr = 4

    #: if_IPv6addr
    if_IPv6addr = 5

    #: if_MACaddr
    if_MACaddr = 6

    #: if_EUIaddr
    if_EUIaddr = 7

    #: if_speed
    if_speed = 8

    #: if_tsresol
    if_tsresol = 9

    #: if_tzone
    if_tzone = 10

    #: if_filter
    if_filter = 11

    #: if_os
    if_os = 12

    #: if_fcslen
    if_fcslen = 13

    #: if_tsoffset
    if_tsoffset = 14

    #: if_hardware
    if_hardware = 15

    #: if_txspeed
    if_txspeed = 16

    #: if_rxspeed
    if_rxspeed = 17

    #: epb_flags
    epb_flags = 2

    #: epb_hash
    epb_hash = 3

    #: epb_dropcount
    epb_dropcount = 4

    #: epb_packetid
    epb_packetid = 5

    #: epb_queue
    epb_queue = 6

    #: epb_verdict
    epb_verdict = 7

    #: ns_dnsname
    ns_dnsname = 2

    #: ns_dnsIP4addr
    ns_dnsIP4addr = 3

    #: ns_dnsIP6addr
    ns_dnsIP6addr = 4

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OptionType(key)
        if key not in OptionType._member_map_:  # pylint: disable=no-member
            extend_enum(OptionType, key, default)
        return OptionType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if value in (2988, 2989, 19372, 19373):
            #: opt_custom
            extend_enum(cls, 'opt_custom_%d' % value, value)
            return cls(value)
        return super()._missing_(value)

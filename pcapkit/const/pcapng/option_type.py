# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
# pylint: disable=line-too-long,consider-using-f-string
"""Option Types
==================

.. module:: pcapkit.const.pcapng.option_type

This module contains the constant enumeration for **Option Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.option_type.OptionType`.

"""
from collections import defaultdict
from typing import TYPE_CHECKING

from aenum import StrEnum, extend_enum

__all__ = ['OptionType']

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, Type


class OptionType(StrEnum):
    """[OptionType] Option Types"""

    if TYPE_CHECKING:
        #: Short name of the option type.
        opt_name: 'str'
        #: Numeric value of the option type.
        opt_value: 'int'

    #: Mapping of members based on namespace.
    __members_ns__: 'DefaultDict[str, dict[int, OptionType]]' = defaultdict(dict)

    def __new__(cls, value: 'int', name: 'str' = 'opt_unknown') -> 'Type[OptionType]':
        temp = '%s [%d]' % (name, value)

        obj = str.__new__(cls, temp)
        obj._value_ = temp

        obj.opt_name = name
        obj.opt_value = value

        namespace = name.split('_', maxsplit=1)[0]
        cls.__members_ns__[namespace][value] = obj

        return obj

    def __repr__(self) -> 'str':
        return "<%s.%s: %d>" % (self.__class__.__name__, self.opt_name, self.opt_value)

    def __str__(self) -> 'str':
        return '%s [%d]' % (self.opt_name, self.opt_value)

    def __int__(self) -> 'int':
        return self.opt_value

    def __lt__(self, other: 'OptionType') -> 'bool':
        return self.opt_value < other

    def __gt__(self, other: 'OptionType') -> 'bool':
        return self.opt_value > other

    def __le__(self, other: 'OptionType') -> 'bool':
        return self.opt_value <= other

    def __ge__(self, other: 'OptionType') -> 'bool':
        return self.opt_value >= other

    def __eq__(self, other: 'Any') -> 'bool':
        return self.opt_value == other

    def __ne__(self, other: 'Any') -> 'bool':
        return self.opt_value != other

    def __hash__(self) -> 'int':
        return hash(self.opt_value)

    #: opt_endofopt
    opt_endofopt: 'OptionType' = 0, 'opt_endofopt'

    #: opt_comment
    opt_comment: 'OptionType' = 1, 'opt_comment'

    #: opt_custom
    opt_custom_2988: 'OptionType' = 2988, 'opt_custom'

    #: opt_custom
    opt_custom_2989: 'OptionType' = 2989, 'opt_custom'

    #: opt_custom
    opt_custom_19372: 'OptionType' = 19372, 'opt_custom'

    #: opt_custom
    opt_custom_19373: 'OptionType' = 19373, 'opt_custom'

    #: if_name
    if_name: 'OptionType' = 2, 'if_name'

    #: if_description
    if_description: 'OptionType' = 3, 'if_description'

    #: if_IPv4addr
    if_IPv4addr: 'OptionType' = 4, 'if_IPv4addr'

    #: if_IPv6addr
    if_IPv6addr: 'OptionType' = 5, 'if_IPv6addr'

    #: if_MACaddr
    if_MACaddr: 'OptionType' = 6, 'if_MACaddr'

    #: if_EUIaddr
    if_EUIaddr: 'OptionType' = 7, 'if_EUIaddr'

    #: if_speed
    if_speed: 'OptionType' = 8, 'if_speed'

    #: if_tsresol
    if_tsresol: 'OptionType' = 9, 'if_tsresol'

    #: if_tzone
    if_tzone: 'OptionType' = 10, 'if_tzone'

    #: if_filter
    if_filter: 'OptionType' = 11, 'if_filter'

    #: if_os
    if_os: 'OptionType' = 12, 'if_os'

    #: if_fcslen
    if_fcslen: 'OptionType' = 13, 'if_fcslen'

    #: if_tsoffset
    if_tsoffset: 'OptionType' = 14, 'if_tsoffset'

    #: if_hardware
    if_hardware: 'OptionType' = 15, 'if_hardware'

    #: if_txspeed
    if_txspeed: 'OptionType' = 16, 'if_txspeed'

    #: if_rxspeed
    if_rxspeed: 'OptionType' = 17, 'if_rxspeed'

    #: epb_flags
    epb_flags: 'OptionType' = 2, 'epb_flags'

    #: epb_hash
    epb_hash: 'OptionType' = 3, 'epb_hash'

    #: epb_dropcount
    epb_dropcount: 'OptionType' = 4, 'epb_dropcount'

    #: epb_packetid
    epb_packetid: 'OptionType' = 5, 'epb_packetid'

    #: epb_queue
    epb_queue: 'OptionType' = 6, 'epb_queue'

    #: epb_verdict
    epb_verdict: 'OptionType' = 7, 'epb_verdict'

    #: ns_dnsname
    ns_dnsname: 'OptionType' = 2, 'ns_dnsname'

    #: ns_dnsIP4addr
    ns_dnsIP4addr: 'OptionType' = 3, 'ns_dnsIP4addr'

    #: ns_dnsIP6addr
    ns_dnsIP6addr: 'OptionType' = 4, 'ns_dnsIP6addr'

    #: isb_starttime
    isb_starttime: 'OptionType' = 2, 'isb_starttime'

    #: isb_endtime
    isb_endtime: 'OptionType' = 3, 'isb_endtime'

    #: isb_ifrecv
    isb_ifrecv: 'OptionType' = 4, 'isb_ifrecv'

    #: isb_ifdrop
    isb_ifdrop: 'OptionType' = 5, 'isb_ifdrop'

    #: isb_filteraccept
    isb_filteraccept: 'OptionType' = 6, 'isb_filteraccept'

    #: isb_osdrop
    isb_osdrop: 'OptionType' = 7, 'isb_osdrop'

    #: isb_usrdeliv
    isb_usrdeliv: 'OptionType' = 8, 'isb_usrdeliv'

    #: pack_flags
    pack_flags: 'OptionType' = 2, 'pack_flags'

    #: pack_hash
    pack_hash: 'OptionType' = 3, 'pack_hash'

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1, *, namespace: 'str' = 'opt') -> 'OptionType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.
            namespace: Namespace of the enum item.

        :meta private:
        """
        if isinstance(key, int):
            temp_ns = OptionType.__members_ns__.get('opt', {}).copy()
            temp_ns.update(OptionType.__members_ns__.get(namespace, {}))
            if key in temp_ns:
                return temp_ns[key]
            return extend_enum(OptionType, '%s_unknown_%d' % (namespace, key), key, '%s_unknown' % namespace)
        if key in OptionType.__members__:
            return getattr(OptionType, key)
        return extend_enum(OptionType, key, default, key)

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if value in cls.__members_ns__.get('opt', {}):
            return cls.__members_ns__['opt'][value]
        return extend_enum(cls, 'opt_unknown_%d' % value, value, 'opt_unknown')

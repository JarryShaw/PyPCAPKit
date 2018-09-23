# -*- coding: utf-8 -*-
"""(inverse) address resolution protocol

`pcapkit.protocols.link.arp` contains `ARP` only,
which implements extractor for (Inverse) Address Resolution
Protocol (ARP/InARP), whose structure is described as below.

Octets      Bits        Name                    Description
  0           0     arp.htype               Hardware Type
  2          16     arp.ptype               Protocol Type
  4          32     arp.hlen                Hardware Address Length
  5          40     arp.plen                Protocol Address Length
  6          48     arp.oper                Operation
  8          64     arp.sha                 Sender Hardware Address
  14        112     arp.spa                 Sender Protocol Address
  18        144     arp.tha                 Target Hardware Address
  24        192     arp.tpa                 Target Protocol Address

"""
import collections
import ipaddress
import re
import textwrap

from pcapkit._common.arp_hrd import HrdType as HRD
from pcapkit._common.arp_oper import OperType as OPER
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import ETHERTYPE
from pcapkit.protocols.link.link import Link

__all__ = ['ARP']


class ARP(Link):
    """This class implements all protocols in ARP family.

    - Address Resolution Protocol (ARP) [RFC 826]
    - Reverse Address Resolution Protocol (RARP) [RFC 903]
    - Dynamic Reverse Address Resolution Protocol (DRARP) [RFC 1931]
    - Inverse Address Resolution Protocol (InARP) [RFC 2390]

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- tuple<str, str>, sender hardware & protocol address
        * dst -- tuple<str, str>, target hardware & protocol address
        * type -- tuple<str, str>, hardware & protocol type

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_arp -- read Address Resolution Protocol

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance
        * _acnm -- str, acronym of corresponding protocol
        * _name -- str, name of corresponding protocol

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _read_addr_resolve -- resolve MAC address according to protocol
        * _read_proto_resolve -- solve IP address according to protocol

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return self._name

    @property
    def alias(self):
        """Acronym of corresponding protocol."""
        return self._acnm

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.len

    @property
    def src(self):
        """Sender hardware & protocol address."""
        return (self._info.sha, self._info.spa)

    @property
    def dst(self):
        """Target hardware & protocol address."""
        return (self._info.tha, self._info.tpa)

    @property
    def type(self):
        """Hardware & protocol type."""
        return (self._info.htype, self._info.ptype)

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_arp(self, length):
        """Read Address Resolution Protocol.

        Structure of ARP header [RFC 826]:
            Octets      Bits        Name                    Description
              0           0     arp.htype               Hardware Type
              2          16     arp.ptype               Protocol Type
              4          32     arp.hlen                Hardware Address Length
              5          40     arp.plen                Protocol Address Length
              6          48     arp.oper                Operation
              8          64     arp.sha                 Sender Hardware Address
              14        112     arp.spa                 Sender Protocol Address
              18        144     arp.tha                 Target Hardware Address
              24        192     arp.tpa                 Target Protocol Address

        """
        if length is None:
            length = len(self)

        _hwty = self._read_unpack(2)
        _ptty = self._read_unpack(2)
        _hlen = self._read_unpack(1)
        _plen = self._read_unpack(1)
        _oper = self._read_unpack(2)
        _shwa = self._read_addr_resolve(_hlen, _hwty)
        _spta = self._read_proto_resolve(_plen, _ptty)
        _thwa = self._read_addr_resolve(_hlen, _hwty)
        _tpta = self._read_proto_resolve(_plen, _ptty)

        if _oper in (5, 6, 7):
            self._acnm = 'DRARP'
            self._name = 'Dynamic Reverse Address Resolution Protocol'
        elif _oper in (8, 9):
            self._acnm = 'InARP'
            self._name = 'Inverse Address Resolution Protocol'
        elif _oper in (3, 4):
            self._acnm = 'RARP'
            self._name = 'Reverse Address Resolution Protocol'
        else:
            self._acnm = 'ARP'
            self._name = 'Address Resolution Protocol'

        _htype = HRD.get(_hwty)
        if re.match(r'.*Ethernet.*', _htype, re.IGNORECASE):
            _ptype = ETHERTYPE.get(_ptty)
        else:
            _ptype = 'Unknown [{}]'.format(_ptty)

        arp = dict(
            htype=_htype,
            ptype=_ptype,
            hlen=_hlen,
            plen=_plen,
            oper=OPER.get(_oper),
            sha=_shwa,
            spa=_spta,
            tha=_thwa,
            tpa=_tpta,
            len=8 + _hlen * 2 + _plen * 2,
        )

        length -= arp['len']
        arp['packet'] = self._read_packet(header=arp['len'], payload=length)

        return self._decode_next_layer(arp, None, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_arp(length))

    def __length_hint__(self):
        return 28

    @classmethod
    def __index__(cls):
        return ('ARP', 'InARP')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_addr_resolve(self, length, htype):
        """Resolve MAC address according to protocol.

        Positional arguments:
            * length -- int, hardware address length
            * htype -- int, hardware type

        Returns:
            * str -- MAC address

        """
        if htype == 1:  # Ethernet
            _byte = self._read_fileng(6)
            _addr = '-'.join(textwrap.wrap(_byte.hex(), 2))
        else:
            _addr = self._read_fileng(length)
        return _addr

    def _read_proto_resolve(self, length, ptype):
        """Resolve IP address according to protocol.

        Positional arguments:
            * length -- int, protocol address length
            * ptype -- int, protocol type

        Returns:
            * str -- IP address

        """
        # if ptype == '0800':     # IPv4
        #     _byte = self._read_fileng(4)
        #     _addr = '.'.join([str(_) for _ in _byte])
        # elif ptype == '86dd':   # IPv6
        #     adlt = []       # list of IPv6 hexadecimal address
        #     ctr_ = collections.defaultdict(int)
        #                     # counter for consecutive groups of zero value
        #     ptr_ = 0        # start pointer of consecutive groups of zero value
        #     last = False    # if last hextet/group is zero value
        #     omit = False    # omitted flag, since IPv6 address can omit to `::` only once

        #     for index in range(8):
        #         hex_ = self._read_fileng(2).hex().lstrip('0')

        #         if hex_:    # if hextet is not '', directly append
        #             adlt.append(hex_)
        #             last = False
        #         else:       # if hextet is '', append '0'
        #             adlt.append('0')
        #             if last:    # if last hextet is '', ascend counter
        #                 ctr_[ptr_] += 1
        #             else:       # if last hextet is not '', record pointer
        #                 ptr_ = index
        #                 last = True
        #                 ctr_[ptr_] = 1

        #     ptr_ = max(ctr_, key=ctr_.get) if ctr_ else 0   # fetch start pointer with longest zero values
        #     end_ = ptr_ + ctr_[ptr_]                        # calculate end pointer

        #     if ctr_[ptr_] > 1:      # only omit if zero values are in a consecutive group
        #         del adlt[ptr_:end_] # remove zero values

        #         if ptr_ == 0 and end_ == 8:     # insert `::` if IPv6 unspecified address (::)
        #             adlt.insert(ptr_, '::')
        #         elif ptr_ == 0 or end_ == 8:    # insert `:` if zero values are from start or at end
        #             adlt.insert(ptr_, ':')
        #         else:                           # insert '' otherwise
        #             adlt.insert(ptr_, '')

        #     _addr = ':'.join(adlt)
        # else:
        #     _addr = self._read_fileng(length)
        # return _addr
        if ptype == '0800':     # IPv4
            return ipaddress.ip_address(self._read_fileng(4))
        elif ptype == '86dd':   # IPv6
            return ipaddress.ip_address(self._read_fileng(16))
        else:
            return self._read_fileng(length)

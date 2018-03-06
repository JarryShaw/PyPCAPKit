#!/usr/bin/python3
# -*- coding: utf-8 -*-


import collections
import textwrap


# Address Resolution Protocol
# Analyser for ARP/InARP header


from jspcap.utilities import Info
from jspcap.protocols.internet.internet import ETHERTYPE
from jspcap.protocols.link.link import Link, LINKTYPE


__all__ = ['ARP']


# Operation Codes [RFC 826][RFC 5494]
OPER = {
    0 : 'Reserved',         # [RFC 5494]
    1 : 'REQUEST',          # [RFC 826][RFC 5227]
    2 : 'REPLY',            # [RFC 826][RFC 5227]
    3 : 'request Reverse',  # [RFC 826][RFC 5227]
    4 : 'reply Reverse',    # [RFC 903]
    5 : 'DRARP-Request',    # [RFC 1931]
    6 : 'DRARP-Reply',      # [RFC 1931]
    7 : 'DRARP-Error',      # [RFC 1931]
    8 : 'InARP-Request',    # [RFC 2390]
    9 : 'InARP-Reply',      # [RFC 2390]
   10 : 'ARP-NAK',          # [RFC 1577]
65535 : 'Reserved',         # [RFC 5494]
}


class ARP(Link):
    """This class implements all protocols in ARP family.

     - Address Resolution Protocol (ARP) [RFC 826]
     - Reverse Address Resolution Protocol (RARP) [RFC 903]
     - Dynamic Reverse Address Resolution Protocol (DRARP) [RFC 1931]
     - Inverse Address Resolution Protocol (IARP) [RFC 2390]

     Properties:
         * name -- str, name of corresponding procotol
         * info -- Info, info dict of current instance
         * layer -- str, `Link`
         * length -- int, header length of corresponding protocol
         * protocol -- str, name of next layer protocol
         * protochain -- ProtoChain, protocol chain of current instance
         * src -- tuple(str, str), sender hardware & protocol address
         * dst -- tuple(str, str), target hardware & protocol address
         * type -- tuple(str, str), hardware & protocol type

    Methods:
        * read_arp -- read Address Resolution Protocol

     Attributes:
         * _file -- BytesIO, bytes to be extracted
         * _info -- Info, info dict of current instance
         * _protos -- ProtoChain, protocol chain of current instance

     Utilities:
         * _read_protos -- read next layer protocol type
         * _read_fileng -- read file buffer
         * _read_unpack -- read bytes and unpack to integers
         * _read_binary -- read bytes and convert into binaries
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
        return self._name

    @property
    def length(self):
        return self._info.len

    @property
    def src(self):
        return (self._info.sha, self._info.spa)

    @property
    def dst(self):
        return (self._info.tha, self._info.tpa)

    @property
    def type(self):
        return (self._info.htype, self._info.ptype)

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_arp(self, length):
        """Read Address Resolution Protocol.

        Structure of ARP header [RFC 826]:
            Octets          Bits          Name                Discription
              0              0          arp.htype         Hardware Type
              2              16         arp.ptype         Protocol Type
              4              32         arp.hlen          Hardware Address Length
              5              40         arp.plen          Protocol Address Length
              6              48         arp.oper          Operation
              8              64         arp.sha           Sender Hardware Address
              14             112        arp.spa           Sender Protocol Address
              18             144        arp.tha           Target Hardware Address
              24             192        arp.tpa           Target Protocol Address
        """
        _hwty = self._read_unpack(2)
        _ptty = self._read_fileng(2).hex()
        _hlen = self._read_unpack(1)
        _plen = self._read_unpack(1)
        _oper = self._read_unpack(2)
        _shwa = self._read_addr_resolve(_hlen, _hwty)
        _spta = self._read_proto_resolve(_plen, _ptty)
        _thwa = self._read_addr_resolve(_hlen, _hwty)
        _tpta = self._read_proto_resolve(_plen, _ptty)

        if _oper in (5, 6, 7):
            self._name = 'Dynamic Reverse Address Resolution Protocol'
        elif _oper in (8, 9):
            self._name = 'Inverse Address Resolution Protocol'
        else:
            self._name = 'Address Resolution Protocol'

        arp = dict(
            htype = LINKTYPE.get(_hwty),
            ptype = ETHERTYPE.get(_ptty),
            hlen = _hlen,
            plen = _plen,
            oper = OPER.get(_oper),
            sha = _shwa,
            spa = _spta,
            tha = _thwa,
            tpa = _tpta,
            len = 8 + _hlen * 2 + _plen * 2,
        )

        proto = None
        if length is not None:
            length -= arp['len']
        return self._decode_next_layer(arp, proto, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_arp(length))

    def __len__(self):
        return self._info.len

    def __length_hint__(self):
        return 28

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_addr_resolve(self, length, htype):
        """Resolve MAC address according to protocol.

        Keyword arguments:
            * length -- int, hardware address length
            * htype -- int, hardware type

        """
        if htype == 1:  # Ethernet
            _byte = self._read_fileng(6)
            _addr = '-'.join(textwrap.wrap(_byte.hex(), 2))
        else:
            _addr = self._read_fileng(length)
        return _addr

    def _read_proto_resolve(self, length, ptype):
        """Resolve IP address according to protocol.

        Keyword arguments:
            * length -- int, protocol address length
            * hptype -- int, protocol type

        """
        if ptype == '0800':     # IPv4
            _byte = self._read_fileng(4)
            _addr = '.'.join([str(_) for _ in _byte])
        elif ptype == '86dd':   # IPv6
            adlt = []       # list of IPv6 hexadecimal address
            ctr_ = collections.defaultdict(int)
                            # counter for consecutive groups of zero value
            ptr_ = 0        # start pointer of consecutive groups of zero value
            last = False    # if last hextet/group is zero value
            ommt = False    # ommitted flag, since IPv6 address can ommit to `::` only once

            for _ in range(8):
                hex_ = self._read_fileng(2).hex().lstrip('0')

                if hex_:    # if hextet is not '', directly append
                    adlt.append(hex_)
                    last = False
                else:       # if hextet is '', append '0'
                    adlt.append('0')
                    if last:    # if last hextet is '', ascend counter
                        ctr_[ptr_] += 1
                    else:       # if last hextet is not '', record pointer
                        ptr_ = _
                        last = True
                        ctr_[ptr_] = 1

            ptr_ = max(ctr_, key=ctr_.get) if ctr_ else 0   # fetch start pointer with longest zero values
            end_ = ptr_ + ctr_[ptr_]                        # calculate end pointer

            if ctr_[ptr_] > 1:      # only ommit if zero values are in a consecutive group
                del adlt[ptr_:end_] # remove zero values

                if ptr_ == 0 and end_ == 8:     # insert `::` if IPv6 unspecified address (::)
                    adlt.insert(ptr_, '::')
                elif ptr_ == 0 or end_ == 8:    # insert `:` if zero values are from start or at end
                    adlt.insert(ptr_, ':')
                else:                           # insert '' otherwise
                    adlt.insert(ptr_, '')

            addr = ':'.join(adlt)
        else:
            _addr = self._read_fileng(length)
        return _addr

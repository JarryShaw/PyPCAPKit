#!/usr/bin/python3
# -*- coding: utf-8 -*-


# TODO: Implements IPv6 extension headers.


import collections


# Internet Protocol version 6
# Analyser for IPv6 header


from jspcap.utilities import Info
from jspcap.protocols.internet.ip import IP


__all__ = ['IPv6']


# IPv6 Extension Header Types
EXT_HDR = (
    'HOPOPT',       # IPv6 Hop-by-Hop Option
    'IPv6-Route',   # Routing Header for IPv6
    'IPv6-Frag',    # Fragment Header for IPv6
    'ESP',          # Encapsulating Security Payload
    'AH',           # Authentication Header
    'IPv6-NoNxt',   # No Next Header for IPv6
    'IPv6-Opts',    # Destination Options for IPv6 (before routing / upper-layer header)
    'Mobility',     # Mobility Extension Header for IPv6 (currently without upper-layer header)
    'HIP',          # Host Identity Protocol
    'Shim6',        # Site Multihoming by IPv6 Intermediation
)

class IPv6(IP):
    """This class implements Internet Protocol version 6.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source IP address
        * dst -- str, destination IP address

    Methods:
        * read_ipv4 -- read Internet Protocol version 6 (IPv6)

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
        * _read_ip_seekset -- when fragmented, read payload throughout first
        * _read_ip_hextet -- read first four hextets of IPv6
        * _read_ip_addr -- read IP address
        * _read_ip_options -- read IP option list

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 6'

    @property
    def length(self):
        return self._info.hdr_len

    @property
    def protocol(self):
        return self._info.next

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ipv6(self, length):
        """Read Internet Protocol version 6 (IPv6).

        Structure of IPv6 header [RFC 2460]:

             0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version| Traffic Class |           Flow Label                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Payload Length        |  Next Header  |   Hop Limit   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                         Source Address                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                      Destination Address                      +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets          Bits          Name                Discription
              0              0          ip.version        Version (6)
              0              4          ip.class          Traffic Class
              1              12         ip.label          Flow Label
              4              32         ip.payload        Payload Length (header excludes)
              6              48         ip.next           Next Header
              7              56         ip.limit          Hop Limit
              8              64         ip.src            Source Address
              24             192        ip.dst            Destination Address

        """
        _htet = self._read_ip_hextet()
        _plen = self._read_unpack(2)
        _next = self._read_protos(1)
        _hlmt = self._read_unpack(1)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ipv6 = dict(
            version = _htet[0],
            tclass = _htet[1],
            label = _htet[2],
            payload = _plen,
            next = _next,
            limit = _hlmt,
            src = _srca,
            dst = _dsta,
        )

        return self._decode_next_layer(ipv6, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_ipv6(length))

    def __len__(self):
        return self._info.hdr_len

    def __length_hint__(self):
        return 40

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ip_hextet(self):
        """Read first four hextets of IPv6."""
        _htet = self._read_fileng(4).hex()
        _vers = _htet[0]                    # version number (6)
        _tcls = int(_htet[0:2], base=16)    # traffic class
        _flow = int(_htet[2:], base=16)     # flow label

        return (_vers, _tcls, _flow)

    def _read_ip_addr(self):
        """Read IP address."""
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
        return addr

    def _decode_next_layer(self, ipv6, proto=None, length=None):
        """Decode next layer extractor.

        Keyword arguments:
            ipv6 -- dict, info buffer
            proto -- str, next layer protocol name
            length -- int, valid (not padding) length

        """
        # recurse if next header is an extensive header
        hdr_len = 40                # header length
        raw_len = ipv6['payload']   # payload length
        while proto in EXT_HDR:
            # break & keep original data after fragment header
            if proto == 'IPv6-Frag':
                ipv6 = self._read_ip_seekset(ipv6, hdr_len, raw_len)
                break

            # make & record protocol name
            name_ = proto.replace('IPv6-', '').lower()
            next_ = self._import_next_layer(proto)
            ipv6[name_] = next_[0]
            if next_[1] is None:
                break
            proto = next_[0].next

            # update header & payload length
            hdr_len += next_[0].hdr_len
            raw_len -= next_[0].hdr_len

        # record real header & payload length (headers exclude)
        ipv6['hdr_len'] = hdr_len
        ipv6['raw_len'] = raw_len

        # update next header
        ipv6['proto'] = proto
        return super()._decode_next_layer(ipv6, proto, raw_len)

# -*- coding: utf-8 -*-
"""internet protocol version 6

`pcapkit.protocols.internet.ipv6` contains `IPv6` only,
which implements extractor for Internet Protocol version 6
(IPv6), whose structure is described as below.

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

"""
import collections
import ipaddress

from pcapkit._common.ipv6_ext_hdr import EXT_HDR
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.ip import IP

# TODO: Implements IPv6 extension headers.
__all__ = ['IPv6']


class IPv6(IP):
    """This class implements Internet Protocol version 6.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- str, source IP address
        * dst -- str, destination IP address

    Methods:
        * read_ipv6 -- read Internet Protocol version 6 (IPv6)

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor
        * _read_ip_hextet -- read first four hextets of IPv6
        * _read_ip_addr -- read IP address

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Internet Protocol version 6'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return self._info.hdr_len

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.protocol

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

            Octets      Bits        Name                    Description
              0           0     ip.version              Version (6)
              0           4     ip.class                Traffic Class
              1          12     ip.label                Flow Label
              4          32     ip.payload              Payload Length (header excludes)
              6          48     ip.next                 Next Header
              7          56     ip.limit                Hop Limit
              8          64     ip.src                  Source Address
              24        192     ip.dst                  Destination Address

        """
        if length is None:
            length = len(self)

        _htet = self._read_ip_hextet()
        _plen = self._read_unpack(2)
        _next = self._read_protos(1)
        _hlmt = self._read_unpack(1)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ipv6 = dict(
            version=_htet[0],
            tclass=_htet[1],
            label=_htet[2],
            payload=_plen,
            next=_next,
            limit=_hlmt,
            src=_srca,
            dst=_dsta,
        )

        hdr_len = 40
        raw_len = ipv6['payload']
        ipv6['packet'] = self._read_packet(header=hdr_len, payload=raw_len)

        return self._decode_next_layer(ipv6, _next, raw_len)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_ipv6(length))

    def __length_hint__(self):
        return 40

    @classmethod
    def __index__(cls):
        return cls.__name__

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
        # adlt = []       # list of IPv6 hexadecimal address
        # ctr_ = collections.defaultdict(int)
        #                 # counter for consecutive groups of zero value
        # ptr_ = 0        # start pointer of consecutive groups of zero value
        # last = False    # if last hextet/group is zero value
        # omit = False    # omitted flag, since IPv6 address can omit to `::` only once

        # for _ in range(8):
        #     hex_ = self._read_fileng(2).hex().lstrip('0')

        #     if hex_:    # if hextet is not '', directly append
        #         adlt.append(hex_)
        #         last = False
        #     else:       # if hextet is '', append '0'
        #         adlt.append('0')
        #         if last:    # if last hextet is '', ascend counter
        #             ctr_[ptr_] += 1
        #         else:       # if last hextet is not '', record pointer
        #             ptr_ = _
        #             last = True
        #             ctr_[ptr_] = 1

        # ptr_ = max(ctr_, key=ctr_.get) if ctr_ else 0   # fetch start pointer with longest zero values
        # end_ = ptr_ + ctr_[ptr_]                        # calculate end pointer

        # if ctr_[ptr_] > 1:      # only omit if zero values are in a consecutive group
        #     del adlt[ptr_:end_] # remove zero values

        #     if ptr_ == 0 and end_ == 8:     # insert `::` if IPv6 unspecified address (::)
        #         adlt.insert(ptr_, '::')
        #     elif ptr_ == 0 or end_ == 8:    # insert `:` if zero values are from start or at end
        #         adlt.insert(ptr_, ':')
        #     else:                           # insert '' otherwise
        #         adlt.insert(ptr_, '')

        # addr = ':'.join(adlt)
        # return addr
        return ipaddress.ip_address(self._read_fileng(16))

    def _decode_next_layer(self, ipv6, proto=None, length=None):
        """Decode next layer extractor.

        Positional arguments:
            * ipv6 -- dict, info buffer
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Returns:
            * dict -- current protocol with next layer extracted

        """
        hdr_len = 40                # header length
        raw_len = ipv6['payload']   # payload length
        _protos = list()            # ProtoChain buffer

        # traverse if next header is an extensive header
        while proto in EXT_HDR:
            # keep original data after fragment header
            if proto.value == 44:
                ipv6['fragment'] = self._read_packet(header=hdr_len, payload=raw_len)

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            next_ = self._import_next_layer(proto, version=6, extension=True)
            info = next_.info
            name = next_.alias.lstrip('IPv6-').lower()
            ipv6[name] = info

            # record protocol name
            # self._protos = ProtoChain(name, chain, alias)
            _protos.append(next_)
            proto = info.next

            # update header & payload length
            hdr_len += info.length
            raw_len -= info.length

        # record real header & payload length (headers exclude)
        ipv6['hdr_len'] = hdr_len
        ipv6['raw_len'] = raw_len

        # update next header
        ipv6['protocol'] = proto
        return super()._decode_next_layer(ipv6, proto, raw_len, ipv6_exthdr=_protos)

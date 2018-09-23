# -*- coding: utf-8 -*-
"""internetwork packet exchange

`pcapkit.protocols.internet.ipx` contains `IPX` only,
which implements extractor for Internetwork Packet
Exchange (IPX), whose structure is described as below.

Octets      Bits        Name                    Description
  0           0     ipx.cksum               Checksum
  2          16     ipx.len                 Packet Length (header includes)
  4          32     ipx.count               Transport Control (hop count)
  5          40     ipx.type                Packet Type
  6          48     ipx.dst                 Destination Address
  18        144     ipx.src                 Source Address

"""
import textwrap

from pcapkit._common.ipx_sock import Sockets as SOCK
from pcapkit._common.ipx_type import PktType as TYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet

__all__ = ['IPX']


class IPX(Internet):
    """This class implements Internetwork Packet Exchange.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- Info, source IPX address
        * dst -- Info, destination IPX address

    Methods:
        * read_ipx -- read Internetwork Packet Exchange

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
        * _read_ipx_address -- read IPX address field

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Internetwork Packet Exchange'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 30

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.type

    @property
    def src(self):
        """Source IPX address."""
        return self._info.src.addr

    @property
    def dst(self):
        """Destination IPX address."""
        return self._info.dst.addr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ipx(self, length):
        """Read Internetwork Packet Exchange.

        Structure of IPX header [RFC 1132]:
            Octets      Bits        Name                    Description
              0           0     ipx.cksum               Checksum
              2          16     ipx.len                 Packet Length (header includes)
              4          32     ipx.count               Transport Control (hop count)
              5          40     ipx.type                Packet Type
              6          48     ipx.dst                 Destination Address
              18        144     ipx.src                 Source Address

        """
        if length is None:
            length = len(self)

        _csum = self._read_fileng(2)
        _tlen = self._read_unpack(2)
        _ctrl = self._read_unpack(1)
        _type = self._read_unpack(1)
        _dsta = self._read_ipx_address()
        _srca = self._read_ipx_address()

        ipx = dict(
            chksum=_csum,
            len=_tlen,
            count=_ctrl,
            type=TYPE.get(_type),
            dst=_dsta,
            src=_srca,
        )

        proto = ipx['type']
        length = ipx['len'] - 30
        ipx['packet'] = self._read_packet(header=30, payload=length)

        return self._decode_next_layer(ipx, proto, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_ipx(length))

    def __length_hint__(self):
        return 30

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ipx_address(self):
        """Read IPX address field.

        Structure of IPX address:
            Octets      Bits        Name                    Description
              0           0     ipx.addr.network        Network Number
              4          32     ipx.addr.node           Node Number
              10         80     ipx.addr.socket         Socket Number

        """
        # Address Number
        _byte = self._read_fileng(4)
        _ntwk = ':'.join(textwrap.wrap(_byte.hex(), 2))

        # Node Number (MAC)
        _byte = self._read_fileng(6)
        _node = ':'.join(textwrap.wrap(_byte.hex(), 2))
        _maca = '-'.join(textwrap.wrap(_byte.hex(), 2))

        # Socket Number
        _sock = self._read_fileng(2)

        # Whole Address
        _list = [_ntwk, _node, _sock.hex()]
        _addr = ':'.join(_list)

        addr = dict(
            network=_ntwk,
            node=_maca,
            socket=SOCK.get(int(_sock.hex(), base=16)) or _sock,
            addr=_addr,
        )

        return addr

# -*- coding: utf-8 -*-
"""layer two tunnelling protocol

`pcapkit.protocols.link.l2tp` contains `L2TP` only,
which implements extractor for Layer Two Tunnelling Protocol
(L2TP), whose structure is described as below.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Tunnel ID           |           Session ID          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Ns (opt)          |             Nr (opt)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Offset Size (opt)        |    Offset pad... (opt)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.link.link import Link

__all__ = ['L2TP']


class L2TP(Link):
    """This class implements Layer Two Tunnelling Protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * type -- str, L2TP packet type
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * type -- str, L2TP type

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_l2tp -- read Layer Two Tunnelling Protocol

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

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return 'Layer 2 Tunnelling Protocol'

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def type(self):
        """L2TP type."""
        return self._info.flags.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_l2tp(self, length):
        """Read Layer Two Tunnelling Protocol.

        Structure of L2TP header [RFC 2661]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Tunnel ID           |           Session ID          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Ns (opt)          |             Nr (opt)          |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |      Offset Size (opt)        |    Offset pad... (opt)
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     l2tp.flags              Flags and Version Info
              0           0     l2tp.flags.type         Type (0/1)
              0           1     l2tp.flags.len          Length
              0           2     -                       Reserved (must be zero)
              0           4     l2tp.flags.seq          Sequence
              0           5     -                       Reserved (must be zero)
              0           6     l2tp.flags.offset       Offset
              0           7     l2tp.flags.prio         Priority
              1           8     -                       Reserved (must be zero)
              1          12     l2tp.ver                Version (2)
              2          16     l2tp.length             Length (optional by len)
              4          32     l2tp.tunnelid           Tunnel ID
              6          48     l2tp.sessionid          Session ID
              8          64     l2tp.ns                 Sequence Number (optional by seq)
              10         80     l2tp.nr                 Next Sequence Number (optional by seq)
              12         96     l2tp.offset             Offset Size (optional by offset)

        """
        if length is None:
            length = len(self)

        _flag = self._read_binary(1)
        _vers = self._read_fileng(1).hex()[1]
        _hlen = self._read_unpack(2) if int(_flag[1]) else None
        _tnnl = self._read_unpack(2)
        _sssn = self._read_unpack(2)
        _nseq = self._read_unpack(2) if int(_flag[4]) else None
        _nrec = self._read_unpack(2) if int(_flag[4]) else None
        _size = self._read_unpack(2) if int(_flag[6]) else 0

        l2tp = dict(
            flags=dict(
                type='Control' if int(_flag[0]) else 'Data',
                len=True if int(_flag[1]) else False,
                seq=True if int(_flag[4]) else False,
                offset=True if int(_flag[6]) else False,
                prio=True if int(_flag[7]) else False,
            ),
            ver=int(_vers, base=16),
            length=_hlen,
            tunnelid=_tnnl,
            sessionid=_sssn,
            ns=_nseq,
            nr=_nrec,
            offset=8*_size or None,
        )

        hdr_len = _hlen or (6 + 2*(int(_flag[1]) + 2*int(_flag[4]) + int(_flag[6])))
        l2tp['hdr_len'] = hdr_len + _size * 8
        # if _size:
        #     l2tp['padding'] = self._read_fileng(_size * 8)

        length -= l2tp['hdr_len']
        l2tp['packet'] = self._read_packet(header=l2tp['hdr_len'], payload=length)

        return self._decode_next_layer(l2tp, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_l2tp(length))

    def __length_hint__(self):
        return 16

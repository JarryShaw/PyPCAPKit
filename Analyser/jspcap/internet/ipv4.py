#!/usr/bin/python3
# -*- coding: utf-8 -*-


import struct


# Internet Protocol version 4
# Analyser for IPv4 header


from ..protocol import Info, Protocol
from ..transport.transport import TP_PROTO


class IPv4(Protocol):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer', 'protocol']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 4'

    @property
    def info(self):
        return self._info

    @property
    def length(self):
        return self._info.hdr_len

    @property
    def src(self):
        return self._info.src

    @property
    def dst(self):
        return self._info.dst

    @property
    def layer(self):
        return self.__layer__

    @property
    def protocol(self):
        return self._info.proto

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_ipv4())

    def __len__(self):
        return self._info.hdr_len

    def __length_hint__(self):
        return 20

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_ipv4(self):
        """Read Internet Protocol version 4 (IPv4).

        Structure of IPv4 header:
            Octets          Bits          Name                Discription
              0              0          ip.version        Version
              0              4          ip.hdr_len        Interal Header Length (IHL)
              1              8          ip.dsfield.dscp   Differentiated Services Code Point (DSCP)
              1              14         ip.dsfield.ecn    Explicit Congestion Notification (ECN)
              2              16         ip.len            Total Length
              4              32         ip.id             Identification
              6              48         ip.flags.rb       Reserved Bit (must be zero)
              6              49         ip.flags.df       Don't Fragment (DF)
              6              50         ip.flags.mf       More Fragments (MF)
              6              51         ip.frag_offset    Fragment Offset
              8              64         ip.ttl            Time To Live (TTL)
              9              72         ip.proto          Protocol (Transport Layer)
              10             80         ip.checksum       Header Checksum
              12             96         ip.src            Source IP Address
              16             128        ip.dst            Destination IP Address
              20             160        ip.options        IP Options (if IHL > 5)

        """
        _vihl = self._file.read(1).hex()
        _dscp = self.read_binary(self._file, 1)
        _tlen = self.read_unpack(self._file, 2)
        _iden = self.read_unpack(self._file, 2)
        _frag = self.read_binary(self._file, 2)
        _ttol = self.read_unpack(self._file, 1)
        _prot = self._read_ip_proto()
        _csum = self._file.read(2)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ip = dict(
            version = _vihl[0],
            hdr_len = int(_vihl[1], base=16) * 4,
            dsfield = dict(
                dscp = int(_dscp[:-2], base=2),
                ecn = int(_dscp[-2:], base=2),
            ),
            len = _tlen,
            id = _iden,
            flags = dict(
                rb = b'\x00',
                df = True if _frag[1] else False,
                mf = True if _frag[2] else False,
            ),
            frag_offset = int(_frag[3:], base=2),
            ttl = _ttol,
            proto = _prot,
            checksum = _csum,
            src = _srca,
            dst = _dsta,
        )

        _optl = ip['hdr_len'] - 20
        if _optl:
            ip['options'] = self._read_ipv4_options(_optl)

        return ip

    def _read_ip_addr(self):
        _byte = self._file.read(4)
        _addr = '.'.join([str(_) for _ in _byte])
        return _addr

    def _read_ip_proto(self):
        _byte = struct.unpack('>B', self._file.read(1))[0]
        _prot = TP_PROTO.get(_byte)
        return _prot

    def _read_ipv4_options(self, size=None):
        return self._file.read(size)

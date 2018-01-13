#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Internet Protocol version 4
# Analyser for IPv4 header


from .ip import IP
from ..utilities import Info, ProtoChain


# TOS (DS Field) Precedence
TOS_PRE = {
    '111':  'Network Control',
    '110':  'Internetwork Control',
    '101':  'CRITIC/ECP',
    '100':  'Flash Override',
    '011':  'Flash',
    '010':  'Immediate',
    '001':  'Priority',
    '000':  'Routine',
}

# TOS (DS Field) Delay
TOS_DEL = {
    '0':    'Normal Delay',
    '1':    'Low Delay',
}

# TOS (DS Field) Throughput
TOS_THR = {
    '0':    'Normal Throughput',
    '1':    'High Throughput',
}

# TOS (DS Field) Relibility
TOS_REL = {
    '0':    'Normal Relibility',
    '1':    'High Relibility',
}

# TOS ECN FIELD
TOS_ECN = {
    '00':   'Not-ECT',
    '01':   'ECT(1)',
    '10':   'ECT(0)',
    '11':   'CE',
}


class IPv4(IP):

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Internet Protocol version 4'

    @property
    def length(self):
        return self._info.hdr_len

    @property
    def protocol(self):
        return self._info.proto

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_ipv4(length))

    def __len__(self):
        return self._info.hdr_len

    def __length_hint__(self):
        return 20

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_ipv4(self, length):
        """Read Internet Protocol version 4 (IPv4).

        Structure of IPv4 header [RFC 791]:

             0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version|  IHL  |Type of Service|          Total Length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Identification        |Flags|      Fragment Offset    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Time to Live |    Protocol   |         Header Checksum       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Source Address                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Destination Address                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Options                    |    Padding    |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets          Bits          Name                Discription
              0              0          ip.version        Version (4)
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
        _vihl = self._read_fileng(1).hex()
        _dscp = self._read_binary(1)
        _tlen = self._read_unpack(2)
        _iden = self._read_unpack(2)
        _frag = self._read_binary(2)
        _ttol = self._read_unpack(1)
        _prot = self._read_protos(1)
        _csum = self._read_fileng(2)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ipv4 = dict(
            version = _vihl[0],
            hdr_len = int(_vihl[1], base=16) * 4,
            dsfield = dict(
                dscp = (
                    TOS_PRE.get(_dscp[:3]),
                    TOS_DEL.get(_dscp[3]),
                    TOS_THR.get(_dscp[4]),
                    TOS_REL.get(_dscp[5]),
                ),
                ecn = TOS_ECN.get(_dscp[-2:]),
            ),
            len = _tlen,
            id = _iden,
            flags = dict(
                rb = b'\x00',
                df = True if int(_frag[1]) else False,
                mf = True if int(_frag[2]) else False,
            ),
            frag_offset = int(_frag[3:], base=2) * 8,
            ttl = _ttol,
            proto = _prot,
            checksum = _csum,
            src = _srca,
            dst = _dsta,
        )

        _optl = ipv4['hdr_len'] - 20
        if _optl:
            ipv4['options'] = self._read_ip_options(_optl)

        hdr_len = ipv4['hdr_len']
        raw_len = ipv4['len'] - hdr_len

        if not ipv4['flags']['df']:
            ipv4 = self._read_ip_seekset(ipv4, hdr_len, raw_len)

        # make next layer protocol name
        proto = ipv4['proto']
        if proto is None:
            proto = ''
        name_ = proto.lower() or 'raw'
        proto = proto or None
        self._protos = ProtoChain(proto)

        return self._read_next_layer(ipv4, _prot, raw_len)

    def _read_ip_addr(self):
        _byte = self._read_fileng(4)
        _addr = '.'.join([str(_) for _ in _byte])
        return _addr

    def _read_ip_options(self, size=None):
        return self._read_fileng(size)

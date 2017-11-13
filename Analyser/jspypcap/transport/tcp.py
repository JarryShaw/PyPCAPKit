#!/usr/bin/python3
# -*- coding: utf-8 -*-


# Transport Control Protocol
# Analyser for TCP header


from transport import Transport

from ..exceptions import StringError


# TCP Options
TCP_OPT = {
    0:  (True, None),
    1:  (True, 0, 'No-Operation'),
    2:  (True, 4, 'Maximum Segment Size'),
    3:  (True, 4, 'Window Scale'),
    4:  (True, 2, 'SACK Permitted'),
    5:  (False, 'SACK'),
}


class TCP(Transport):

    __all__ = ['name', 'layer', 'source', 'destination']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Transport Control Protocol'

    @property
    def layer(self):
        return self.__layer__

    @property
    def length(self):
        pass

    @property
    def source(self):
        self._dict['src']

    @property
    def destination(self):
        self._dict['dst']

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._dict = self.read_tcp()

    def __len__(self):
        return self._dict['hdr_len']

    def __length_hint__(self):
        return 20

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self._dict[key]
            except KeyError:
                return None
        else:
            raise StringError

    ##########################################################################
    # Utilities.
    ##########################################################################

    def read_tcp(self):
        """Read Transmission Control Protocol (TCP).

        Structure of TCP header:
            Octets          Bits          Name                      Discription
              0              0          tcp.srcport             Source Port
              2              16         tcp.dstport             Destination Port
              4              32         tcp.seq                 Sequence Number
              8              64         tcp.ack                 Acknowledgment Number (if ACK set)
              12             96         tcp.hdr_len             Data Offset
              13             100        tcp.flags.str           N/A
              12             100        tcp.flags.res           Reserved (must be zero)
              12             103        tcp.flags.ns            ECN Concealment Protection (NS)
              13             104        tcp.flags.cwr           Congestion Window Reduced (CWR)
              13             105        tcp.flags.ecn           ECN-Echo (ECE)
              13             106        tcp.flags.urg           Urgent (URG)
              13             107        tcp.flags.ack           Acknowledgment (ACK)
              13             108        tcp.flags.push          Push Function (PSH)
              13             109        tcp.flags.reset         Reset Connection (RST)
              13             110        tcp.flags.syn           Synchronize Sequence Numbers (SYN)
              13             111        tcp.flags.fin           Last Packet from Sender (FIN)
              14             112        tcp.window_size         Size of Receive Window
              16             128        tcp.checksum            Checksum
              18             144        tcp.urgent_pointer      Urgent Pointer (if URG set)
              20             160        tcp.options             TCP Options (if data offset > 5)

        """
        _srcp = self.read_unpack(self._file, 2, _bige=True)
        _dstp = self.read_unpack(self._file, 2, _bige=True)
        _seqn = self.read_unpack(self._file, 4, _bige=True)
        _ackn = self.read_unpack(self._file, 4, _bige=True)
        _lenf = self.read_binary(self._file, 1)
        _flag = self.read_binary(self._file, 1)
        _wins = self.read_unpack(self._file, 2, _bige=True)
        _csum = self._file.read(2)
        _urgp = self.read_unpack(self._file, 2, _bige=True)

        tcp = dict(
            srcport = _srcp,
            dstport = _dstp,
            seq = _seqn,
            ack = _ackn,
            hdr_len = int(_lenf[:4], base=2) * 4,
            flags = dict(
                res = b'\x00\x00\x00',
                ns = True if int(_lenf[7]) else False,
                cwr = True if int(_flag[0]) else False,
                ecn = True if int(_flag[1]) else False,
                urg = True if int(_flag[2]) else False,
                ack = True if int(_flag[3]) else False,
                push = True if int(_flag[4]) else False,
                reset = True if int(_flag[5]) else False,
                syn = True if int(_flag[6]) else False,
                fin = True if int(_flag[7]) else False,
            ),
            window_size = _wins,
            checksum = _csum,
            urgent_pointer = _urgp,
        )

        _optl = tcp['hdr_len'] - 20
        if _optl:
            tcp['options'] = self._read_tcp_options(_optl)

        return tcp

    def _read_tcp_options(self, _optl):
        return self._file.read(_optl)

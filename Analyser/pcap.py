#!/usr/bin/python3
# -*- coding: utf-8 -*-

import datetime
import struct
import textwrap

# Reader for PCAP files
# Extract parametres from a PCAP file

from plist import Writer

# Link laywer protocols
LINKTYPE = {
    0: 'Null',
    1: 'Eithernet',
}


# Internet laywer protocols
INTERNET = {
    '0800': 'IPv4',
    '0806': 'ARP',
    '8137': 'IPX',
    '86dd': 'IPv6',
}


# Tranport laywer protocols
TP_PROTO = {
    1:   'ICMP',
    2:   'IGMP',
    6:   'TCP',
    17:  'UDP',
    41:  'ENCAP',
    89:  'OSPF',
    132: 'SCTP',
}


class Reader:
    """Reader for PCAP files.

    Properties:
        _frame -- int, frame number
        _plist -- object, temperory output writer

        _dlink -- str, data link layer protocol
        _netwk -- str, network layer protocol
        _trans -- str, transport layer protocol
        _applc -- str, application layer protocol

        _dleng -- int, length of data that ip contains
        _tzone -- int, timezone offset in seconds

    Usage:
        reader = Reader('sample.pcap')

    """

    def __init__(self, fname=None):
        """Initialise PCAP Reader.

        Keyword arguemnts:
            fname -- str, file name to be read; if file not exist, raise error

        """
        self._frame = 1                     # frame number
        self._plist = Writer('tmp.plist')   # temp PLIST file
        with open(fname, 'rb') as _file:
            self.read_header(_file)     # read PCAP global header
            self.read_frames(_file)     # read frames

    def _read_unpack(self, _file, _size=1, *, _sign=False, _bige=False):
        """Read bytes and unpack for integers.

        Keyword arguemnts:
            _file -- file object
            _size -- int, buffer size (default is 1)
            _sign -- bool, signed flag (default is False)
                     <keyword> True / False
            _bige -- bool, big-endian flag (default is False)
                     <keyword> True / False

        """
        _endian = '>' if _bige else '<'
        if _size == 4:      _format = 'i' if _sign else 'I'     # unpack to 4-byte integer (int)
        elif _size == 2:    _format = 'h' if _sign else 'H'     # unpack to 2-byte integer (short)
        elif _size == 1:    _format = 'b' if _sign else 'B'     # unpack to 1-byte integer (char)
        else:               _format = None                      # do not unpack

        if _format is None:
            buf = self._file.read(_size)
        else:
            try:
                fmt = '{endian}{format}'.format(endian=_endian, format=_format)
                buf = struct.unpack(fmt, _file.read(_size))[0]
            except struct.error:
                return None
        return buf

    def _read_binary(self, _file, _size=1):
        _bins = ''
        for tmpctr in range(_size):
            _byte = _file.read(1)
            _bins += bin(ord(_byte))[2:].zfill(8)
        return _bins

    def read_header(self, _file):
        """Read global header of *.pcap file.

        Keyword arguments:
            _file -- file object

        Structure of global header (C):
            typedef struct pcap_hdr_s {
            guint32 magic_number;   /* magic number */
            guint16 version_major;  /* major version number */
            guint16 version_minor;  /* minor version number */
            gint32  thiszone;       /* GMT to local correction */
            guint32 sigfigs;        /* accuracy of timestamps */
            guint32 snaplen;        /* max length of captured packets, in octets */
            guint32 network;        /* data link type */
            } pcap_hdr_t;

        """
        _temp = _file.read(4)
        if _temp != b'\xd4\xc3\xb2\xa1':
            raise SyntaxError('Unsupported file format.')

        _magn = _temp
        _vmaj = self._read_unpack(_file, 2)
        _vmin = self._read_unpack(_file, 2)
        _zone = self._read_unpack(_file, 4, _sign=True)
        _acts = self._read_unpack(_file, 4)
        _slen = self._read_unpack(_file, 4)
        _type = self._read_unpack(_file, 4)

        header = dict(
            magic_number = _magn,
            version_major = _vmaj,
            version_minor = _vmin,
            thiszone = _zone,
            sigfigs = _acts,
            snaplen = _slen,
            network = LINKTYPE[_type],
        )

        self._tzone = _zone
        self._dlink = header['network']
        self._plist(header, _name='Global Header')

    def read_frames(self, _file):
        """Read each block after global header.

        Keyword arguments:
            _file -- file object

        Structure of record/package header (C):
            typedef struct pcaprec_hdr_s {
            guint32 ts_sec;     /* timestamp seconds */
            guint32 ts_usec;    /* timestamp microseconds */
            guint32 incl_len;   /* number of octets of packet saved in file */
            guint32 orig_len;   /* actual length of packet */
            } pcaprec_hdr_t;

        """
        while True:
            _temp = self._read_unpack(_file, 4)
            if _temp is None:   break

            _time = datetime.datetime.fromtimestamp(_temp)
            _tsss = _temp
            _tsus = self._read_unpack(_file, 4)
            _ilen = self._read_unpack(_file, 4)
            _olen = self._read_unpack(_file, 4)

            frame = dict(
                time = _time,
                time_epoch = '{ts_sec}.{ts_usec} seconds'.format(ts_sec=_tsss, ts_usec=_tsus),
                number = self._frame,
                len = _ilen,
                cap_len = _olen,
            )

            frame[self._dlink] = self.read_link(_file)
            frame['protocols'] = '{link}:{internet}:{transport}'.format(
                link=self._dlink, internet=self._netwk, transport=self._trans
            )

            _fnum = 'Frame {fnum}'.format(fnum=self._frame)

            self._frame += 1
            self._plist(frame, _name=_fnum)

    def read_link(self, _file):
        if self._dlink == 'Eithernet':
            return self._read_ethernet(_file)
        else:
            raise NotImplementedError

    def read_internet(self, _file):
        if self._netwk == 'IPv4':
            return self._read_ipv4(_file)
        else:
            raise NotImplementedError

    def read_trans(self, _file):
        if self._trans == 'TCP':
            return self._read_tcp(_file)
        elif self._trans == 'UDP':
            return self._read_udp(_file)
        else:
            raise NotImplementedError

    def _read_ethernet(self, _file):
        """Read Ethernet Protocol.

        Keyword arguments:
        _file -- file object

        Structure of Ethernet Protocol header:
            Octets          Bits          Name                Discription
              0              0          eth.dst           Destination MAC Address
              1              8          eth.src           Source MAC Address
              2              16         eth.type          Protocol (Internet Layer)

        """
        _dstm = self._read_mac_addr(_file)
        _srcm = self._read_mac_addr(_file)
        _type = self._read_eth_type(_file)

        ethernet = dict(
            dst = _dstm,
            src = _srcm,
            type = _type,
        )

        self._netwk = ethernet['type']
        ethernet[self._netwk] = self.read_internet(_file)
        return ethernet

    def _read_ipv4(self, _file):
        """Read Internet Protocol version 4 (IPv4).

        Keyword arguments:
        _file -- file object

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
        _vihl = _file.read(1).hex()
        _dscp = self._read_binary(_file, 1)
        _tlen = self._read_unpack(_file, 2, _bige=True)
        _iden = self._read_unpack(_file, 2, _bige=True)
        _frag = self._read_binary(_file, 2)
        _ttol = self._read_unpack(_file, 1, _bige=True)
        _prot = self._read_ip_proto(_file)
        _csum = _file.read(2)
        _srca = self._read_ip_addr(_file)
        _dsta = self._read_ip_addr(_file)

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

        self._dleng = ip['len'] - ip['hdr_len']
        self._trans = ip['proto']

        ip['opt'] = _file.read(ip['hdr_len'] - 20)
        ip[self._trans] = self.read_trans(_file)
        return ip

    def _read_tcp(self, _file):
        """Read Transmission Control Protocol (TCP).

        Keyword arguments:
        _file -- file object

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
        _srcp = self._read_unpack(_file, 2, _bige=True)
        _dstp = self._read_unpack(_file, 2, _bige=True)
        _seqn = self._read_unpack(_file, 4, _bige=True)
        _ackn = self._read_unpack(_file, 4, _bige=True)
        _lenf = self._read_binary(_file, 1)
        _flag = self._read_binary(_file, 1)
        _wins = self._read_unpack(_file, 2, _bige=True)
        _csum = _file.read(2)
        _urgp = self._read_unpack(_file, 2, _bige=True)

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

        self._dleng -= tcp['hdr_len']
        tcp['options'] = _file.read(tcp['hdr_len'] - 20)
        tcp['Application'] = _file.read(self._dleng)
        return tcp

    def _read_udp(self, _file):
        """Read User Datagram Protocol (UDP).

        Keyword arguments:
        _file -- file object

        Structure of UDP header:
            Octets          Bits          Name                      Discription
              0              0          udp.srcport             Source Port
              2              16         udp.dstport             Destination Port
              4              32         udp.len                 Length
              6              48         udp.checksum            Checksum

        """
        _srcp = self._read_unpack(_file, 2, _bige=True)
        _dstp = self._read_unpack(_file, 2, _bige=True)
        _tlen = self._read_unpack(_file, 2, _bige=True)
        _csum = self._read_unpack(_file, 2, _bige=True)

        udp = dict(
            srcport = _srcp,
            dstport = _dstp,
            len = _tlen,
            checksum = _csum,
        )

        self._dleng -= 16
        udp['Application'] = _file.read(self._dleng)
        return udp

    def _read_mac_addr(self, _file):
        _byte = _file.read(6)
        _addr = ':'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr

    def _read_eth_type(self, _file):
        _byte = _file.read(2).hex()
        _netwk = INTERNET.get(_byte)
        return _netwk

    def _read_ip_addr(self, _file):
        _byte = _file.read(4)
        _addr = '.'.join([str(B) for B in _byte])
        return _addr

    def _read_ip_proto(self, _file):
        _byte = struct.unpack('>B', _file.read(1))[0]
        _trans = TP_PROTO.get(_byte)
        return _trans


if __name__ == '__main__':
    a = Reader('a.pcap')

#!/usr/bin/python3
# -*- coding: utf-8 -*-


# TODO: Implements IPv4 option list extractor.


import collections
import datetime


# Internet Protocol version 4
# Analyser for IPv4 header


from jspcap.utilities import Info, ProtoChain
from jspcap.protocols.internet.ip import IP


__all__ = ['IPv4']


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

# QS Functions
QS_FUNC = {
    1:  'Quick-Start Request',
    2:  'Report of Approved Rate',
}


"""IPv4 Option Utility Table

T | F
    bool, short of True / False

opt_class
    dict, option classes

IPv4_OPT
    dict, IPv4 option dict.
    Value is a tuple which contains:
        |--> bool, if length greater than 1
        |       |--> T - True
        |       |--> F - False
        |--> str, description string, also attribute name
        |--> (optional) int, process that data bytes need (when length greater than 2)
                |--> 0: do nothing
                |--> 1: unpack according to size
                |--> 2: unpack route data options then add to dict
                |--> 3: unpack Quick-Start then add to dict
                |--> 4: unpack Time Stamp then add to dict
                |--> 5: unpack Traceroute then add to dict
                |--> 6: unpack (Extended) Security then add tot dict
                |--> 7: unpack Router Alert then add to dict

"""

T = True
F = False

opt_class = {
    0:  'control',
    1:  'reserved for future use',
    2:  'debugging and measurement',
    3:  'reserved for future use',
}

process_opt = {
    0:  lambda self, size, kind: self._read_mode_donone(size, kind),    # do nothing
    1:  lambda self, size, kind: self._read_mode_unpack(size, kind),    # unpack according to size
    2:  lambda self, size, kind: self._read_mode_route(size, kind),     # route data
    3:  lambda self, size, kind: self._read_mode_qs(size, kind),        # Quick-Start
    4:  lambda self, size, kind: self._read_mode_ts(size, kind),        # Time Stamp
    5:  lambda self, size, kind: self._read_mode_tr(size, kind),        # Traceroute
    6:  lambda self, size, kind: self._read_mode_sec(size, kind),       # (Extended) Security
    7:  lambda self, size, kind: self._read_mode_rsralt(size, kind),    # Router Alert
}

IPv4_OPT = {                        #   copy  class  number  kind  length  process          name
    0:  (F, 'eool'),                #     0     0       0      0      -       -     [RFC 791] End of Option List
    1:  (F, 'nop'),                 #     0     0       1      1      -       -     [RFC 791] No-Operation
    7:  (T, 'rr', 2),               #     0     0       7      7      N       2     [RFC 791] Record Route
   11:  (T, 'mtup', 1),             #     0     0      11     11      4       1     [RFC 1063][RFC 1191] MTU Probe
   12:  (T, 'mtur', 1),             #     0     0      12     12      4       1     [RFC 1063][RFC 1191] MTU Reply
   25:  (T, 'qs', 3),               #     0     0      25     25      8       3     [RFC 4782] Quick-Start
   68:  (T, 'ts', 4),               #     0     2       4     68      N       4     [RFC 791] Time Stamp
   82:  (T, 'tr', 5),               #     0     2      18     82      N       5     [RFC 1393][RFC 6814] Traceroute
  130:  (T, 'sec', 6),              #     1     0       2    130      N       6     [RFC 1108] Security
  131:  (T, 'lsr', 2),              #     1     0       3    131      N       2     [RFC 791] Loose Source Route
  133:  (T, 'esec', 6),             #     1     0       5    133      N       6     [RFC 1108][RFC 6814] Extended Security
  136:  (T, 'sid', 1),              #     1     0       8    136      4       1     [RFC 791][RFC 6814] Stream ID
  137:  (T, 'ssr', 2),              #     1     0       9    137      N       2     [RFC 791] Strict Source Route
  148:  (T, 'rtralt', 7),           #     1     0      20    148      4       7     [RFC 2113] Router Alert
}


class IPv4(IP):
    """This class implements Internet Protocol version 4.

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
        * read_ipv4 -- read Internet Protocol version 4 (IPv4)

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
        * _read_ipv4_addr -- read IPv4 address
        * _read_ipv4_options -- read IPv4 option list

    """
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
    # Methods.
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
        _srca = self._read_ipv4_addr()
        _dsta = self._read_ipv4_addr()

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
            options = self._read_ipv4_options(_optl)
            ipv4['opt'] = options[0]    # tuple of option acronyms
            ipv4.update(options[1])     # merge option info to buffer

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

        return self._decode_next_layer(ipv4, _prot, raw_len)

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

    def _read_ipv4_addr(self):
        """Read IP address."""
        _byte = self._read_fileng(4)
        _addr = '.'.join([str(_) for _ in _byte])
        return _addr

    def _read_opt_type(self, kind):
        """Read option type field.

        Keyword arguments:
            kind -- int, option kind value

        Structure of option type field [RFC 791]:

            Octets          Bits          Name                       Discription
              0              0          ip.opt.type.copy         Copied Flag (0/1)
              0              1          ip.opt.type.class        Option Class (0-3)
              0              3          ip.opt.type.number       Option Number

        """
        bin_ = bin(kind)[2:].zfill(8)
        type_ = {
            'copy' : bool(int(bin_[0], base=2)),
            'class' : opt_class.get(int(bin_[1:3], base=2)),
            'number' : int(bin_[3:], base=2),
        }
        return type_

    def _read_ipv4_options(self, size=None):
        """Read IPv4 option list.

        Keyword arguments:
            * size -- int, buffer size

        """
        counter = 0         # length of read option list
        optkind = tuple()   # option kind list
        options = dict()    # dict of option data

        while counter < size:
            # get option kind
            kind = self._read_unpack(1)

            # fetch corresponding option tuple
            opts = IPv4_OPT.get(kind)
            if opts is None:
                len_ = size - counter
                counter = size
                options['Unknown'] = self._read_fileng(len_)
                break

            # extract option
            dscp = opts[1]
            if opts[0]:
                byte = self._read_unpack(1)
                if byte:    # check option process mode
                    data = process_opt[opts[2]](self, byte, kind)
                else:       # permission options (length is 2)
                    data = dict(
                        kind = kind,                        # option kind
                        type = self._read_opt_type(kind),   # option type info
                        length = 2,                         # option length
                        flag = True,                        # permission flag
                    )
            else:           # 1-bytes options
                byte = 1
                data = dict(
                    kind = kind,                        # option kind
                    type = self._read_opt_type(kind),   # option type info
                    length = 1,                         # option length
                )

            # record option data
            counter += byte
            if dscp in optkind:
                if isinstance(options[dscp], tuple):
                    options[dscp] += (Info(data),)
                else:
                    options[dscp] = (Info(options[dscp]), Info(data))
            else:
                optkind += (dscp,)
                options[dscp] = data

            # break when eol triggered
            if not kind:    break

        # get padding
        if counter < size:
            len_ = size - counter
            options['padding'] = self._read_fileng(len_)

        return optkind, options

    def _read_mode_donone(self, size, kind):
        """Read options request no process.

        Keyword arguemnts:
            size - int, length of option
            kind - int, option kind value

        Structure of TCP options:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.data                    Kind-specific Data

        """
        data = dict(
            kind = kind,
            length = size,
            data = self._read_fileng(size),
        )
        return data

    def _read_mode_unpack(self, size, kind):
        """Read options request unpack process.

        Keyword arguemnts:
            size - int, length of option
            kind - int, option kind value

        Structure of TCP options:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.data                    Kind-specific Data

        """
        data = dict(
            kind = kind,
            length = size,
            data = self._read_unpack(size),
        )
        return data

    def _read_mode_route(self, size, kind):
        """Read options with route data.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 7/131/137 (RR/LSR/SSR)

        Structure of these options:
            * [RFC 791] Loose Source Route
                +--------+--------+--------+---------//--------+
                |10000011| length | pointer|     route data    |
                +--------+--------+--------+---------//--------+
            * [RFC 791] Strict Source Route
                +--------+--------+--------+---------//--------+
                |10001001| length | pointer|     route data    |
                +--------+--------+--------+---------//--------+
            * [RFC 791] Record Route
                +--------+--------+--------+---------//--------+
                |00000111| length | pointer|     route data    |
                +--------+--------+--------+---------//--------+

           Octets          Bits          Name                       Discription
             0              0          ip.opt.kind              Kind (7/131/137)
             0              0          ip.opt.type.copy         Copied Flag (0)
             0              1          ip.opt.type.class        Option Class (0/1)
             0              3          ip.opt.type.number       Option Number (3/7/9)
             1              8          ip.opt.length            Length
             2              16         ip.opt.pointer           Pointer (≥4)
             3              24         ip.opt.data              Route Data

        """
        _rlst = list()
        _rrip = list()
        _rpad = list()

        _type = self._read_opt_type(kind)
        _rptr = self._read_unpack(1)

        _rlst.append(_rptr)
        _rrec = _rptr + 4
        while _rptr <= size:
            _rrec
            _rrip = self._read_ipv4_addr()
            _rpad = self._read_fileng(_rptr - 4)


        _resv = self._read_fileng(_rptr - 4)
        for _ in range((size - 3 - _rptr) // 4):
            _rrip.append(self._read_ipv4_addr())
        _pads = self._read_fileng((size - 3 - _rptr) % 4)

        data = dict(
            kind = kind,
            type = _type,
            length = size,
            pointer = _rptr,
            reserved = _resv,
            data = tuple(_rrip) if len(_rrip) > 1 else _rrip[0],
            padding = _pads,
        )

        return data

    def _read_mode_qs(self, size, kind):
        """Read Quick Start option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 25 (QS)

        Structure of Quick-Start (QS) option [RFC 4782]:
            * A Quick-Start Request.
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |   Option      |  Length=8     | Func. | Rate  |   QS TTL      |
               |               |               | 0000  |Request|               |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                        QS Nonce                           | R |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            * Report of Approved Rate.
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |   Option      |  Length=8     | Func. | Rate  |   Not Used    |
               |               |               | 1000  | Report|               |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                        QS Nonce                           | R |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Octets          Bits          Name                       Discription
             0              0          ip.qs.kind               Kind (25)
             0              0          ip.qs.type.copy          Copied Flag (0)
             0              1          ip.qs.type.class         Option Class (0)
             0              3          ip.qs.type.number        Option Number (25)
             1              8          ip.qs.length             Length (8)
             2              16         ip.qs.func               Function (0/8)
             2              20         ip.qs.rate               Rate Request / Report (in Kbps)
             3              24         ip.qs.ttl                QS TTL / None
             4              32         ip.qs.nounce             QS Nounce
             7              62         ip.qs.resv               Reserved (\x00\x00)

        """
        _type = self._read_opt_type(kind)
        _fcrr = self._read_binary(1)
        _func = int(_fcrr[:4], base=2)
        _rate = int(_fcrr[4:], base=2)
        _ttlv = self._read_unpack(1)
        _nonr = self._read_binary(4)
        _qsnn = int(_nonr[:30], base=2)

        data = dict(
            kind = kind,
            type = _type,
            length = size,
            func = QS_FUNC.get(_func),
            rate = 40000 * (2 ** _rate) / 1000,
            ttl = None if func else _rate,
            nounce = _qsnn,
            resv = '\x00\x00',
        )

        return data

    def _read_mode_ts(self, size, kind):
        """Read Time Stamp option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 68 (TS)

        Structure of Timestamp (TS) option [RFC 791]:
            +--------+--------+--------+--------+
            |01000100| length | pointer|oflw|flg|
            +--------+--------+--------+--------+
            |         internet address          |
            +--------+--------+--------+--------+
            |             timestamp             |
            +--------+--------+--------+--------+
            |                 .                 |
                              .
                              .

           Octets          Bits          Name                       Discription
             0              0          ip.ts.kind               Kind (25)
             0              0          ip.ts.type.copy          Copied Flag (0)
             0              1          ip.ts.type.class         Option Class (0)
             0              3          ip.ts.type.number        Option Number (25)
             1              8          ip.ts.length             Length (≤40)
             2              16         ip.ts.pointer            Pointer (≥5)
             3              24         ip.ts.overflow           Overflow Octets
             3              28         ip.ts.flag               Flag
             4              32         ip.ts.ip                 Internet Address
             8              64         ip.ts.timestamp          Timestamp

        """
        _tptr = self._read_unpack(1)
        _oflg = self._read_binary(1)
        _oflw = int(_oflg[:4], base=2)
        _flag = int(_flag[4:], base=2)
        _ipad = self._read_ipv4_addr()
        _time = self._read_unpack(4, lilendian=True)

        data = dict(

        )

        return data

    def _read_mode_tr(self, size, kind):
        return self._read_fileng(size)

    def _read_mode_sec(self, size, kind):
        return self._read_fileng(size)

    def _read_mode_rsralt(self, size, kind):
        return self._read_fileng(size)

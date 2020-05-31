# -*- coding: utf-8 -*-
"""internet protocol version 4

:mod:`pcapkit.protocols.internet.ipv4` contains
:class:`~pcapkit.protocols.internet.ipv4.IPv4` only,
which implements extractor for Internet Protocol
version 4 (IPv4) [*]_, whose structure is described
as below:

======= ========= ====================== =============================================
Octets      Bits        Name                    Description
======= ========= ====================== =============================================
  0           0   ``ip.version``              Version (``4``)
  0           4   ``ip.hdr_len``              Internal Header Length (IHL)
  1           8   ``ip.dsfield.dscp``         Differentiated Services Code Point (DSCP)
  1          14   ``ip.dsfield.ecn``          Explicit Congestion Notification (ECN)
  2          16   ``ip.len``                  Total Length
  4          32   ``ip.id``                   Identification
  6          48                               Reserved Bit (must be ``\\x00``)
  6          49   ``ip.flags.df``             Don't Fragment (DF)
  6          50   ``ip.flags.mf``             More Fragments (MF)
  6          51   ``ip.frag_offset``          Fragment Offset
  8          64   ``ip.ttl``                  Time To Live (TTL)
  9          72   ``ip.proto``                Protocol (Transport Layer)
  10         80   ``ip.checksum``             Header Checksum
  12         96   ``ip.src``                  Source IP Address
  16        128   ``ip.dst``                  Destination IP Address
  20        160   ``ip.options``              IP Options (if IHL > ``5``)
======= ========= ====================== =============================================

.. [*] https://en.wikipedia.org/wiki/IPv4

"""
import datetime
import ipaddress

from pcapkit.const.ipv4.classification_level import ClassificationLevel as _CLASSIFICATION_LEVEL
from pcapkit.const.ipv4.option_class import OptionClass as opt_class
from pcapkit.const.ipv4.option_number import OptionNumber as OPT_TYPE
from pcapkit.const.ipv4.protection_authority import ProtectionAuthority as _PROTECTION_AUTHORITY
from pcapkit.const.ipv4.qs_function import QSFunction as QS_FUNC
from pcapkit.const.ipv4.router_alert import RouterAlert as _ROUTER_ALERT
from pcapkit.const.reg.transtype import TransType
from pcapkit.const.ipv4.tos_del import ToSDelay as TOS_DEL
from pcapkit.const.ipv4.tos_ecn import ToSECN as TOS_ECN
from pcapkit.const.ipv4.tos_pre import ToSPrecedence as TOS_PRE
from pcapkit.const.ipv4.tos_rel import ToSReliability as TOS_REL
from pcapkit.const.ipv4.tos_thr import ToSThroughput as TOS_THR
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.ip import IP
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['IPv4']

T = True
F = False

# pylint: disable=protected-access
process_opt = {
    0: lambda self, size, kind: self._read_mode_donone(size, kind),    # do nothing
    1: lambda self, size, kind: self._read_mode_unpack(size, kind),    # unpack according to size
    2: lambda self, size, kind: self._read_mode_route(size, kind),     # route data
    3: lambda self, size, kind: self._read_mode_qs(size, kind),        # Quick-Start
    4: lambda self, size, kind: self._read_mode_ts(size, kind),        # Time Stamp
    5: lambda self, size, kind: self._read_mode_tr(size, kind),        # Traceroute
    6: lambda self, size, kind: self._read_mode_sec(size, kind),       # (Extended) Security
    7: lambda self, size, kind: self._read_mode_rsralt(size, kind),    # Router Alert
}

IPv4_OPT = {                 # # copy  class  number  kind  length  process          name
    0:    (F, 'eool'),       # #   0     0       0      0      -       -     [RFC 791] End of Option List
    1:    (F, 'nop'),        # #   0     0       1      1      -       -     [RFC 791] No-Operation
    7:    (T, 'rr', 2),      # #   0     0       7      7      N       2     [RFC 791] Record Route
    11:   (T, 'mtup', 1),    # #   0     0      11     11      4       1     [RFC 1063][RFC 1191] MTU Probe
    12:   (T, 'mtur', 1),    # #   0     0      12     12      4       1     [RFC 1063][RFC 1191] MTU Reply
    25:   (T, 'qs', 3),      # #   0     0      25     25      8       3     [RFC 4782] Quick-Start
    68:   (T, 'ts', 4),      # #   0     2       4     68      N       4     [RFC 791] Time Stamp
    82:   (T, 'tr', 5),      # #   0     2      18     82      N       5     [RFC 1393][RFC 6814] Traceroute
    130:  (T, 'sec', 6),     # #   1     0       2    130      N       6     [RFC 1108] Security
    131:  (T, 'lsr', 2),     # #   1     0       3    131      N       2     [RFC 791] Loose Source Route
    133:  (T, 'esec', 6),    # #   1     0       5    133      N       6     [RFC 1108] Extended Security
    136:  (T, 'sid', 1),     # #   1     0       8    136      4       1     [RFC 791][RFC 6814] Stream ID
    137:  (T, 'ssr', 2),     # #   1     0       9    137      N       2     [RFC 791] Strict Source Route
    145:  (T, 'eip', 0),     # #   1     0      17    145      N       0     [RFC 1385][RFC 6814] Ext. Inet. Protocol
    148:  (T, 'rtralt', 7),  # #   1     0      20    148      4       7     [RFC 2113] Router Alert
}
"""IPv4 Option Utility Table

T | F
    bool, short of True / False

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


class IPv4(IP):
    """This class implements Internet Protocol version 4."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: Literal['Internet Protocol version 4']
        """
        return 'Internet Protocol version 4'

    @property
    def length(self):
        """Header length of corresponding protocol.

        :rtype: int
        """
        return self._info.hdr_len  # pylint: disable=E1101

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.proto  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Internet Protocol version 4 (IPv4).

        Structure of IPv4 header [:rfc:`791`]::

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

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPv4: Parsed packet data.

        """
        if length is None:
            length = len(self)

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
            version=int(_vihl[0]),
            hdr_len=int(_vihl[1], base=16) * 4,
            dsfield=dict(
                dscp={
                    'pre': TOS_PRE.get(int(_dscp[:3], base=2)),
                    'del': TOS_DEL.get(int(_dscp[3], base=2)),
                    'thr': TOS_THR.get(int(_dscp[4], base=2)),
                    'rel': TOS_REL.get(int(_dscp[5], base=2)),
                },
                ecn=TOS_ECN.get(int(_dscp[-2:], base=2)),
            ),
            len=_tlen,
            id=_iden,
            flags=dict(
                df=bool(int(_frag[1])),
                mf=bool(int(_frag[2])),
            ),
            frag_offset=int(_frag[3:], base=2) * 8,
            ttl=_ttol,
            proto=_prot,
            checksum=_csum,
            src=_srca,
            dst=_dsta,
        )

        _optl = ipv4['hdr_len'] - 20
        if _optl:
            options = self._read_ipv4_options(_optl)
            ipv4['opt'] = options[0]    # tuple of option acronyms
            ipv4.update(options[1])     # merge option info to buffer
            # ipv4['opt'] = self._read_fileng(_optl) or None

        hdr_len = ipv4['hdr_len']
        raw_len = ipv4['len'] - hdr_len
        ipv4['packet'] = self._read_packet(header=hdr_len, payload=raw_len)

        return self._decode_next_layer(ipv4, _prot, raw_len)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
           Literal['IPv4']: Index ID of the protocol.

        """
        return cls.__name__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[20]
        """
        return 20

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(4)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ipv4_addr(self):
        """Read IP address.

        Returns:
            ipaddress.IPv4Address: Parsed IP address.

        """
        # _byte = self._read_fileng(4)
        # _addr = '.'.join([str(_) for _ in _byte])
        # return _addr
        return ipaddress.ip_address(self._read_fileng(4))

    def _read_opt_type(self, kind):  # pylint: disable=no-self-use
        """Read option type field.

        Arguments:
            kind (int): option kind value

        Returns:
            DataType_IPv4_Option_Type: extracted IPv4 option

        """
        bin_ = bin(kind)[2:].zfill(8)

        type_ = {
            'copy': bool(int(bin_[0], base=2)),
            'class': opt_class.get(int(bin_[1:3], base=2)),
            'number': int(bin_[3:], base=2),
        }

        return type_

    def _read_ipv4_options(self, size=None):
        """Read IPv4 option list.

        Arguments:
            size (Optional[int]): buffer size

        Returns:
            Tuple[Tuple[pcapkit.const.ipv4.option_number.OptionNumber],
            Dict[str, Union[DataType_Opt, Tuple[DataType_Opt]]]]: IPv4
            option list and extracted IPv4 options

        """
        counter = 0         # length of read option list
        optkind = list()    # option kind list
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
            dscp = OPT_TYPE.get(kind)
            desc = dscp.name
            if opts[0]:
                byte = self._read_unpack(1)
                if byte:    # check option process mode
                    data = process_opt[opts[2]](self, byte, kind)
                else:       # permission options (length is 2)
                    data = dict(
                        kind=kind,                          # option kind
                        type=self._read_opt_type(kind),     # option type info
                        length=2,                           # option length
                        flag=True,                          # permission flag
                    )
            else:           # 1-byte options
                byte = 1

                data = dict(
                    kind=kind,                          # option kind
                    type=self._read_opt_type(kind),     # option type info
                    length=1,                           # option length
                )

            # record option data
            counter += byte
            if dscp in optkind:
                if isinstance(options[desc], tuple):
                    options[desc] += (Info(data),)
                else:
                    options[desc] = (Info(options[desc]), Info(data))
            else:
                optkind.append(dscp)
                options[desc] = data

            # break when eol triggered
            if not kind:
                break

        # get padding
        if counter < size:
            len_ = size - counter
            self._read_binary(len_)

        return tuple(optkind), options

    def _read_mode_donone(self, size, kind):
        """Read options require no process.

        Arguments:
            size (int): length of option
            kind (int): option kind value

        Returns:
            DataType_Opt_Do_None: extracted option

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            data=self._read_fileng(size),
        )

        return data

    def _read_mode_unpack(self, size, kind):
        """Read options require unpack process.

        Arguments:
            size (int): length of option
            kind (int): option kind value

        Returns:
            DataType_Opt_Unpack: extracted option

        Raises:
            ProtocolError: If ``size`` is **LESS THAN** ``3``.

        """
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            data=self._read_unpack(size),
        )

        return data

    def _read_mode_route(self, size, kind):
        """Read options with route data.

        Structure of these options [:rfc:`791`]:

        * Loose Source Route

          .. code:: text

             +--------+--------+--------+---------//--------+
             |10000011| length | pointer|     route data    |
             +--------+--------+--------+---------//--------+

        * Strict Source Route

          .. code:: text

             +--------+--------+--------+---------//--------+
             |10001001| length | pointer|     route data    |
             +--------+--------+--------+---------//--------+

        * Record Route

          .. code:: text

             +--------+--------+--------+---------//--------+
             |00000111| length | pointer|     route data    |
             +--------+--------+--------+---------//--------+

        Arguments:
            size (int): length of option
            kind (Literal[7, 131, 137]): option kind value (RR/LSR/SSR)

        Returns:
            DataType_Opt_Route_Data: extracted option with route data

        Raises:
            ProtocolError: If the option is malformed.

        """
        if size < 3 or (size - 3) % 4 != 0:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _rptr = self._read_unpack(1)
        if _rptr < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            pointer=_rptr,
        )

        counter = 4
        address = list()
        endpoint = min(_rptr, size)
        while counter < endpoint:
            counter += 4
            address.append(self._read_ipv4_addr())
        data['data'] = tuple(address) or None

        return data

    def _read_mode_qs(self, size, kind):
        """Read Quick Start option.

        Structure of Quick-Start (QS) option [:rfc:`4782`]:

        * A Quick-Start Request

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=8     | Func. | Rate  |   QS TTL      |
             |               |               | 0000  |Request|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        * Report of Approved Rate

          .. code:: text

              0                   1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |   Option      |  Length=8     | Func. | Rate  |   Not Used    |
             |               |               | 1000  | Report|               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                        QS Nonce                           | R |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            size (int): length of option
            kind (Literal[25]): option kind value (QS)

        Returns:
            DataType_Opt_QuickStart: extracted Quick Start option

        Raises:
            ProtocolError: If the option is malformed.

        """
        if size != 8:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _type = self._read_opt_type(kind)
        _fcrr = self._read_binary(1)
        _func = int(_fcrr[:4], base=2)
        _rate = int(_fcrr[4:], base=2)
        _ttlv = self._read_unpack(1)
        _nonr = self._read_binary(4)
        _qsnn = int(_nonr[:30], base=2)

        if _func not in (0, 8):
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = dict(
            kind=kind,
            type=_type,
            length=size,
            func=QS_FUNC.get(_func),
            rate=40000 * (2 ** _rate) / 1000,
            ttl=None if _func else _rate,
            nounce=_qsnn,
        )

        return data

    def _read_mode_ts(self, size, kind):
        """Read Time Stamp option.

        Structure of Timestamp (TS) option [:rfc:`791`]::

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

        Arguments:
            size (int): length of option
            kind (Literal[68]): option kind value (TS)

        Returns:
            DataType_Opt_TimeStamp: extracted Time Stamp option

        Raises:
            ProtocolError: If the option is malformed.

        """
        if size > 40 or size < 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _tptr = self._read_unpack(1)
        _oflg = self._read_binary(1)
        _oflw = int(_oflg[:4], base=2)
        _flag = int(_oflg[4:], base=2)

        if _tptr < 5:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            pointer=_tptr,
            overflow=_oflw,
            flag=_flag,
        )

        endpoint = min(_tptr, size)
        if _flag == 0:
            if (size - 4) % 4 != 0:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')
            counter = 5
            timestamp = list()
            while counter < endpoint:
                counter += 4
                time = self._read_unpack(4, lilendian=True)
                timestamp.append(datetime.datetime.fromtimestamp(time))
            data['timestamp'] = timestamp or None
        elif _flag in (1, 3):
            if (size - 4) % 8 != 0:
                raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')
            counter = 5
            ipaddress = list()  # pylint: disable=redefined-outer-name
            timestamp = list()
            while counter < endpoint:
                counter += 8
                ipaddress.append(self._read_ipv4_addr())
                time = self._read_unpack(4, lilendian=True)
                timestamp.append(datetime.datetime.fromtimestamp(time))
            data['ip'] = tuple(ipaddress) or None
            data['timestamp'] = tuple(timestamp) or None
        else:
            data['data'] = self._read_fileng(size - 4) or None

        return data

    def _read_mode_tr(self, size, kind):
        """Read Traceroute option.

        Structure of Traceroute (TR) option [:rfc:`6814`]::

             0               8              16              24
            +-+-+-+-+-+-+-+-+---------------+---------------+---------------+
            |F| C |  Number |    Length     |          ID Number            |
            +-+-+-+-+-+-+-+-+---------------+---------------+---------------+
            |      Outbound Hop Count       |       Return Hop Count        |
            +---------------+---------------+---------------+---------------+
            |                     Originator IP Address                     |
            +---------------+---------------+---------------+---------------+

        Arguments:
            size (int): length of option
            kind (Literal[82]): option kind value (TR)

        Returns:
            DataType_Opt_Traceroute: extracted Traceroute option

        Raises:
            ProtocolError: If ``size`` is **NOT** ``12``.

        """
        if size != 12:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _idnm = self._read_unpack(2)
        _ohcn = self._read_unpack(2)
        _rhcn = self._read_unpack(2)
        _ipad = self._read_ipv4_addr()

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            id=_idnm,
            ohc=_ohcn,
            rhc=_rhcn,
            ip=_ipad,
        )

        return data

    def _read_mode_sec(self, size, kind):
        """Read options with security info.

        Structure of these options [:rfc:`1108`]:

        * Security (SEC)

          .. code:: text

             +------------+------------+------------+-------------//----------+
             |  10000010  |  XXXXXXXX  |  SSSSSSSS  |  AAAAAAA[1]    AAAAAAA0 |
             |            |            |            |         [0]             |
             +------------+------------+------------+-------------//----------+
               TYPE = 130     LENGTH   CLASSIFICATION         PROTECTION
                                            LEVEL              AUTHORITY
                                                                 FLAGS
        * Extended Security (ESEC)

          .. code:: text

             +------------+------------+------------+-------//-------+
             |  10000101  |  000LLLLL  |  AAAAAAAA  |  add sec info  |
             +------------+------------+------------+-------//-------+
              TYPE = 133      LENGTH     ADDITIONAL      ADDITIONAL
                                        SECURITY INFO     SECURITY
                                         FORMAT CODE        INFO

        c

        """
        if size < 3:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _clvl = self._read_unpack(1)

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            level=_CLASSIFICATION_LEVEL.get(_clvl, _clvl),
        )

        if size > 3:
            _list = list()
            for counter in range(3, size):
                _flag = self._read_binary(1)
                if (counter < size - 1 and not int(_flag[7], base=2)) \
                        or (counter == size - 1 and int(_flag[7], base=2)):
                    raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

                _dict = dict()
                for (index, bit) in enumerate(_flag[:5]):
                    _auth = _PROTECTION_AUTHORITY.get(index)
                    _dict[_auth] = bool(int(bit, base=2))
                _list.append(Info(_dict))
            data['flags'] = tuple(_list)

        return data

    def _read_mode_rsralt(self, size, kind):
        """Read Router Alert option.

        Structure of Router Alert (RTRALT) option [:rfc:`2113`]::

            +--------+--------+--------+--------+
            |10010100|00000100|  2 octet value  |
            +--------+--------+--------+--------+

        Arguments:
            size (int): length of option
            kind (Literal[140]): option kind value (RTRALT)

        Returns:
            DataType_Opt_RouterAlert: extracted option with security info

        Raises:
            ProtocolError: If ``size`` is **NOT** ``4``.

        """
        if size != 4:
            raise ProtocolError(f'{self.alias}: [OptNo {kind}] invalid format')

        _code = self._read_unpack(2)

        data = dict(
            kind=kind,
            type=self._read_opt_type(kind),
            length=size,
            alert=_ROUTER_ALERT.get(_code),
            code=_code,
        )

        return data

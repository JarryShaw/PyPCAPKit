# -*- coding: utf-8 -*-
"""transmission control protocol

:mod:`pcapkit.protocols.transport.tcp` contains
:class:`~pcapkit.protocols.transport.tcp.TCP` only,
which implements extractor for Transmission Control
Protocol (TCP) [*]_, whose structure is described as
below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``tcp.srcport``           Source Port
  2          16   ``tcp.dstport``           Destination Port
  4          32   ``tcp.seq``               Sequence Number
  8          64   ``tcp.ack``               Acknowledgement Number (if ACK set)
  12         96   ``tcp.hdr_len``           Data Offset
  12        100                             Reserved (must be ``\\x00``)
  12        103   ``tcp.flags.ns``          ECN Concealment Protection (NS)
  13        104   ``tcp.flags.cwr``         Congestion Window Reduced (CWR)
  13        105   ``tcp.flags.ece``         ECN-Echo (ECE)
  13        106   ``tcp.flags.urg``         Urgent (URG)
  13        107   ``tcp.flags.ack``         Acknowledgement (ACK)
  13        108   ``tcp.flags.psh``         Push Function (PSH)
  13        109   ``tcp.flags.rst``         Reset Connection (RST)
  13        110   ``tcp.flags.syn``         Synchronize Sequence Numbers (SYN)
  13        111   ``tcp.flags.fin``         Last Packet from Sender (FIN)
  14        112   ``tcp.window_size``       Size of Receive Window
  16        128   ``tcp.checksum``          Checksum
  18        144   ``tcp.urgent_pointer``    Urgent Pointer (if URG set)
  20        160   ``tcp.opt``               TCP Options (if data offset > 5)
======= ========= ========================= =======================================

.. [*] https://en.wikipedia.org/wiki/Transmission_Control_Protocol

"""
import datetime
import ipaddress
import struct

from pcapkit.const.reg.transtype import TransType
from pcapkit.const.tcp.checksum import Checksum as chksum_opt
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
from pcapkit.const.tcp.option import Option as OPT_TYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.transport.transport import Transport
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['TCP']

T = True
F = False

nm_len = lambda n: n - 2
op_len = lambda n: n * 8

# pylint: disable=protected-access
mptcp_opt = {   # [RFC 6824]
    0: lambda self, bits, size, kind: self._read_mptcp_capable(bits, size, kind),      # MP_CAPABLE
    1: lambda self, bits, size, kind: self._read_mptcp_join(bits, size, kind),         # MP_JOIN
    2: lambda self, bits, size, kind: self._read_mptcp_dss(bits, size, kind),          # DSS
    3: lambda self, bits, size, kind: self._read_mptcp_add(bits, size, kind),          # ADD_ADDR
    4: lambda self, bits, size, kind: self._read_mptcp_remove(bits, size, kind),       # REMOVE_ADDR
    5: lambda self, bits, size, kind: self._read_mptcp_prio(bits, size, kind),         # MP_PRIO
    6: lambda self, bits, size, kind: self._read_mptcp_fail(bits, size, kind),         # MP_FAIL
    7: lambda self, bits, size, kind: self._read_mptcp_fastclose(bits, size, kind),    # MP_FASTCLOSE
}

# pylint: disable=protected-access
process_opt = {
    0: lambda self, size, kind: self._read_mode_donone(size, kind),    # do nothing
    1: lambda self, size, kind: self._read_mode_unpack(size, kind),    # unpack according to size
    2: lambda self, size, kind: self._read_mode_tsopt(size, kind),     # Timestamps
    3: lambda self, size, kind: self._read_mode_pocsp(size, kind),     # POC Service Profile
    4: lambda self, size, kind: self._read_mode_acopt(size, kind),     # Alternate Checksum Request
    5: lambda self, size, kind: self._read_mode_qsopt(size, kind),     # Quick-Start Response
    6: lambda self, size, kind: self._read_mode_utopt(size, kind),     # User Timeout Option
    7: lambda self, size, kind: self._read_mode_tcpao(size, kind),     # TCP Authentication Option
    8: lambda self, size, kind: self._read_mode_mptcp(size, kind),     # Multipath TCP
}

TCP_OPT = {                          # # kind  length  type  process  comment            name
    0:  (F, 'eool'),                 # #   0      -      -      -                [RFC 793] End of Option List
    1:  (F, 'nop'),                  # #   1      -      -      -                [RFC 793] No-Operation
    2:  (T, 'mss', nm_len, 1),       # #   2      4      H      1                [RFC 793] Maximum Segment Size
    3:  (T, 'ws', nm_len, 1),        # #   3      3      B      1                [RFC 7323] Window Scale
    4:  (T, 'sackpmt', nm_len),      # #   4      2      ?      -       True     [RFC 2018] SACK Permitted
    5:  (T, 'sack', op_len, 0),      # #   5      N      P      0      2+8*N     [RFC 2018] SACK
    6:  (T, 'echo', nm_len, 0),      # #   6      6      P      0                [RFC 1072][RFC 6247] Echo
    7:  (T, 'echore', nm_len, 0),    # #   7      6      P      0                [RFC 1072][RFC 6247] Echo Reply
    8:  (T, 'ts', nm_len, 2),        # #   8     10     II      2                [RFC 7323] Timestamps
    9:  (T, 'poc', nm_len),          # #   9      2      ?      -       True     [RFC 1693][RFC 6247] POC Permitted
    10: (T, 'pocsp', nm_len, 3),     # #  10      3    ??P      3                [RFC 1693][RFC 6247] POC-Serv Profile
    11: (T, 'cc', nm_len, 0),        # #  11      6      P      0                [RFC 1693][RFC 6247] Connection Count
    12: (T, 'ccnew', nm_len, 0),     # #  12      6      P      0                [RFC 1693][RFC 6247] CC.NEW
    13: (T, 'ccecho', nm_len, 0),    # #  13      6      P      0                [RFC 1693][RFC 6247] CC.ECHO
    14: (T, 'chkreq', nm_len, 4),    # #  14      3      B      4                [RFC 1146][RFC 6247] Alt-Chksum Request
    15: (T, 'chksum', nm_len, 0),    # #  15      N      P      0                [RFC 1146][RFC 6247] Alt-Chksum Data
    19: (T, 'sig', nm_len, 0),       # #  19     18      P      0                [RFC 2385] MD5 Signature Option
    27: (T, 'qs', nm_len, 5),        # #  27      8      P      5                [RFC 4782] Quick-Start Response
    28: (T, 'timeout', nm_len, 6),   # #  28      4      P      6                [RFC 5482] User Timeout Option
    29: (T, 'ao', nm_len, 7),        # #  29      N      P      7                [RFC 5925] TCP Authentication Option
    30: (T, 'mp', nm_len, 8),        # #  30      N      P      8                [RFC 6824] Multipath TCP
    34: (T, 'fastopen', nm_len, 0),  # #  34      N      P      0                [RFC 7413] Fast Open
}
"""TCP Option Utility Table

T | F
    bool, short of True / False

nm_len | op_len
    function, length of data bytes

chksum_opt
    dict, checksum algorithm

mptcp_opt
    dict, Multipath TCP option subtype dict

TCP_OPT
    dict, TCP option dict.
    Value is a tuple which contains:
        |--> bool, if length greater than 1
        |       |--> T - True
        |       |--> F - False
        |--> str, description string, also attribute name
        |--> (optional) function, length of data bytes
        |       |--> nm_len - default length calculation
        |       |--> op_len - optional length calculation (indicates in comment)
        |--> (optional) int, process that data bytes need (when length greater than 2)
                |--> 0: do nothing
                |--> 1: unpack according to size
                |--> 2: unpack TSopt then add to dict
                |--> 3: unpack POC-SP then add to dict
                |--> 4: unpack ACopt then fetch algorithm
                |           |--> TCP checksum
                |           |--> 8-bit Fletcher's algorithm
                |           |--> 16-bit Fletcher's algorithm
                |           |--> Redundant Checksum Avoidance
                |--> 5: unpack QSopt then add to dict
                |--> 6: unpack UTopt then add to dict
                |--> 7: unpack TCP-AO then add tot dict
                |--> 8: unpack MPTCP then add to dict
                            |--> extract subtype MP_CAPABLE
                            |--> extract subtype MP_JOIN (SYN | SYN/ACK | ACK)
                            |--> extract subtype DSS
                            |--> extract subtype ADD_ADDR
                            |--> extract subtype REMOVE_ADDR
                            |--> extract subtype MP_PRIO
                            |--> extract subtype MP_FAIL
                            |--> extract subtype MP_FASTCLOSE

"""


class TCP(Transport):
    """This class implements Transmission Control Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Transmission Control Protocol']
        """
        return 'Transmission Control Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: int
        """
        return self._info.hdr_len  # pylint: disable=E1101

    @property
    def src(self):
        """Source port.

        :rtype: int
        """
        return self._info.srcport  # pylint: disable=E1101

    @property
    def dst(self):
        """Destination port.

        :rtype: int
        """
        return self._info.dstport  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Transmission Control Protocol (TCP).

        Structure of TCP header [:rfc:`793`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Source Port          |       Destination Port        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                        Sequence Number                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                   Acknowledgement Number                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Data |           |U|A|P|R|S|F|                               |
            | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
            |       |           |G|K|H|T|N|N|                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Checksum            |         Urgent Pointer        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                    Options                    |    Padding    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                             data                              |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_TCP: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _srcp = self._read_unpack(2)
        _dstp = self._read_unpack(2)
        _seqn = self._read_unpack(4)
        _ackn = self._read_unpack(4)
        _lenf = self._read_binary(1)
        _flag = self._read_binary(1)
        _wins = self._read_unpack(2)
        _csum = self._read_fileng(2)
        _urgp = self._read_unpack(2)

        tcp = dict(
            srcport=_srcp,
            dstport=_dstp,
            seq=_seqn,
            ack=_ackn,
            hdr_len=int(_lenf[:4], base=2) * 4,
            flags=dict(
                ns=bool(int(_lenf[7])),
                cwr=bool(int(_flag[0])),
                ece=bool(int(_flag[1])),
                urg=bool(int(_flag[2])),
                ack=bool(int(_flag[3])),
                psh=bool(int(_flag[4])),
                rst=bool(int(_flag[5])),
                syn=bool(int(_flag[6])),
                fin=bool(int(_flag[7])),
            ),
            window_size=_wins,
            checksum=_csum,
            urgent_pointer=_urgp,
        )

        # packet type flags
        self._syn = bool(int(_flag[6]))
        self._ack = bool(int(_flag[3]))

        _hlen = tcp['hdr_len']
        _optl = _hlen - 20
        if _optl:
            options = self._read_tcp_options(_optl)
            tcp['opt'] = options[0]     # tuple of option acronyms
            tcp.update(options[1])      # merge option info to buffer

        length -= _hlen
        tcp['packet'] = self._read_packet(header=_hlen, payload=length)

        return self._decode_next_layer(tcp, None, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

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
        return TransType(6)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_tcp_options(self, size):
        """Read TCP option list.

        Arguments:
            size (int): length of option list

        Returns:
            Tuple[Tuple[pcapkit.const.tcp.option.Option], DataType_TCP_Opt]:
            Tuple of TCP option list and extracted TCP options.

        """
        counter = 0         # length of read option list
        optkind = list()    # option kind list
        options = dict()    # dict of option data

        while counter < size:
            # get option kind
            kind = self._read_unpack(1)

            # fetch corresponding option tuple
            opts = TCP_OPT.get(kind)
            enum = OPT_TYPE.get(kind)
            if opts is None:
                len_ = size - counter
                counter = size
                optkind.append(enum)
                options[enum.name] = self._read_fileng(len_)
                break

            # extract option
            dscp = opts[1]
            if opts[0]:
                len_ = self._read_unpack(1)
                byte = opts[2](len_)
                if byte:    # check option process mode
                    data = process_opt[opts[3]](self, byte, kind)
                else:       # permission options (length is 2)
                    data = dict(
                        kind=kind,      # option kind
                        length=2,       # option length
                        flag=True,      # permission flag
                    )
            else:           # 1-bytes options
                len_ = 1
                data = dict(
                    kind=kind,      # option kind
                    length=1,       # option length
                )

            # record option data
            counter += len_
            if enum in optkind:
                if isinstance(options[dscp], tuple):
                    options[dscp] += (Info(data),)
                else:
                    options[dscp] = (Info(options[dscp]), Info(data))
            else:
                optkind.append(enum)
                options[dscp] = data

            # break when eol triggered
            if not kind:
                break

        # get padding
        if counter < size:
            len_ = size - counter
            options['padding'] = self._read_fileng(len_)

        return tuple(optkind), options

    def _read_mode_donone(self, size, kind):
        """Read options request no process.

        Arguments:
            size (int): length of option
            kind (int): option kind value

        Returns:
            DataType_TCP_Opt_DONONE: Extracted option with no operation.

        """
        data = dict(
            kind=kind,
            length=size,
            data=self._read_fileng(size),
        )
        return data

    def _read_mode_unpack(self, size, kind):
        """Read options request unpack process.

        Arguments:
            size (int): length of option
            kind (int): option kind value

        Returns:
            DataType_TCP_Opt_UNPACK: Extracted option which unpacked.

        """
        data = dict(
            kind=kind,
            length=size,
            data=self._read_unpack(size),
        )
        return data

    def _read_mode_tsopt(self, size, kind):
        """Read Timestamps option.

        Structure of TCP ``TSopt`` [:rfc:`7323`]::

            +-------+-------+---------------------+---------------------+
            |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
            +-------+-------+---------------------+---------------------+
                1       1              4                     4

        Arguments:
            size (int): length of option
            kind (Literal[8]): option kind value (Timestamps)

        Returns:
            DataType_TCP_Opt_TS: extracted Timestamps (``TS``) option

        """
        temp = struct.unpack('>II', self._read_fileng(size))
        data = dict(
            kind=kind,
            length=size,
            val=temp[0],
            ecr=temp[1],
        )
        return data

    def _read_mode_pocsp(self, size, kind):
        """Read Partial Order Connection Service Profile option.

        Structure of TCP ``POC-SP`` Option [:rfc:`1693`][:rfc:`6247`]::

                                      1 bit        1 bit    6 bits
            +----------+----------+------------+----------+--------+
            |  Kind=10 | Length=3 | Start_flag | End_flag | Filler |
            +----------+----------+------------+----------+--------+

        Arguments:
            size (int): length of option
            kind (Literal[10]): option kind value (POC-Serv Profile)

        Returns:
            DataType_TCP_Opt_POCSP: extracted Partial Order Connection Service Profile (``POC-SP``) option

        """
        temp = self._read_binary(size)

        data = dict(
            kind=kind,
            length=size,
            start=bool(int(temp[0])),
            end=bool(int(temp[1])),
            filler=bytes(chr(int(temp[2:], base=2)), encoding='utf-8'),
        )

        return data

    def _read_mode_acopt(self, size, kind):
        """Read Alternate Checksum Request option.

        Structure of TCP ``CHKSUM-REQ`` [:rfc:`1146`][:rfc:`6247`]::

            +----------+----------+----------+
            |  Kind=14 | Length=3 |  chksum  |
            +----------+----------+----------+

        Arguments:
            size (int): length of option
            kind (Literal[14]): option kind value (Alt-Chksum Request)

        Returns:
            DataType_TCP_Opt_ACOPT: extracted Alternate Checksum Request (``CHKSUM-REQ``) option

        """
        temp = self._read_unpack(size)
        algo = chksum_opt.get(temp)

        data = dict(
            kind=kind,
            length=size,
            ac=algo,
        )

        return data

    def _read_mode_qsopt(self, size, kind):
        """Read Quick-Start Response option.

        Structure of TCP ``QSopt`` [:rfc:`4782`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Kind      |  Length=8     | Resv. | Rate  |   TTL Diff    |
            |               |               |       |Request|               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                   QS Nonce                                | R |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            size (int): length of option
            kind (Literal[27]): option kind value (Quick-Start Response)

        Returns:
            DataType_TCP_Opt_QSOPT: extracted Quick-Start Response (``QS``) option

        """
        rvrr = self._read_binary(1)
        ttld = self._read_unpack(1)
        noun = self._read_binary(4)

        data = dict(
            kind=kind,
            length=size,
            req_rate=int(rvrr[4:], base=2),
            ttl_diff=ttld,
            nounce=int(noun[:-2], base=2),
        )

        return data

    def _read_mode_utopt(self, size, kind):
        """Read User Timeout option.

        Structure of TCP ``TIMEOUT`` [:rfc:`5482`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |   Kind = 28   |   Length = 4  |G|        User Timeout         |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Arguments:
            size (int): length of option
            kind (Literal[28]): option kind value (User Timeout Option)

        Returns:
            DataType_TCP_Opt_UTOPT: extracted User Timeout (``TIMEOUT``) option

        """
        temp = self._read_fileng(size)
        if int(temp[0]):
            time = datetime.timedelta(minutes=int(temp[0:], base=2))
        else:
            time = datetime.timedelta(seconds=int(temp[0:], base=2))

        data = dict(
            kind=kind,
            length=size,
            granularity='minutes' if int(temp[0]) else 'seconds',
            timeout=time,
        )

        return data

    def _read_mode_tcpao(self, size, kind):
        """Read Authentication option.

        Structure of TCP ``AOopt`` [:rfc:`5925`]::

            +------------+------------+------------+------------+
            |  Kind=29   |   Length   |   KeyID    | RNextKeyID |
            +------------+------------+------------+------------+
            |                     MAC           ...
            +-----------------------------------...

            ...-----------------+
            ...  MAC (con't)    |
            ...-----------------+

        Arguments:
            size (int): length of option
            kind (Literal[29]): option kind value (TCP Authentication Option)

        Returns:
            DataType_TCP_Opt_TCPAO: extracted Authentication (``AO``) option

        """
        key_ = self._read_unpack(1)
        rkey = self._read_unpack(1)
        mac_ = self._read_fileng(size - 2)

        data = dict(
            kind=kind,
            length=size,
            key_id=key_,
            r_next_key_id=rkey,
            mac=mac_,
        )

        return data

    def _read_mode_mptcp(self, size, kind):
        """Read Multipath TCP option.

        Structure of ``MP-TCP`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----------------------+
            |     Kind      |    Length     |Subtype|                       |
            +---------------+---------------+-------+                       |
            |                     Subtype-specific data                     |
            |                       (variable length)                       |
            +---------------------------------------------------------------+

        Arguments:
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MPTCP: extracted Multipath TCP (``MP-TCP``) option

        """
        bins = self._read_binary(1)
        subt = int(bins[:4], base=2)    # subtype number
        bits = bins[4:]                 # 4-bit data
        dlen = size - 1                 # length of remaining data

        # fetch subtype-specific data
        func = mptcp_opt.get(subt)
        if func is None:    # if subtype not exist, directly read all data
            temp = self._read_fileng(dlen)
            data = dict(
                kind=kind,
                length=size,
                subtype=MPTCPOption.get(subt),
                data=bytes(chr(int(bits[:4], base=2)), encoding='utf-8') + temp,
            )
        else:               # fetch corresponding subtype data dict
            data = func(self, bits, dlen, kind)
        return data

    def _read_mptcp_capable(self, bits, size, kind):
        """Read Multipath Capable option.

        Structure of ``MP_CAPABLE`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-------+---------------+
            |     Kind      |    Length     |Subtype|Version|A|B|C|D|E|F|G|H|
            +---------------+---------------+-------+-------+---------------+
            |                   Option Sender's Key (64 bits)               |
            |                                                               |
            |                                                               |
            +---------------------------------------------------------------+
            |                  Option Receiver's Key (64 bits)              |
            |                     (if option Length == 20)                  |
            |                                                               |
            +---------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_CAPABLE: extracted Multipath Capable (``MP_CAPABLE``) option

        """
        vers = int(bits, base=2)
        bins = self._read_binary(1)
        skey = self._read_unpack(8)
        rkey = self._read_unpack(8) if size == 17 else None

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(0),
            capable=dict(
                version=vers,
                flags=dict(
                    req=bool(int(bins[0])),
                    ext=bool(int(bins[1])),
                    res=tuple(bool(int(bit)) for bit in bits[2:7]),
                    hsa=bool(int(bins[7])),
                ),
                skey=skey,
                rkey=rkey,
            ),
        )

        return data

    def _read_mptcp_join(self, bits, size, kind):
        """Read Join Connection option.

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_JOIN: extracted Join Connection (``MP_JOIN``) option

        """
        if self._syn and self._ack:      # MP_JOIN-SYN/ACK
            return self._read_join_synack(bits, size, kind)
        if self._syn and not self._ack:  # MP_JOIN-SYN
            return self._read_join_syn(bits, size, kind)
        if not self._syn and self._ack:  # MP_JOIN-ACK
            return self._read_join_ack(bits, size, kind)

        temp = self._read_fileng(size)   # illegal MP_JOIN occurred
        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(1),
            connection=None,
            join=dict(
                data=bytes(chr(int(bits[:4], base=2)), encoding='utf-8') + temp,
            ),
        )
        return data

    def _read_join_syn(self, bits, size, kind):
        """Read Join Connection option for Initial SYN.

        Structure of ``MP_JOIN-SYN`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----+-+---------------+
            |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
            +---------------+---------------+-------+-----+-+---------------+
            |                   Receiver's Token (32 bits)                  |
            +---------------------------------------------------------------+
            |                Sender's Random Number (32 bits)               |
            +---------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_JOIN_SYN: extracted Join Connection (``MP_JOIN-SYN``) option for Initial SYN

        """
        adid = self._read_unpack(1)
        rtkn = self._read_unpack(4)
        srno = self._read_unpack(4)

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(1),
            connection='SYN',
            join=dict(
                syn=dict(
                    backup=bool(int(bits[3])),
                    addr_id=adid,
                    token=rtkn,
                    rand_num=srno,
                ),
            ),
        )

        return data

    def _read_join_synack(self, bits, size, kind):
        """Read Join Connection option for Responding SYN/ACK.

        Structure of ``MP_JOIN-SYN/ACK`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----+-+---------------+
            |     Kind      |  Length = 16  |Subtype|     |B|   Address ID  |
            +---------------+---------------+-------+-----+-+---------------+
            |                                                               |
            |                Sender's Truncated HMAC (64 bits)              |
            |                                                               |
            +---------------------------------------------------------------+
            |                Sender's Random Number (32 bits)               |
            +---------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_JOIN_SYNACK: extracted Join Connection (``MP_JOIN-SYN/ACK``)
            option for Responding SYN/ACK

        """
        adid = self._read_unpack(1)
        hmac = self._read_fileng(8)
        srno = self._read_unpack(4)

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(1),
            connection='SYN/ACK',
            join=dict(
                synack=dict(
                    backup=bool(int(bits[3])),
                    addr_id=adid,
                    hmac=hmac,
                    rand_num=srno,
                ),
            ),
        )

        return data

    def _read_join_ack(self, bits, size, kind):  # pylint: disable=unused-argument
        """Read Join Connection option for Third ACK.

        Structure of ``MP_JOIN-ACK`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----------------------+
            |     Kind      |  Length = 24  |Subtype|      (reserved)       |
            +---------------+---------------+-------+-----------------------+
            |                                                               |
            |                                                               |
            |                   Sender's HMAC (160 bits)                    |
            |                                                               |
            |                                                               |
            +---------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_JOIN_ACK: extracted Join Connection (``MP_JOIN-ACK``)
            option for Third ACK

        """
        temp = self._read_fileng(20)

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(1),
            connection='ACK',
            join=dict(
                ack=dict(
                    hmac=temp,
                ),
            ),
        )

        return data

    def _read_mptcp_dss(self, bits, size, kind):
        """Read Data Sequence Signal (Data ACK and Data Sequence Mapping) option.

        Structure of ``DSS`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+----------------------+
            |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|
            +---------------+---------------+-------+----------------------+
            |                                                              |
            |           Data ACK (4 or 8 octets, depending on flags)       |
            |                                                              |
            +--------------------------------------------------------------+
            |                                                              |
            |   Data sequence number (4 or 8 octets, depending on flags)   |
            |                                                              |
            +--------------------------------------------------------------+
            |              Subflow Sequence Number (4 octets)              |
            +-------------------------------+------------------------------+
            |  Data-Level Length (2 octets) |      Checksum (2 octets)     |
            +-------------------------------+------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_DSS: extracted Data Sequence Signal (``DSS``) option

        """
        bits = self._read_binary(1)
        mflg = 8 if int(bits[4]) else 4
        Mflg = bool(int(bits[5]))
        aflg = 8 if int(bits[6]) else 4
        Aflg = bool(int(bits[7]))
        ack_ = self._read_unpack(aflg) if Aflg else None
        dsn_ = self._read_unpack(mflg) if Mflg else None
        ssn_ = self._read_unpack(4) if Mflg else None
        dll_ = self._read_unpack(2) if Mflg else None
        chk_ = self._read_fileng(2) if Mflg else None

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(2),
            dss=dict(
                flags=dict(
                    fin=bool(int(bits[3])),
                    dsn_len=mflg,
                    data_pre=Mflg,
                    ack_len=aflg,
                    ack_pre=Aflg,
                ),
                ack=ack_,
                dsn=dsn_,
                ssn=ssn_,
                dl_len=dll_,
                checksum=chk_,
            ),
        )

        return data

    def _read_mptcp_add(self, bits, size, kind):
        """Read Add Address option.

        Structure of ``ADD_ADDR`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-------+---------------+
            |     Kind      |     Length    |Subtype| IPVer |  Address ID   |
            +---------------+---------------+-------+-------+---------------+
            |          Address (IPv4 - 4 octets / IPv6 - 16 octets)         |
            +-------------------------------+-------------------------------+
            |   Port (2 octets, optional)   |
            +-------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_ADD_ADDR: extracted Add Address (``ADD_ADDR``) option

        Raises:
            ProtocolError: If the option is malformed.

        """
        vers = int(bits, base=2)
        if vers == 4:
            ip_l = 4
        elif vers == 6:
            ip_l = 16
        else:
            raise ProtocolError('[MP_TCP ADD_ADDR] malformed option')

        adid = self._read_unpack(1)
        ipad = self._read_fileng(ip_l)
        pt_l = size - 1 - ip_l
        port = self._read_unpack(2) if pt_l else None

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(3),
            add_addr=dict(
                ip_ver=vers,
                addrid=adid,
                addr=ipaddress.ip_address(ipad),
                port=port,
            ),
        )

        return data

    def _read_mptcp_remove(self, bits, size, kind):  # pylint: disable=unused-argument
        """Read Remove Address option.

        Structure of ``REMOVE_ADDR`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-------+---------------+
            |     Kind      |  Length = 3+n |Subtype|(resvd)|   Address ID  | ...
            +---------------+---------------+-------+-------+---------------+
                                       (followed by n-1 Address IDs, if required)

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_REMOVE_ADDR: extracted Remove Address (``REMOVE_ADDR``) option

        """
        adid = []
        for _ in size:
            adid.append(self._read_unpack(1))

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(4),
            removeaddr=dict(
                addr_id=tuple(adid),
            ),
        )

        return data

    def _read_mptcp_prio(self, bits, size, kind):
        """Read Change Subflow Priority option.

        Structure of ``MP_PRIO`` [RFC 6824]::

                                  1                   2                   3
              0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----+-+--------------+
            |     Kind      |     Length    |Subtype|     |B| AddrID (opt) |
            +---------------+---------------+-------+-----+-+--------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_REMOVE_ADDR: extracted Change Subflow Priority (``MP_PRIO``) option

        """
        temp = self._read_unpack(1) if size else None

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(4),
            prio=dict(
                backup=bool(int(bits[3])),
                addr_id=temp,
            ),
        )

        return data

    def _read_mptcp_fail(self, bits, size, kind):  # pylint: disable=unused-argument
        """Read Fallback option.

        Structure of ``MP_FAIL`` [:rfc:`6824`]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+----------------------+
            |     Kind      |   Length=12   |Subtype|      (reserved)      |
            +---------------+---------------+-------+----------------------+
            |                                                              |
            |                 Data Sequence Number (8 octets)              |
            |                                                              |
            +--------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_FAIL: extracted Fallback (``MP_FAIL``) option

        """
        resv = self._read_fileng(1)  # pylint: disable=unused-variable
        dsn_ = self._read_unpack(8)

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(6),
            fail=dict(
                dsn=dsn_,
            ),
        )

        return data

    def _read_mptcp_fastclose(self, bits, size, kind):  # pylint: disable=unused-argument
        """Read Fast Close option.

        Structure of ``MP_FASTCLOSE`` [RFC 6824]::

                                 1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +---------------+---------------+-------+-----------------------+
            |     Kind      |    Length     |Subtype|      (reserved)       |
            +---------------+---------------+-------+-----------------------+
            |                      Option Receiver's Key                    |
            |                            (64 bits)                          |
            |                                                               |
            +---------------------------------------------------------------+

        Arguments:
            bits (str): 4-bit data (after subtype)
            size (int): length of option
            kind (Literal[30]): option kind value (Multipath TCP)

        Returns:
            DataType_TCP_Opt_MP_FAIL: extracted Fast Close (``MP_FASTCLOSE``) option

        """
        resv = self._read_fileng(1)  # pylint: disable=unused-variable
        rkey = self._read_fileng(8)

        data = dict(
            kind=kind,
            length=size + 1,
            subtype=MPTCPOption(7),
            fastclose=dict(
                rkey=rkey,
            ),
        )

        return data

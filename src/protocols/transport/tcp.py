#!/usr/bin/python3
# -*- coding: utf-8 -*-


import struct


# Transmission Control Protocol
# Analyser for TCP header


from jspcap.utilities import Info
from jspcap.protocols.transport.transport import Transport


__all__ = ['TCP']


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

T = True
F = False

nm_len = lambda n: n - 2
op_len = lambda n: n * 8

chksum_opt = {  # [RFC 1146]
    0:  'TCP checksum',
    1:  "8-bit Fletcher's algorithm",
    2:  "16-bit Fletcher's algorithm",
    3:  'Redundant Checksum Avoidance',
}

mptcp_opt = {   # [RFC 6824]
    0:  lambda self, bits, size: self._read_mptcp_capable(bits, size),      # MP_CAPABLE
    1:  lambda self, bits, size: self._read_mptcp_join(bits, size),         # MP_JOIN
    2:  lambda self, bits, size: self._read_mptcp_dss(bits, size),          # DSS
    3:  lambda self, bits, size: self._read_mptcp_add(bits, size),          # ADD_ADDR
    4:  lambda self, bits, size: self._read_mptcp_remove(bits, size),       # REMOVE_ADDR
    5:  lambda self, bits, size: self._read_mptcp_prio(bits, size),         # MP_PRIO
    6:  lambda self, bits, size: self._read_mptcp_fail(bits, size),         # MP_FAIL
    7:  lambda self, bits, size: self._read_mptcp_fastclose(bits, size),    # MP_FASTCLOSE
}

process_opt = {
    0:  lambda self, size, kind: self._read_mode_donone(size, kind),    # do nothing
    1:  lambda self, size, kind: self._read_mode_unpack(size, kind),    # unpack according to size
    2:  lambda self, size, kind: self._read_mode_tsopt(size, kind),     # Timestamps
    3:  lambda self, size, kind: self._read_mode_pocsp(size, kind),     # POC Service Profile
    4:  lambda self, size, kind: self._read_mode_acopt(size, kind),     # Alternate Checksum Request
    5:  lambda self, size, kind: self._read_mode_qsopt(size, kind),     # Quick-Start Response
    6:  lambda self, size, kind: self._read_mode_utopt(size, kind),     # User Timeout Option
    7:  lambda self, size, kind: self._read_mode_tcpao(size, kind),     # TCP Authentication Option
    8:  lambda self, size, kind: self._read_mode_mptcp(size, kind),     # Multipath TCP
}

TCP_OPT = {                         #   kind  length  type  process  comment            name
    0:  (F, 'eool'),                #     0      -      -      -                [RFC 793] End of Option List
    1:  (F, 'nop'),                 #     1      -      -      -                [RFC 793] No-Operation
    2:  (T, 'mss', nm_len, 1),      #     2      4      H      1                [RFC 793] Maximum Segment Size
    3:  (T, 'ws', nm_len, 1),       #     3      3      B      1                [RFC 7323] Window Scale
    4:  (T, 'sackpmt', nm_len),     #     4      2      ?      -       True     [RFC 2018] SACK Permitted
    5:  (T, 'sack', op_len, 0),     #     5      N      P      0      2+8*N     [RFC 2018] SACK
    6:  (T, 'echo', nm_len, 0),     #     6      6      P      0                [RFC 1072][RFC 6247] Echo
    7:  (T, 'echore', nm_len, 0),   #     7      6      P      0                [RFC 1072][RFC 6247] Echo Reply
    8:  (T, 'ts', nm_len, 2),       #     8     10     II      2                [RFC 7323] Timestamps
    9:  (T, 'poc', nm_len),         #     9      2      ?      -       True     [RFC 1693][RFC 6247] POC Permitted
   10:  (T, 'pocsp', nm_len, 3),    #    10      3    ??P      3                [RFC 1693][RFC 6247] POC-Serv Profile
   11:  (T, 'cc', nm_len, 0),       #    11      6      P      0                [RFC 1693][RFC 6247] Connection Count
   12:  (T, 'ccnew', nm_len, 0),    #    12      6      P      0                [RFC 1693][RFC 6247] CC.NEW
   13:  (T, 'ccecho', nm_len, 0),   #    13      6      P      0                [RFC 1693][RFC 6247] CC.ECHO
   14:  (T, 'chkreq', nm_len, 4),   #    14      3      B      4                [RFC 1146][RFC 6247] Alt-Chksum Request
   15:  (T, 'chksum', nm_len, 0),   #    15      N      P      0                [RFC 1146][RFC 6247] Alt-Chksum Data
   19:  (T, 'sig', nm_len, 0),      #    19     18      P      0                [RFC 2385] MD5 Signature Option
   27:  (T, 'qs', nm_len, 5),       #    27      8      P      5                [RFC 4782] Quick-Start Response
   28:  (T, 'timeout', nm_len, 6),  #    28      4      P      6                [RFC 5482] User Timeout Option
   29:  (T, 'ao', nm_len, 7),       #    29      N      P      7                [RFC 5925] TCP Authentication Option
   30:  (T, 'mp', nm_len, 8),       #    30      N      P      8                [RFC 6824] Multipath TCP
   34:  (T, 'fastopen', nm_len, 0), #    34      N      P      0                [RFC 7413] Fast Open
}


class TCP(Transport):
    """This class implements Transmission Control Protocol.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * layer -- str, `Transport`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- int, source port
        * dst -- int, destination port

    Methods:
        * read_tcp -- read Transmission Control Protocol (TCP)

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
        * _read_tcp_options -- read TCP option list
        * _read_mode_donone -- read options request no process
        * _read_mode_unpack -- read options request unpack process
        * _read_mode_tsopt -- read Timestamps option
        * _read_mode_pocsp -- read Partial Order Connection Service Profile Option
        * _read_mode_acopt -- read Alternate Checksum Request Option
        * _read_mode_qsopt -- read Quick-Start Response Option
        * _read_mode_utopt -- read User Timeout Option
        * _read_mode_tcpao -- read Authentication Option
        * _read_mode_mptcp -- read Multipath TCP Option
        * _read_mptcp_capable -- read Multipath Capable Option
        * _read_mptcp_join -- read Join Connection Option
        * _read_join_syn -- read Join Connection Option for Initial SYN
        * _read_join_synack -- read Join Connection Option for Responding SYN/ACK
        * _read_join_ack -- read Join Connection Option for Third ACK
        * _read_mptcp_dss -- read Data Sequence Signal (Data ACK and Data Sequence Mapping) Option
        * _read_mptcp_add -- read Add Address Option
        * _read_addr_ipv4 -- read IPv4 address
        * _read_addr_ipv6 -- read IPv6 address
        * _read_mptcp_remove -- read Remove Address Option
        * _read_mptcp_prio -- read Change Subflow Priority Option
        * _read_mptcp_fail -- read Fallback Option
        * _read_mptcp_fastclose -- read Fast Close Option

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Transmission Control Protocol'

    @property
    def length(self):
        return self._info.hdr_len

    @property
    def src(self):
        return self._info.srcport

    @property
    def dst(self):
        return self._info.dstport

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_tcp(self, length):
        """Read Transmission Control Protocol (TCP).

        Structure of TCP header [RFC 793]:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Source Port          |       Destination Port        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Sequence Number                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    Acknowledgment Number                      |
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


            Octets          Bits          Name                      Discription
              0              0          tcp.srcport             Source Port
              2              16         tcp.dstport             Destination Port
              4              32         tcp.seq                 Sequence Number
              8              64         tcp.ack                 Acknowledgment Number (if ACK set)
              12             96         tcp.hdr_len             Data Offset
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
              20             160        tcp.opt                 TCP Options (if data offset > 5)

        """
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
            options = self._read_tcp_options(_optl)
            tcp['opt'] = options[0]     # tuple of option acronyms
            tcp.update(options[1])      # merge option info to buffer

        if length is not None:
            length -= tcp['hdr_len']
        return self._decode_next_layer(tcp, None, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_tcp(length))

    def __len__(self):
        return self._info.hdr_len

    def __length_hint__(self):
        return 20

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_tcp_options(self, size):
        """Read TCP option list.

        Keyword arguments:
            * size -- int, length of option list

        """
        counter = 0         # length of read option list
        optkind = tuple()   # option kind list
        options = dict()    # dict of option data

        while counter < size:
            # get option kind
            kind = self._read_unpack(1)

            # fetch corresponding option tuple
            opts = TCP_OPT.get(kind)
            if opts is None:
                len_ = size - counter
                counter = size
                options['Unknown'] = self._read_fileng(len_)
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
                        kind = kind,    # option kind
                        length = 2,     # option length
                        flag = True,    # permission flag
                    )
            else:           # 1-bytes options
                len_ = 1
                data = dict(
                    kind = kind,    # option kind
                    length = 1,     # option length
                )

            # record option data
            counter += len_
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

    def _read_mode_tsopt(self, size, kind):
        """Read Timestamps option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 8 (Timestamps)

        Structure of TCP TSopt [RFC 7323]:

           +-------+-------+---------------------+---------------------+
           |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
           +-------+-------+---------------------+---------------------+
               1       1              4                     4

            Octets          Bits            Name                        Discription
              0              0          tcp.ts.kind                 Kind (8)
              1              8          tcp.ts.length               Length (10)
              2             16          tcp.ts.val                  Timestamp Value
              6             48          tcp.ts.ecr                  Timestamps Echo Reply

        """
        temp = struct.unpack('>II', self._read_fileng(size))
        data = dict(
            kind = kind,
            length = size,
            val = temp[0],
            ecr = temp[1],
        )
        return data

    def _read_mode_pocsp(self, size, kind):
        """Read Partial Order Connection Service Profile Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 10 (POC-Serv Profile)

        Structure of TCP POC-SP Option [RFC 1693][RFC 6247]:

                                      1 bit        1 bit    6 bits
            +----------+----------+------------+----------+--------+
            |  Kind=10 | Length=3 | Start_flag | End_flag | Filler |
            +----------+----------+------------+----------+--------+

            Octets          Bits            Name                        Discription
              0              0          tcp.pocsp.kind              Kind (10)
              1              8          tcp.pocsp.length            Length (3)
              2             16          tcp.pocsp.start             Start Flag
              2             17          tcp.pocsp.end               End Flag
              2             18          tcp.pocsp.filler            Filler

        """
        temp = self._read_binary(size)

        data = dict(
            kind = kind,
            length = size,
            start = True if int(temp[0]) else False,
            end = True if int(temp[1]) else False,
            filler = bytes(chr(int(bits[2:], base=2)), encoding='utf-8'),
        )

        return data

    def _read_mode_acopt(self, size, kind):
        """Read Alternate Checksum Request Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 14 (Alt-Chksum Request)

        Structure of TCP CHKSUM-REQ [RFC 1146][RFC 6247]:

           +----------+----------+----------+
           |  Kind=14 | Length=3 |  chksum  |
           +----------+----------+----------+

            Octets          Bits            Name                            Discription
              0              0          tcp.chksumreq.kind             Kind (14)
              1              8          tcp.chksumreq.length           Length (3)
              2             16          tcp.chksumreq.ac               Checksum Algorithm

        """
        temp = self._read_unpack(size)
        algo = chksum_opt.get(temp)

        data = dict(
            kind = kind,
            length = size,
            ac = algo,
        )

        return data

    def _read_mode_qsopt(self, size, kind):
        """Read Quick-Start Response Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 27 (Quick-Start Response)

        Structure of TCP QSopt [RFC 4782]:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Kind      |  Length=8     | Resv. | Rate  |   TTL Diff    |
           |               |               |       |Request|               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                   QS Nonce                                | R |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets          Bits            Name                        Discription
              0              0          tcp.qs.kind                 Kind (27)
              1              8          tcp.qs.length               Length (8)
              2             16          tcp.qs.resv                 Reserved (must be zero)
              2             20          tcp.qs.req_rate             Request Rate
              3             24          tcp.qs.ttl_diff             TTL Difference
              4             32          tcp.qs.nounce               QS Nounce
              7             62          tcp.qs.res                  Reserved (must be zero)

        """
        rvrr = self._read_binary(1)
        ttld = self._read_unpack(1)
        noun = self._read_fileng(4)

        data = dict(
            kind = kind,
            length = size,
            resv = b'\x00' * 4,
            req_rate = int(rvrr[4:], base=2),
            ttl_diff = ttld,
            nounce = noun[:-2],
            res = b'\x00\x00',
        )

        return data

    def _read_mode_utopt(self, size, kind):
        """Read User Timeout Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 28 (User Timeout Option)

        Structure of TCP TIMEOUT [RFC 5482]:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Kind = 28   |   Length = 4  |G|        User Timeout         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets          Bits            Name                        Discription
              0              0          tcp.timeout.kind            Kind (28)
              1              8          tcp.timeout.length          Length (4)
              2             16          tcp.timeout.granularity     Granularity
              2             17          tcp.timeout.timeout         User Timeout

        """
        temp = self._read_fileng(size)

        data = dict(
            kind = kind,
            length = size,
            granularity = 'minutes' if int(temp[0]) else 'seconds',
            timeout = bytes(chr(int(bits[0:], base=2)), encoding='utf-8'),
        )

        return data

    def _read_mode_tcpao(self, size, kind):
        """Read Authentication Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 29 (TCP Authentication Option)

        Structure of TCP AOopt [RFC 5925]:

           +------------+------------+------------+------------+
           |  Kind=29   |   Length   |   KeyID    | RNextKeyID |
           +------------+------------+------------+------------+
           |                     MAC           ...
           +-----------------------------------...

           ...-----------------+
           ...  MAC (con't)    |
           ...-----------------+

            Octets          Bits            Name                        Discription
              0              0          tcp.ao.kind                 Kind (29)
              1              8          tcp.ao.length               Length
              2             16          tcp.ao.keyid                KeyID
              3             24          tcp.ao.rnextkeyid           RNextKeyID
              4             32          tcp.ao.mac                  Message Authentication Code

        """
        key_ = self._read_unpack(1)
        rkey = self._read_unpack(1)
        mac_ = self._read_fileng(size - 2)

        data = dict(
            kind = kind,
            length = size,
            keyid = key_,
            rnextkeyid = rkey,
            mac = mac_,
        )

        return data

    def _read_mode_mptcp(self, size, kind):
        """Read Multipath TCP Option.

        Keyword arguemnts:
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP-TCP [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----------------------+
           |     Kind      |    Length     |Subtype|                       |
           +---------------+---------------+-------+                       |
           |                     Subtype-specific data                     |
           |                       (variable length)                       |
           +---------------------------------------------------------------+

            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length
              2             16          tcp.mp.subtype              Subtype
              2             20          tcp.mp.data                 Subtype-specific Data

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
                kind = kind,
                length = size,
                subtype = 'Unknown',
                data = bytes(chr(int(bits[:4], base=2)), encoding='utf-8') + temp,
            )
        else:               # fetch corresponding subtype data dict
            data = func(self, bits, dlen, kind)
        return data

    def _read_mptcp_capable(self, bits, size, kind):
        """Read Multipath Capable Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP_CAPABLE [RFC 6824]:

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

            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length (12/20)
              2             16          tcp.mp.subtype              Subtype (0)
              2             20          tcp.mp.capable.version      Version
              3             24          tcp.mp.capable.flags.req    Checksum Require Flag (A)
              3             25          tcp.mp.capable.flags.ext    Extensibility Flag (B)
              3             26          tcp.mp.capable.flags.res    Unassigned (C-G)
              3             31          tcp.mp.capable.flags.hsa    HMAC-SHA1 Flag (H)
              4             32          tcp.mp.capable.skey         Option Sender's Key
              12            96          tcp.mp.capable.rkey         Option Receiver's Key
                                                                        (if option Length == 20)

        """
        vers = int(bits, base=2)
        bins = self._read_binary(1)
        skey = self._read_fileng(8)
        rkey = self._read_fileng(8) if size == 17 else None

        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'MP_CAPABLE',
            capable = dict(
                version = vers,
                flags = dict(
                    req = True if int(bins[0]) else False,
                    ext = True if int(bins[1]) else False,
                    res = bytes(chr(int(bits[2:7], base=2)), encoding='utf-8'),
                    hsa = True if int(bins[7]) else False,
                ),
                skey = skey,
                rkey = rkey,
            ),
        )

        return data

    def _read_mptcp_join(self, bits, size, kind):
        """Read Join Connection Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP_JOIN [RFC 6824]:
            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length
              2             16          tcp.mp.subtype              Subtype (1)
              2             20          tcp.mp.data                 Handshake-specific Data

        """
        if self._syn and self._ack: # MP_JOIN-SYN/ACK
            return self._read_join_synack(bits, size)
        elif self._syn:             # MP_JOIN-SYN
            return self._read_join_syn(bits, size)
        elif self._ack:             # MP_JOIN-ACK
            return self._read_join_ack(bits, size)
        else:   # illegal MP_JOIN occurred
            temp = self._read_fileng(dlen)
            data = dict(
                kind = kind,
                length = size + 1,
                subtype = 'MP_JOIN-Unknown',
                data = bytes(chr(int(bits[:4], base=2)), encoding='utf-8') + temp,
            )
            return data

    def _read_join_syn(self, bits, size, kind):
        """Read Join Connection Option for Initial SYN.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP_JOIN-SYN [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----+-+---------------+
           |     Kind      |  Length = 12  |Subtype|     |B|   Address ID  |
           +---------------+---------------+-------+-----+-+---------------+
           |                   Receiver's Token (32 bits)                  |
           +---------------------------------------------------------------+
           |                Sender's Random Number (32 bits)               |
           +---------------------------------------------------------------+

            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length (12)
              2             16          tcp.mp.subtype              Subtype (1|SYN)
              2             20          tcp.mp.join.syn.res         Reserved (must be zero)
              2             23          tcp.mp.join.syn.backup      Backup Path (B)
              3             24          tcp.mp.join.syn.addrid      Address ID
              4             32          tcp.mp.join.syn.token       Receiver's Token
              8             64          tcp.mp.join.syn.randnum     Sender's Random Number

        """
        adid = self._read_unpack(1)
        rtkn = self._read_fileng(4)
        srno = self._read_unpack(4)

        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'MP_JOIN-SYN',
            join = dict(
                syn = dict(
                    res = b'\x00\x00\x00',
                    backup = True if int(bits[3]) else False,
                    addrid = adid,
                    token = rtkn,
                    randnum = srno,
                ),
            ),
        )

        return data

    def _read_join_synack(self, bits, size, kind):
        """Read Join Connection Option for Responding SYN/ACK.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP_JOIN-SYN/ACK [RFC 6824]:

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

            Octets          Bits            Name                            Discription
              0              0          tcp.mp.kind                    Kind (30)
              1              8          tcp.mp.length                  Length (16)
              2             16          tcp.mp.subtype              Subtype (1|SYN/ACK)
              2             20          tcp.mp.join.synack.res      Reserved (must be zero)
              2             23          tcp.mp.join.synack.backup   Backup Path (B)
              3             24          tcp.mp.join.synack.addrid   Address ID
              4             32          tcp.mp.join.synack.hmac     Sender's Truncated HMAC
              12            96          tcp.mp.join.synack.randnum  Sender's Random Number

        """
        adid = self._read_unpack(1)
        hmac = self._read_fileng(8)
        srno = self._read_unpack(4)

        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'MP_JOIN-SYN/ACK',
            join = dict(
                synack = dict(
                    res = b'\x00\x00\x00',
                    backup = True if int(bits[3]) else False,
                    addrid = adid,
                    hmac = hmac,
                    randnum = srno,
                ),
            ),
        )

        return data

    def _read_join_ack(self, bits, size, kind):
        """Read Join Connection Option for Third ACK.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of MP_JOIN-ACK [RFC 6824]:

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

            Octets          Bits            Name                            Discription
              0              0          tcp.mp.kind                    Kind (30)
              1              8          tcp.mp.length                  Length (24)
              2             16          tcp.mp.subtype              Subtype (1|ACK)
              2             20          tcp.mp.join.ack.res         Reserved (must be zero)
              4             32          tcp.mp.join.ack.hmac        Sender's HMAC

        """
        temp = self._read_fileng(20)
        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'MP_JOIN-ACK',
            join = dict(
                ack = dict(
                    res = b'\x00' * 12,
                    hmac = temp,
                ),
            ),
        )

        return data

    def _read_mptcp_dss(self, bits, size, kind):
        """Read Data Sequence Signal (Data ACK and Data Sequence Mapping) Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of DSS [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+----------------------+
           |     Kind      |    Length     |Subtype| (reserved) |F|m|M|a|A|
           +---------------+---------------+-------+----------------------+
           |           Data ACK (4 or 8 octets, depending on flags)       |
           +--------------------------------------------------------------+
           |   Data sequence number (4 or 8 octets, depending on flags)   |
           +--------------------------------------------------------------+
           |              Subflow Sequence Number (4 octets)              |
           +-------------------------------+------------------------------+
           |  Data-Level Length (2 octets) |      Checksum (2 octets)     |
           +-------------------------------+------------------------------+

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +--------------------------------------------------------------+
           |                                                              |
           |                Data Sequence Number (8 octets)               |
           |                                                              |
           +--------------------------------------------------------------+
           |              Subflow Sequence Number (4 octets)              |
           +-------------------------------+------------------------------+
           |  Data-Level Length (2 octets) |        Zeros (2 octets)      |
           +-------------------------------+------------------------------+

            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length
              2             16          tcp.mp.subtype              Subtype (2)
              2             20          tcp.mp.dss.flags.res        Reserved (must be zero)
              3             27          tcp.mp.dss.flags.fin        DATA_FIN (F)
              3             28          tcp.mp.dss.flags.dsn_len    DSN Length (m)
              3             29          tcp.mp.dss.flags.data_pre   DSN, SSN, Data-Level Length, CHKSUM Present (M)
              3             30          tcp.mp.dss.flags.ack_len    ACK Length (a)
              3             31          tcp.mp.dss.flags.ack_pre    Data ACK Present (A)
              4             32          tcp.mp.dss.ack              Data ACK (4/8 octets)
              8-12       64-96          tcp.mp.dss.dsn              DSN (4/8 octets)
              12-20     48-160          tcp.mp.dss.ssn              Subflow Sequence Number
              16-24    128-192          tcp.mp.dss.dl_len           Data-Level Length
              18-26    144-208          tcp.mp.dss.checksum         Checksum

        """
        bits = self._read_binary(1)
        mflg = 8 if int(bits[4]) else 4
        Mflg = True if int(bits[5]) else False
        aflg = 8 if int(bits[6]) else 4
        Aflg = True if int(bits[7]) else False
        ack_ = self._read_fileng(aflg) if Aflg else None
        dsn_ = self._read_unpack(mflg) if Mflg else None
        ssn_ = self._read_unpack(4) if Mflg else None
        dll_ = self._read_unpack(2) if Mflg else None
        chk_ = self._read_fileng(2) if Mflg else None

        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'DSS',
            dss = dict(
                flags = dict(
                    res = b'\x00' * 7,
                    fin = True if int(bits[3]) else False,
                    dsn_len = mflg,
                    data_pre = Mflg,
                    ack_len = aflg,
                    ack_pre = Aflg,
                ),
                ack = ack_,
                dsn = dsn_,
                ssn = ssn_,
                dl_len = dll_,
                checksum = chk,
            ),
        )

        return data

    def _read_mptcp_add(self, bits, size, kind):
        """Read Add Address Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option
            kind - int, 30 (Multipath TCP)

        Structure of ADD_ADDR [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-------+---------------+
           |     Kind      |     Length    |Subtype| IPVer |  Address ID   |
           +---------------+---------------+-------+-------+---------------+
           |          Address (IPv4 - 4 octets / IPv6 - 16 octets)         |
           +-------------------------------+-------------------------------+
           |   Port (2 octets, optional)   |
           +-------------------------------+

            Octets          Bits            Name                        Discription
              0              0          tcp.mp.kind                 Kind (30)
              1              8          tcp.mp.length               Length
              2             16          tcp.mp.subtype              Subtype (3)
              2             20          tcp.mp.addaddr.ipver        IP Version
              3             24          tcp.mp.addaddr.addrid       Address ID
              4             32          tcp.mp.addaddr.addr         IP Address (4/16)
              8-20      64-160          tcp.mp.addaddr.port         Port (optional)

        """
        vers = int(bits, base=2)
        adid = self._read_unpack(1)
        ipad = self._read_addr_ipv4() if vers == 4 else self._read_addr_ipv6()
        ip_l = 4 if vers == 4 else 16
        pt_l = size - 1 - ip_l
        port = self._read_unpack(2) if pt_l else None

        data = dict(
            kind = kind,
            length = size + 1,
            subtype = 'ADD_ADDR',
            addaddr = dict(
                ipver = vers,
                addrid = adid,
                addr = ipad,
                port = port,
            ),
        )

        return data

    def _read_addr_ipv4(self):
        """Read IPv4 address."""
        byte = self._read_fileng(4)
        addr = '.'.join([str(_) for _ in byte])
        return addr

    def _read_addr_ipv6(self):
        """Read IPv6 address."""
        adlt = []       # list of IPv6 hexadecimal address
        ctr_ = collections.defaultdict(int)
                        # counter for consecutive groups of zero value
        ptr_ = 0        # start pointer of consecutive groups of zero value
        last = False    # if last hextet/group is zero value
        ommt = False    # ommitted flag, since IPv6 address can ommit to `::` only once

        for _ in range(8):
            hex_ = self._read_fileng(2).hex().lstrip('0')

            if hex_:    # if hextet is not '', directly append
                adlt.append(hex_)
                last = False
            else:       # if hextet is '', append '0'
                adlt.append('0')
                if last:    # if last hextet is '', ascend counter
                    ctr_[ptr_] += 1
                else:       # if last hextet is not '', record pointer
                    ptr_ = _
                    last = True
                    ctr_[ptr_] = 1

        ptr_ = max(ctr_, key=ctr_.get) if ctr_ else 0   # fetch start pointer with longest zero values
        end_ = ptr_ + ctr_[ptr_]                        # calculate end pointer

        if ctr_[ptr_] > 1:      # only ommit if zero values are in a consecutive group
            del adlt[ptr_:end_] # remove zero values

            if ptr_ == 0 and end_ == 8:     # insert `::` if IPv6 unspecified address (::)
                adlt.insert(ptr_, '::')
            elif ptr_ == 0 or end_ == 8:    # insert `:` if zero values are from start or at end
                adlt.insert(ptr_, ':')
            else:                           # insert '' otherwise
                adlt.insert(ptr_, '')

        addr = ':'.join(adlt)
        return addr

    def _read_mptcp_remove(self, bits, size):
        """Read Remove Address Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of REMOVE_ADDR [RFC 6824]:

                               1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-------+---------------+
           |     Kind      |  Length = 3+n |Subtype|(resvd)|   Address ID  | ...
           +---------------+---------------+-------+-------+---------------+
                                      (followed by n-1 Address IDs, if required)

            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype (4)
              2             20          tcp.opt.mp.removeaddr.res       Reserved (must be zero)
              3             24          tcp.opt.mp.removeaddr.addrid    Address ID (optional list)

        """
        adid = []
        for _ in size:
            adid.append(self._read_unpack(1))

        data = dict(
            subtype = 'REMOVE_ADDR',
            removeaddr = dict(
                res = b'\x00' * 4,
                addrid = adid or None,
            ),
        )

        return data

    def _read_mptcp_prio(self, bits, size):
        """Read Change Subflow Priority Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_PRIO [RFC 6824]:

                              1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----+-+--------------+
           |     Kind      |     Length    |Subtype|     |B| AddrID (opt) |
           +---------------+---------------+-------+-----+-+--------------+

            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (3/4)
              2             16          tcp.opt.mp.subtype              Subtype (5)
              2             23          tcp.opt.mp.prio.backup          Backup Path (B)
              3             24          tcp.opt.mp.prio.addrid          Address ID (optional)

        """
        temp = self._read_unpack(1) if size else None
        data = dict(
            subtype = 'MP_PRIO',
            prio = dict(
                res = b'\x00' * 3,
                backup = True if int(bits[3]) else False,
                addrid = temp,
            ),
        )
        return data

    def _read_mptcp_fail(self, bits, size):
        """Read Fallback Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_FAIL [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+----------------------+
           |     Kind      |   Length=12   |Subtype|      (reserved)      |
           +---------------+---------------+-------+----------------------+
           |                                                              |
           |                 Data Sequence Number (8 octets)              |
           |                                                              |
           +--------------------------------------------------------------+

            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (6)
              2             23          tcp.opt.mp.fail.res             Reserved (must be zero)
              4             32          tcp.opt.mp.fail.dsn             Data Sequence Number

        """
        resv = self._read_fileng(1)
        dsn_ = self._read_unpack(8)

        data = dict(
            subtype = 'MP_FAIL',
            fail = dict(
                res = b'\x00' * 12,
                dsn = dsn_,
            ),
        )

        return data

    def _read_mptcp_fastclose(self, bits, size):
        """Read Fast Close Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_FASTCLOSE [RFC 6824]:

                                1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+-------+-----------------------+
           |     Kind      |    Length     |Subtype|      (reserved)       |
           +---------------+---------------+-------+-----------------------+
           |                      Option Receiver's Key                    |
           |                            (64 bits)                          |
           |                                                               |
           +---------------------------------------------------------------+

            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (7)
              2             23          tcp.opt.mp.fastclose.res        Reserved (must be zero)
              4             32          tcp.opt.mp.fastclose.rkey       Option Receiver's Key

        """
        resv = self._read_fileng(1)
        rkey = self._read_fileng(8)

        data = dict(
            subtype = 'MP_FASTCLOSE',
            fastclose = dict(
                res = b'\x00' * 12,
                rkey = rkey,
            ),
        )

        return data

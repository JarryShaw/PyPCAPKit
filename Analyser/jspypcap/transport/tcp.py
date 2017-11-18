#!/usr/bin/python3
# -*- coding: utf-8 -*-


import struct


# Transmission Control Protocol
# Analyser for TCP header


# from transport import Transport


##############################################################################
# for unknown reason and never-encountered situation, at current time
# we have to change the working directory to import from parent folders

import os
import sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from protocol import Info, Protocol

del sys.path[1]

# and afterwards, we recover the whole scene back to its original state
##############################################################################


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

chksum_opt = {
    0:  'TCP checksum',
    1:  "8-bit Fletcher's algorithm",
    2:  "16-bit Fletcher's algorithm",
    3:  'Redundant Checksum Avoidance',
}

mptcp_opt = {
    0:  lambda self_, bits, size: self_._read_mptcp_capable(bits, size),    # MP_CAPABLE
    1:  lambda self_, bits, size: self_._read_mptcp_join(bits, size),       # MP_JOIN
    2:  lambda self_, bits, size: self_._read_mptcp_dss(bits, size),        # DSS
    3:  lambda self_, bits, size: self_._read_mptcp_add(bits, size),        # ADD_ADDR
    4:  lambda self_, bits, size: self_._read_mptcp_remove(bits, size),     # REMOVE_ADDR
    5:  lambda self_, bits, size: self_._read_mptcp_prio(bits, size),       # MP_PRIO
    6:  lambda self_, bits, size: self_._read_mptcp_fail(bits, size),       # MP_FAIL
    7:  lambda self_, bits, size: self_._read_mptcp_fastclose(bits, size),  # MP_FASTCLOSE
}

process_opt = {
    0:  lambda self_, size, name: self_._read_mode_donone(size, name),    # do nothing
    1:  lambda self_, size, name: self_._read_mode_unpack(size, name),    # unpack according to size
    2:  lambda self_, size, name: self_._read_mode_tsopt(size, name),     # Timestamps
    3:  lambda self_, size, name: self_._read_mode_pocsp(size, name),     # POC Service Profile
    4:  lambda self_, size, name: self_._read_mode_acopt(size, name),     # Alternate Checksum Request
    5:  lambda self_, size, name: self_._read_mode_qsopt(size, name),     # Quick-Start Response
    6:  lambda self_, size, name: self_._read_mode_utopt(size, name),     # User Timeout Option
    7:  lambda self_, size, name: self_._read_mode_tcpao(size, name),     # TCP Authentication Option
    8:  lambda self_, size, name: self_._read_mode_mptcp(size, name),     # Multipath TCP
}

TCP_OPT = {                         #   kind  length  type  process  comment            name
    0:  (F, 'eol'),                 #     0      -      -      -                End of Option List
    1:  (F, 'nop'),                 #     1      -      -      -                No-Operation
    2:  (T, 'mss', nm_len, 1),      #     2      4      H      1                Maximum Segment Size
    3:  (T, 'ws', nm_len, 1),       #     3      3      B      1                Window Scale
    4:  (T, 'sackpmt', nm_len),     #     4      2      ?      -       True     SACK Permitted
    5:  (T, 'sack', op_len, 0),     #     5      N      P      0      2+8*N     SACK
    6:  (T, 'echo', nm_len, 0),     #     6      6      P      0                Echo
    7:  (T, 'echore', nm_len, 0),   #     7      6      P      0                Echo Reply
    8:  (T, 'ts', nm_len, 2),       #     8     10     II      2                Timestamps
    9:  (T, 'poc', nm_len),         #     9      2      ?      -       True     POC Permitted
   10:  (T, 'pocsp', nm_len, 3),    #    10      3    ??P      3                POC Service Profile
   11:  (T, 'cc', nm_len, 0),       #    11      6      P      0                Connection Count
   12:  (T, 'ccnew', nm_len, 0),    #    12      6      P      0                CC.NEW
   13:  (T, 'ccecho', nm_len, 0),   #    13      6      P      0                CC.ECHO
   14:  (T, 'chkreq', nm_len, 4),   #    14      3      B      4                Alternate Checksum Request
   15:  (T, 'chksum', nm_len, 0),   #    15      N      P      0                Alternate Checksum Data
   19:  (T, 'sig', nm_len, 0),      #    19     18      P      0                MD5 Signature Option
   27:  (T, 'qs', nm_len, 5),       #    27      8      P      5                Quick-Start Response
   28:  (T, 'timeout', nm_len, 6),  #    28      4      P      6                User Timeout Option
   29:  (T, 'auth', nm_len, 7),     #    29      N      P      7                TCP Authentication Option
   30:  (T, 'mp', nm_len, 8),       #    30      N      P      8                Multipath TCP
   34:  (T, 'fastopen', nm_len, 0), #    34      N      P      0                Fast Open
}


class TCP(Protocol):

    __all__ = ['name', 'info', 'length', 'src', 'dst', 'layer']

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'Transmission Control Protocol'

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file):
        self._file = _file
        self._info = Info(self.read_tcp())

    def __len__(self):
        return self._info.hdr_len

    def __length_hint__(self):
        return 20

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
        _srcp = self.read_unpack(self._file, 2)
        _dstp = self.read_unpack(self._file, 2)
        _seqn = self.read_unpack(self._file, 4)
        _ackn = self.read_unpack(self._file, 4)
        _lenf = self.read_binary(self._file, 1)
        _flag = self.read_binary(self._file, 1)
        _wins = self.read_unpack(self._file, 2)
        _csum = self._file.read(2)
        _urgp = self.read_unpack(self._file, 2)

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

        self._syn = tcp['flags']['syn']
        self._ack = tcp['flags']['ack']

        _optl = tcp['hdr_len'] - 20
        if _optl:
            tcp['opt'] = self._read_tcp_options(_optl)
            # tcp['opt'] = self._file.read(_optl)

        return tcp

    def _read_tcp_options(self, _optl):
        counter = 0     # length of read option list
        options = dict( # dict of option data
            kind = [],      # option kind list
            length = {},    # option length dict
        )
        while counter < _optl:
            # get option kind
            kind = self.read_unpack(self._file, 1)

            # fetch corresponding option tuple
            opts = TCP_OPT.get(kind)
            if opts is None:
                len_ = _optl - counter
                options['Unknown'] = self._file.read(len_)
                break

            # extract option
            dscp = opts[1]
            if opts[0]:
                len_ = self.read_unpack(self._file, 1)
                byte = opts[2](len_)
                if byte:    # check option process mode
                    data = process_opt[opts[3]](self, byte, dscp)
                else:       # permission options (length is 2)
                    data = True
            else:           # 1-bytes options
                len_ = 1
                data = True

            # record option data
            counter += len_
            options[dscp] = data
            options['kind'].append(kind)
            options['length'].update({kind: len_})

            # break when eol triggered
            if not kind:    break

        return options

    def _read_mode_donone(self, size, name):
        """Read options request no process.

        Keyword arguemnts:
            size - int, length of option
            name - str, acronym of option

        Structure of TCP ACopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (14)
              1              8          tcp.opt.length                  Length (3)
              2             16          tcp.opt.data                    Kind-specific Data

        """
        data = self._file.read(size)
        return data

    def _read_mode_unpack(self, size, name):
        """Read options request unpack process.

        Keyword arguemnts:
            size - int, length of option
            name - str, acronym of option

        Structure of TCP ACopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (14)
              1              8          tcp.opt.length                  Length (3)
              2             16          tcp.opt.data                    Kind-specific Data

        """
        data = self.read_unpack(self._file, size)
        return data

    def _read_mode_tsopt(self, size, *args):
        """Read Timestamps option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP TSopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (8)
              1              8          tcp.opt.length                  Length (10)
              2             16          tcp.opt.ts.val                  Timestamp Value
              6             48          tcp.opt.ts.ecr                  Timestamps Echo Reply

        """
        temp = struct.unpack('>II', self._file.read(size))
        data = dict(
            val = temp[0],
            ecr = temp[1],
        )
        return data

    def _read_mode_pocsp(self, size, *args):
        """Read Partial Order Connection Service Profile Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP POC-SP Option:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (10)
              1              8          tcp.opt.length                  Length (3)
              2             16          tcp.opt.pocsp.start             Start Flag
              2             17          tcp.opt.pocsp.end               End Flag
              2             18          tcp.opt.pocsp.filler            Filler

        """
        temp = self.read_binary(self._file, size)

        data = dict(
            start = True if int(temp[0]) else False,
            end = True if int(temp[1]) else False,
            filler = bytes(temp[2:], encoding='utf-8'),
        )

        return data

    def _read_mode_acopt(self, size, *args):
        """Read Alternate Checksum Request Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP CHKSUM-REQ:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (14)
              1              8          tcp.opt.length                  Length (3)
              2             16          tcp.opt.chksumreq               Checksum Algorithm

        """
        temp = self.read_unpack(self._file, size)
        algo = chksum_opt.get(temp)

        data = dict(
            ac = algo,
        )

        return data

    def _read_mode_qsopt(self, size, *args):
        """Read Quick-Start Response Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP QSopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (27)
              1              8          tcp.opt.length                  Length (8)
              2             16          tcp.opt.qs.resv                 Reserved (must be zero)
              2             20          tcp.opt.qs.req_rate             Request Rate
              3             24          tcp.opt.qs.ttl_diff             TTL Difference
              4             32          tcp.opt.qs.nounce               QS Nounce
              7             62          tcp.opt.qs.res                  Reserved (must be zero)

        """
        rvrr = self.read_binary(self._file, 1)
        ttld = self.read_unpack(self._file, 1)
        noun = self._file.read(4)

        data = dict(
            resv = b'\x00' * 4,
            req_rate = int(rvrr[4:], base=2),
            ttl_diff = ttld,
            nounce = noun[:-2],
            res = b'\x00\x00',
        )

        return data

    def _read_mode_utopt(self, size, *args):
        """Read User Timeout Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP TIMEOUT:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (28)
              1              8          tcp.opt.length                  Length (4)
              2             16          tcp.opt.timeout.granularity     Granularity
              2             17          tcp.opt.timeout.timeout         User Timeout

        """
        temp = self._file.read(size)

        data = dict(
            granularity = 'minutes' if int(temp[0]) else 'seconds',
            timeout = bytes(temp[0:], encoding='utf-8'),
        )

        return data

    def _read_mode_tcpao(self, size, *args):
        """Read Authentication Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP AUTH:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (29)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.auth.keyid              KeyID
              3             24          tcp.opt.auth.rnextkeyid         RNextKeyID
              4             32          tcp.opt.auth.mac                Message Authentication Code

        """
        key_ = self.read_unpack(self._file, 1)
        rkey = self.read_unpack(self._file, 1)
        mac_ = self._file.read(size - 2)

        data = dict(
            keyid = key_,
            rnextkeyid = rkey,
            mac = mac_,
        )

        return data

    def _read_mode_mptcp(self, size, *args):
        """Read Multipath TCP Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of MP-TCP:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype
              2             20          tcp.opt.mp.data                 Subtype-specific Data

        """
        bins = self.read_binary(self._file, 1)
        subt = int(bins[:4], base=2)    # subtype number
        bits = bins[4:]                 # 4-bit data
        dlen = size - 1                 # length of remaining data

        # fetch subtype-specific data
        func = mptcp_opt.get(subt)
        if func is None:    # if subtype not exist, directly read all data
            temp = self._file.read(dlen)
            data = dict(
                subtype = 'Unknown',
                data = bytes(bits[:4], encoding='utf-8') + temp,
            )
        else:               # fetch corresponding subtype data dict
            data = func(self, bits, dlen)
        return data

    def _read_mptcp_capable(self, bits, size):
        """Read Multipath Capable Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_CAPABLE:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12/20)
              2             16          tcp.opt.mp.subtype              Subtype (0)
              2             20          tcp.opt.mp.capable.version      Version
              3             24          tcp.opt.mp.capable.flags.req    Checksum Require Flag (A)
              3             25          tcp.opt.mp.capable.flags.ext    Extensibility Flag (B)
              3             26          tcp.opt.mp.capable.flags.res    Unassigned (C-G)
              3             31          tcp.opt.mp.capable.flags.hsa    HMAC-SHA1 Flag (H)
              4             32          tcp.opt.mp.capable.skey         Option Sender's Key
              12            96          tcp.opt.mp.capable.rkey         Option Receiver's Key
                                                                        (if option Length == 20)

        """
        vers = int(bits, base=2)
        bins = self.read_binary(self._file, 1)
        skey = self._file.read(8)
        rkey = self._file.read(8) if size == 17 else None

        data = dict(
            subtype = 'MP_CAPABLE',
            capable = dict(
                version = vers,
                flags = dict(
                    req = True if int(bins[0]) else False,
                    ext = True if int(bins[1]) else False,
                    res = bytes(bins[2:7], encoding='utf-8'),
                    hsa = True if int(bins[7]) else False,
                ),
                skey = skey,
                rkey = rkey,
            ),
        )

        return data

    def _read_mptcp_join(self, bits, size):
        """Read Join Connection Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_JOIN:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype (1)
              2             20          tcp.opt.mp.data                 Handshake-specific Data

        """
        if self._syn and self._ack: # MP_JOIN-SYN/ACK
            return self._read_join_synack(bits, size)
        elif self._syn:             # MP_JOIN-SYN
            return self._read_join_syn(bits, size)
        elif self._ack:             # MP_JOIN-ACK
            return self._read_join_ack(bits, size)
        else:
            return {}

    def _read_join_syn(self, bits, size):
        """Read Join Connection Option for Initial SYN.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_JOIN-SYN:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (1|SYN)
              2             20          tcp.opt.mp.join.syn.res         Reserved (must be zero)
              2             23          tcp.opt.mp.join.syn.backup      Backup Path (B)
              3             24          tcp.opt.mp.join.syn.addrid      Address ID
              4             32          tcp.opt.mp.join.syn.token       Receiver's Token
              8             64          tcp.opt.mp.join.syn.randnum     Sender's Random Number

        """
        adid = self.read_unpack(self._file, 1)
        rtkn = self._file.read(4)
        srno = self.read_unpack(self._file, 4)

        data = dict(
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

    def _read_join_synack(self, bits, size):
        """Read Join Connection Option for Responding SYN/ACK.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_JOIN-SYN/ACK:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (16)
              2             16          tcp.opt.mp.subtype              Subtype (1|SYN/ACK)
              2             20          tcp.opt.mp.join.synack.res      Reserved (must be zero)
              2             23          tcp.opt.mp.join.synack.backup   Backup Path (B)
              3             24          tcp.opt.mp.join.synack.addrid   Address ID
              4             32          tcp.opt.mp.join.synack.hmac     Sender's Truncated HMAC
              12            96          tcp.opt.mp.join.synack.randnum  Sender's Random Number

        """
        adid = self.read_unpack(self._file, 1)
        hmac = self._file.read(8)
        srno = self.read_unpack(self._file, 4)

        data = dict(
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

    def _read_join_ack(self, bits, size):
        """Read Join Connection Option for Third ACK.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_JOIN-ACK:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (24)
              2             16          tcp.opt.mp.subtype              Subtype (1|ACK)
              2             20          tcp.opt.mp.join.ack.res         Reserved (must be zero)
              4             32          tcp.opt.mp.join.ack.hmac        Sender's HMAC

        """
        temp = self._file.read(20)
        data = dict(
            subtype = 'MP_JOIN-ACK',
            join = dict(
                ack = dict(
                    res = b'\x00' * 12,
                    hmac = temp,
                ),
            ),
        )

        return data

    def _read_mptcp_dss(self, bits, size):
        """Read Data Sequence Signal (Data ACK and Data Sequence Mapping) Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of DSS:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype (2)
              2             20          tcp.opt.mp.dss.flags.res        Reserved (must be zero)
              3             27          tcp.opt.mp.dss.flags.fin        DATA_FIN (F)
              3             28          tcp.opt.mp.dss.flags.dsn_len    DSN Length (m)
              3             29          tcp.opt.mp.dss.flags.data_pre   DSN, SSN, Data-Level Length, CHKSUM Present (M)
              3             30          tcp.opt.mp.dss.flags.ack_len    ACK Length (a)
              3             31          tcp.opt.mp.dss.flags.ack_pre    Data ACK Present (A)
              4             32          tcp.opt.mp.dss.ack              Data ACK (4/8 octets)
              8-12       64-96          tcp.opt.mp.dss.dsn              DSN (4/8 octets)
              12-20     48-160          tcp.opt.mp.dss.ssn              Subflow Sequence Number
              16-24    128-192          tcp.opt.mp.dss.dl_len           Data-Level Length
              18-26    144-208          tcp.opt.mp.dss.checksum         Checksum

        """
        bits = self.read_binary(self._file, 1)
        mflg = 8 if int(bits[4]) else 4
        Mflg = True if int(bits[5]) else False
        aflg = 8 if int(bits[6]) else 4
        Aflg = True if int(bits[7]) else False
        ack_ = self._file.read(aflg) if Aflg else None
        dsn_ = self.read_unpack(self._file, mflg) if Mflg else None
        ssn_ = self.read_unpack(self._file, 4) if Mflg else None
        dll_ = self.read_unpack(self._file, 2) if Mflg else None
        chk_ = self._file.read(2) if Mflg else None

        data = dict(
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

    def _read_mptcp_add(self, bits, size):
        """Read Add Address Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of ADD_ADDR:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype (3)
              2             20          tcp.opt.mp.addaddr.ipver        IP Version
              3             24          tcp.opt.mp.addaddr.addrid       Address ID
              4             32          tcp.opt.mp.addaddr.addr         IP Address (4/16)
              8-20      64-160          tcp.opt.mp.addaddr.port         Port (optional)

        """
        vers = int(bits, base=2)
        adid = self.read_unpack(self._file, 1)
        ipad = self._read_addr_ipv4() if vers == 4 else self._read_addr_ipv6()
        ip_l = 4 if vers == 4 else 16
        pt_l = size - 1 - ip_l
        port = self.read_unpack(self._file, 2) if pt_l else None

        data = dict(
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
        byte = self._file.read(4)
        addr = '.'.join([str(_) for _ in byte])
        return addr

    def _read_addr_ipv6(self):
        adlt = []       # list of IPv6 hexadecimal address
        ctr_ = {}       # counter for consecutive groups of zero value
        ptr_ = 0        # start pointer of consecutive groups of zero value
        last = False    # if last hextet/group is zero value
        ommt = False    # ommitted flag, since IPv6 address can ommit to `::` only once

        for _ in range(8):
            hex_ = _file.read(2).hex().lstrip('0')

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

        ptr_ = max(ctr_, key=ctr_.get)  # fetch start pointer with longest zero values
        end_ = ptr_ + ctr_[ptr_]        # calculate end pointer

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

        Structure of REMOVE_ADDR:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length
              2             16          tcp.opt.mp.subtype              Subtype (4)
              2             20          tcp.opt.mp.removeaddr.res       Reserved (must be zero)
              3             24          tcp.opt.mp.removeaddr.addrid    Address ID (optional list)

        """
        adid = []
        for _ in size:
            adid.append(self.read_unpack(self._file, 1))

        data = dict(
            subtype = 'REMOVE_ADDR',
            removeaddr = dict(
                res = b'\x00' * 4,
                addrid = adid if adid else None,
            ),
        )

        return data

    def _read_mptcp_prio(self, bits, size):
        """Read Change Subflow Priority Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP_PRIO:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (3/4)
              2             16          tcp.opt.mp.subtype              Subtype (5)
              2             23          tcp.opt.mp.prio.backup          Backup Path (B)
              3             24          tcp.opt.mp.prio.addrid          Address ID (optional)

        """
        temp = self.read_unpack(self._file, 1) if size else None
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

        Structure of MP_FAIL:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (6)
              2             23          tcp.opt.mp.fail.res             Reserved (must be zero)
              4             32          tcp.opt.mp.fail.dsn             Data Sequence Number

        """
        resv = self._file.read(1)
        dsn_ = self.read_unpack(self._file, 8)

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

        Structure of MP_FASTCLOSE:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.kind                    Kind (30)
              1              8          tcp.opt.length                  Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (7)
              2             23          tcp.opt.mp.fastclose.res        Reserved (must be zero)
              4             32          tcp.opt.mp.fastclose.rkey       Option Receiver's Key

        """
        resv = self._file.read(1)
        rkey = self._file.read(8)

        data = dict(
            subtype = 'MP_FASTCLOSE',
            fastclose = dict(
                res = b'\x00' * 12,
                rkey = rkey,
            ),
        )

        return data

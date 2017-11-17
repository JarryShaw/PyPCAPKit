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


"""TCP Option Table

tuple contains:
    |--> bool, if length greater than 1
    |--> str, description string
    |--> (optional) function, length of data bytes
    |--> (optional) int, process that data bytes need (when length greater than 2)
            |--> 0: do nothing
            |--> 1: unpack according to size
            |--> 2: unpack TSopt then add to dict
            |--> 3: unpack POC-SP then add to dict
            |--> 4: unpack ACopt then fetch algorithm
            |--> 5: unpack QSopt then add to dict
            |--> 6: unpack UTopt then add to dict
            |--> 7: unpack TCP-AO then add tot dict
            |--> 8: unpack MPTCP then add to dict

"""

T = True
F = False

nm_len = lambda n: n - 2
op_len = lambda n: n * 8

chksum_opt = {
    0:  'TCP checksum',
    1:  "8-bit  Fletcher's algorithm",
    2:  "16-bit Fletcher's algorithm",
    3:  'Redundant Checksum Avoidance',
}

mptcp_opt = {
    0:  lambda self_, flag, size: self_._read_mptcp_capable(bits, size),
    1:  lambda self_, flag, size: self_._read_mptcp_join(bits, size),
    2:  lambda self_, flag, size: self_._read_mptcp_dss(bits, size),
    3:  lambda self_, flag, size: self_._read_mptcp_add(bits, size),
    4:  lambda self_, flag, size: self_._read_mptcp_remove(bits, size),
    5:  lambda self_, flag, size: self_._read_mptcp_prio(bits, size),
    6:  lambda self_, flag, size: self_._read_mptcp_fail(bits, size),
    7:  lambda self_, flag, size: self_._read_mptcp_fastclose(bits, size),
}

process_opt = {
    0:  lambda self_, size: self_._read_mode_donone(size),
    1:  lambda self_, size: self_._read_mode_unpack(size),
    2:  lambda self_, size: self_._read_mode_tsopt(size),
    3:  lambda self_, size: self_._read_mode_pocsp(size),
    4:  lambda self_, size: self_._read_mode_acopt(size),
    5:  lambda self_, size: self_._read_mode_qsopt(size),
    6:  lambda self_, size: self_._read_mode_utopt(size),
    7:  lambda self_, size: self_._read_mode_tcpao(size),
    8:  lambda self_, size: self_._read_mode_mptcp(size),
}

TCP_OPT = {                                             #   kind  length  type  process  comment
    0:  (F, 'End of Option List'),                      #     0      -      -      -
    1:  (F, 'No-Operation'),                            #     1      -      -      -
    2:  (T, 'Maximum Segment Size', nm_len, 1),         #     2      4      H      1
    3:  (T, 'Window Scale', nm_len, 1),                 #     3      3      B      1
    4:  (T, 'SACK Permitted', nm_len),                  #     4      2      ?      -       True
    5:  (T, 'SACK', op_len, 0),                         #     5      N      P      0      2+8*N
    6:  (T, 'Echo', nm_len, 0),                         #     6      6      P      0
    7:  (T, 'Echo Reply', nm_len, 0),                   #     7      6      P      0
    8:  (T, 'Timestamps', nm_len, 2),                   #     8     10     II      2
    9:  (T, 'POC Permitted', nm_len),                   #     9      2      ?      -       True
   10:  (T, 'POC Service Profile', nm_len, 3),          #    10      3    ??P      3
   11:  (T, 'Connection Count', nm_len, 0),             #    11      6      P      0
   12:  (T, 'CC.NEW', nm_len, 0),                       #    12      6      P      0
   13:  (T, 'CC.ECHO', nm_len, 0),                      #    13      6      P      0
   14:  (T, 'Alternate Checksum Request', nm_len, 4),   #    14      3      B      4
   15:  (T, 'Alternate Checksum Data', nm_len, 0),      #    15      N      P      0
   19:  (T, 'MD5 Signature Option', nm_len, 0),         #    19     18      P      0
   27:  (T, 'Quick-Start Response', nm_len, 5),         #    27      8      P      5
   28:  (T, 'User Timeout Option', nm_len, 6),          #    28      4      P      6
   29:  (T, 'TCP Authentication Option', nm_len, 7),    #    29      N      P      7
   30:  (T, 'Multipath TCP', nm_len, 8),                #    30      N      P      8
   34:  (T, 'Fast Open', nm_len, 0),                    #    34      N      P      0
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

        self._syn = tcp['syn']
        self._ack = tcp['ack']

        _optl = tcp['hdr_len'] - 20
        if _optl:
            tcp['opt'] = self._read_tcp_options(_optl)

        return tcp

    def _read_tcp_options(self, _optl):
        counter = 0     # length of read option list
        options = {}    # dict of option data
        while counter < _optl:
            # get option kind (quit when end of option list)
            kind = self.read_unpack(self._file, 1)
            if kind == 0:   break

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
                    data = process_opt[opts[3]](self, byte)
                else:       # permission options (length is 2)
                    data = True
            else:           # 1-bytes options
                len_ = 1
                data = None

            # record option data
            counter += len_
            options[kind] = data
        return options

    def _read_mode_donone(self, size):
        data = self._file.read(size)
        return data

    def _read_mode_unpack(self, size):
        data = self.read_unpack(self._file, size)
        return data

    def _read_mode_tsopt(self, size):
        """Read Timestamps option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP TSopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.ts.kind                 Kind (8)
              1              8          tcp.opt.ts.length               Length (10)
              2             16          tcp.opt.ts.val                  Timestamp Value
              6             48          tcp.opt.ts.ecr                  Timestamps Echo Reply

        """
        temp = struct.unpack('>II', self._file.read(size))
        data = dict(
            val = temp[0],
            ecr = temp[1],
        )
        return data

    def _read_mode_pocsp(self, size):
        """Read Partial Order Connection Service Profile Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP POC-SP Option:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.sp.kind                 Kind (10)
              1              8          tcp.opt.sp.length               Length (3)
              2             16          tcp.opt.sp.start                Start Flag
              2             17          tcp.opt.sp.end                  End Flag
              2             18          tcp.opt.sp.filler               Filler

        """
        temp = self.read_binary(self._file, size)
        data = dict(
            start = True if int(temp[0]) else False,
            end = True if int(temp[1]) else False,
            filler = bytes(temp[2:], encoding='utf-8'),
        )
        return data

    def _read_mode_acopt(self, size):
        temp = self.read_unpack(self._file, size)
        data = chksum_opt.get(temp)
        return data

    def _read_mode_qsopt(self, size):
        """Read Quick-Start Response Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP QSopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.qs.kind                 Kind (27)
              1              8          tcp.opt.qs.length               Length (8)
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
            req_rate = int(rvrr[4:]),
            ttl_diff = ttld,
            nounce = noun[:-2],
            res = b'\x00\x00',
        )

        return data

    def _read_mode_utopt(self, size):
        """Read User Timeout Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP USopt:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.ut.kind                 Kind (28)
              1              8          tcp.opt.ut.length               Length (4)
              2             16          tcp.opt.ut.granularity          Granularity
              2             17          tcp.opt.ut.timeout              User Timeout

        """
        temp = self._file.read(size)

        data = dict(
            granularity = 'minutes' if int(temp[0]) else 'seconds'
            timeout = bytes(temp[0:], encoding='utf-8')
        )

        return data

    def _read_mode_tcpao(self, size):
        """Read Authentication Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of TCP TCP-AO:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.ao.kind                 Kind (29)
              1              8          tcp.opt.ao.length               Length
              2             16          tcp.opt.ao.keyid                KeyID
              3             24          tcp.opt.ao.rnextkeyid           RNextKeyID
              4             32          tcp.opt.ao.mac                  Message Authentication Code

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

    def _read_mode_mptcp(self, size):
        """Read Multipath TCP Option.

        Keyword arguemnts:
            size - int, length of option

        Structure of MP-TCP:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length
              2             16          tcp.opt.mp.subtype              Subtype
              2             20          tcp.opt.mp.data                 Subtype-specific Data

        """
        bins = self.read_binary(self._file, 1)
        sbtp = int(bins[:4], base=2)    # subtype number
        bits = bins[4:]                 # 4-bit data
        dlen = size - 1                 # length of remaining data

        # fetch subtype-specific data
        data = mptcp_opt[sbtp](self, bits, dlen)
        return data

    def _read_mptcp_capable(self, bits, size):
        """Read Multipath Capable Option.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP-CAPABLE:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length (12/20)
              2             16          tcp.opt.mp.subtype              Subtype (MP-CAPABLE)
              2             20          tcp.opt.mp.capable.version      Version
              3             24          tcp.opt.mp.capable.flags.req    A - Checksum Require Flag
              3             25          tcp.opt.mp.capable.flags.ext    B - Extensibility Flag
              3             26          tcp.opt.mp.capable.flags.res    Unassigned (C-G)
              3             31          tcp.opt.mp.capable.flags.hsa    H - HMAC-SHA1 Flag
              4             32          tcp.opt.mp.capable.skey         Option Sender's Key
              12            96          tcp.opt.mp.capable.rkey         Option Receiver's Key
                                                                        (if option Length == 20)

        """
        vers = bits
        bins = self.read_binary(self._file, 1)
        skey = self._file.read(8)
        rkey = self._file.read(8) if size == 17 else None

        data = dict(
            subtype = 'MP-CAPABLE',
            capable = dict(
                version = int(vers, base=2),
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

        """
        if self._syn and self._ack: # MP-JOIN.SYN/ACK
            return self._read_join_synack(bits, size)
        elif self._syn:             # MP-JOIN.SYN
            return self._read_join_syn(bits, size)
        elif self._ack:             # MP-JOIN.ACK
            return self._read_join_ack(bits, size)
        else:
            return None

    def _read_join_syn(self, bits, size):
        """Read Join Connection Option for Initial SYN.

        Keyword arguemnts:
            bits - str, 4-bit data
            size - int, length of option

        Structure of MP-JOIN-SYN:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length (12)
              2             16          tcp.opt.mp.subtype              Subtype (MP-JOIN.SYN)
              2             20          tcp.opt.mp.join.syn.res         Reserved (must be zero)
              2             23          tcp.opt.mp.join.syn.backup      Backup Path (flag)
              3             24          tcp.opt.mp.join.syn.addid       Address ID
              4             32          tcp.opt.mp.join.syn.token       Receiver's Token
              8             64          tcp.opt.mp.join.syn.randnum     Sender's Random Number

        """
        adid = self.read_unpack(self._file, 1)
        rtkn = self._file.read(4)
        srno = self.read_unpack(self._file, 4)

        data = dict(
            subtype = 'MP-JOIN.SYN',
            join = dict(
                syn = dict(
                    res = b'\x00\x00\x00',
                    backup = True if int(bits[3]) else False,
                    addid = adid,
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

        Structure of MP-JOIN-SYNACK:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length (16)
              2             16          tcp.opt.mp.subtype              Subtype (MP-JOIN.SYN/ACK)
              2             20          tcp.opt.mp.join.synack.res      Reserved (must be zero)
              2             23          tcp.opt.mp.join.synack.backup   Backup Path (flag)
              3             24          tcp.opt.mp.join.synack.addid    Address ID
              4             32          tcp.opt.mp.join.synack.hmac     Sender's Truncated HMAC
              12            96          tcp.opt.mp.join.synack.randnum  Sender's Random Number

        """
        adid = self.read_unpack(self._file, 1)
        hmac = self._file.read(8)
        srno = self.read_unpack(self._file, 4)

        data = dict(
            subtype = 'MP-JOIN.SYN/ACK',
            join = dict(
                synack = dict(
                    res = b'\x00\x00\x00',
                    backup = True if int(bits[3]) else False,
                    addid = adid,
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

        Structure of MP-JOIN-ACK:
            Octets          Bits            Name                            Discription
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length (24)
              2             16          tcp.opt.mp.subtype              Subtype (MP-JOIN.ACK)
              2             20          tcp.opt.mp.join.ack.res         Reserved (must be zero)
              4             32          tcp.opt.mp.join.ack.hmac        Sender's HMAC

        """
        temp = self._file.read(20)
        data = dict(
            subtype = 'MP-JOIN.ACK',
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
              0              0          tcp.opt.mp.kind                 Kind (30)
              1              8          tcp.opt.mp.length               Length
              2             16          tcp.opt.mp.subtype              Subtype (DSS)
              2             20          tcp.opt.mp.dss.flags.res        Reserved (must be zero)
              3             27          tcp.opt.mp.dss.flags.fin        DATA_FIN (F)
              3             28          tcp.opt.mp.dss.flags.dsn_len    DSN Length (m)
              3             29          tcp.opt.mp.dss.flags.data_pre   DSN, SSN, Data-Level Length,
                                                                        and Checksum Present (M)
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
        dsn_ = self._file.read(mflg) if Mflg else None
        ssn_ = self._file.read(4) if Mflg else None
        dll_ = self._file.read(2) if Mflg else None
        chk_ = self._file.read(2) if Mflg else None

        data = dict(
            subtype = 'DSS'
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
        pass

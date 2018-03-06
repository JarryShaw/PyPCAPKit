#!/usr/bin/python3
# -*- coding: utf-8 -*-


import copy
import sys


# Reassembly TCP Datagram
# Reconstruct application layer packets


from jspcap.utilities import Info
from jspcap.reassembly.reassembly import Reassembly


__all__ = ['TCP_Reassembly']


class TCP_Reassembly(Reassembly):
    """Reassembly for TCP payload.

    The following algorithm implementment is based on `IP Datagram
    Reassembly Algorithm` introduced in RFC 815. It descripted an
    algorithm dealing with `RCVBT` (fragment received bit table)
    appeared in RFC 791. And here is the process:

    1. Select the next hole descriptor from the hole descriptor
      list. If there are no more entries, go to step eight.
    2. If fragment.first is greater than hole.last, go to step one.
    3. If fragment.last is less than hole.first, go to step one.
    4. Delete the current entry from the hole descriptor list.
    5. If fragment.first is greater than hole.first, then create a
      new hole descriptor "new_hole" with new_hole.first equal to
      hole.first, and new_hole.last equal to fragment.first  minus
      one.
    6. If fragment.last is less than hole.last and fragment.more
      fragments is true, then create a new hole descriptor
      "new_hole", with new_hole.first equal to fragment.last plus
      one and new_hole.last equal to hole.last.
    7. Go to step one.
    8. If the hole descriptor list is now empty, the datagram is now
      complete. Pass it on to the higher level protocol processor
      for further handling. Otherwise, return.

    Usage:
        >>> from reassembly import TCP_Reassembly
        # Initialise instance:
        >>> tcp_reassembly = TCP_Reassembly()
        # Call reassembly:
        >>> tcp_reassembly(packet_dict)
        # Fetch result:
        >>> result = tcp_reassembly.datagram

    Terminology:
     - packet_dict = dict(
            bufid = tuple(
                ip.src,                     # source IP address
                ip.dst,                     # destination IP address
                tcp.srcport,                # source port
                tcp.dstport,                # destination port
            ),
            num = frame.number,             # original packet range number
            ack = tcp.ack,                  # acknowledgement
            dsn = tcp.seq,                  # data sequence number
            syn = tcp.flags.syn,            # synchronise flag
            fin = tcp.flags.fin,            # finish flag
            len = tcp.raw_len,              # payload length, header excludes
            first = tcp.seq,                # this sequence number
            last = tcp.seq + tcp.raw_len,   # next (wanted) sequence number
            payload = tcp.raw,              # raw bytearray type payload
       )
     - (tuple) datagram
           |--> (dict) data
           |       |--> 'NotImplemented' : (bool) True --> implemented
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (bytes/None) reassembled application layer data
           |--> (dict) data
           |       |--> 'NotImplemented' : (bool) False --> not implemented
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (tuple/None) partially reassembled payload
           |                        |--> (bytes/None) payload fragment
           |--> (dict) data ...
     - (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> ip.dst      |
           |       |--> tcp.secport |
           |       |--> tcp.dstport |
           |                        |--> 'hdl' : (list) hole descriptor list
           |                        |               |--> (Info) hole --> hole descriptor
           |                        |                       |--> "first" --> (int) start of hole
           |                        |                       |--> "last" --> (int) stop ofhole
           |                        |--> (int) ACK : (dict)
           |                        |               |--> 'ind' : (list) list of reassembled packets
           |                        |               |               |--> (int) packet range number
           |                        |               |--> 'isn' : (int) ISN of payload buffer
           |                        |               |--> 'len' : (int) length of payload buffer
           |                        |               |--> 'raw' : (bytearray) reassembled payload,
           |                        |                               holes set to b'\x00'
           |                        |--> (int) ACK ...
           |                        |--> ...
           |--> (tuple) BUFID ...

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    @property
    def name(self):
        return 'Transmission Control Protocol'

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info):
        BUFID = info.bufid  # Buffer Identifier
        DSN = info.dsn      # Data Sequence Number
        ACK = info.ack      # Acknowledgement Number
        FIN = info.fin      # Finish Flag (Termination)
        SYN = info.syn      # Synchronise Flag (Establishment)

        # when SYN is set, reset buffer of this session
        # initialise buffer with BUFID & ACK then recurse
        if SYN or BUFID not in self._buffer:
            self._buffer[BUFID] = {
                'hdl' : [Info(dict(first=info.len, last=sys.maxsize)),],
                ACK : dict(
                    ind = list(),
                    isn = info.dsn,
                    len = info.len,
                    raw = info.payload,
                ),
            }
            return

        # initialise buffer with ACK
        if ACK not in self._buffer[BUFID]:
            self._buffer[BUFID][ACK] = dict(
                ind = list(),
                isn = info.dsn,
                len = info.len,
                raw = info.payload,
            )

        # append packet index
        self._buffer[BUFID][ACK]['ind'].append(info.num)

        # record fragment payload
        ISN = self._buffer[BUFID][ACK]['isn']   # Initial Sequence Number
        RAW = self._buffer[BUFID][ACK]['raw']   # Raw Payload Data
        if DSN >= ISN:  # if fragment goes after exsisting payload
            LEN = self._buffer[BUFID][ACK]['len']
            GAP = DSN - (ISN + LEN)     # gap length between payloads
            if GAP >= 0:    # if fragment goes after exsisting payload
                RAW += bytearray(GAP) + info.payload
            else:           # if fragment partially overlaps exsisting payload
                RAW[DSN-ISN:] = info.payload
        else:           # if fragment exceeds exsisting payload
            LEN = info.len
            GAP = ISN - (DSN + LEN)     # gap length between payloads
            self._buffer[BUFID][ACK]['isn'] = DSN
            if GAP >= 0:    # if fragment exceeds exsisting payload
                RAW = info.payload + bytearray(GAP) + RAW
            else:           # if fragment partially overlaps exsisting payload
                RAW = info.payload + RAW[ISN-GAP:]
        self._buffer[BUFID][ACK]['raw'] = RAW       # update payload datagram
        self._buffer[BUFID][ACK]['len'] = len(RAW)  # update payload length

        # update hole descriptor list
        HDL = copy.deepcopy(self._buffer[BUFID]['hdl'])
        for (index, hole) in enumerate(self._buffer[BUFID]['hdl']): # step one
            if info.first > hole.last:                              # step two
                continue
            if info.last < hole.first:                              # step three
                continue
            del HDL[index]                                          # step four
            if info.first > hole.first:                             # step five
                new_hole = Info(dict(
                    first = hole.first,
                    last = info.first - 1,
                ))
                HDL.insert(index, new_hole)
            if info.last < hole.last and not FIN:                   # step six
                new_hole = Info(dict(
                    first = info.last + 1,
                    last = hole.last
                ))
                HDL.insert(index+1, new_hole)
            break                                                   # step seven
        self._buffer[BUFID]['hdl'] = HDL                            # update HDL

        # when FIN is set, submit buffer of this session
        if FIN:
            self._dtgram += self.submit(self._buffer[BUFID])
            del self._buffer[BUFID]

    def submit(self, buf):
        datagram = []           # reassembled datagram
        HDL = buf.pop('hdl')    # hole descriptor list (remove from dict)

        # check through every buffer with ACK
        for buffer in buf.values():
            # if this buffer is not implemented
            # go through every hole and extract received payload
            if len(HDL) > 2:
                data = []
                start = stop = 0
                for hole in HDL:
                    stop = hole.first
                    byte = buffer['raw'][start:stop]
                    start = hole.last
                    if byte:    # strip empty payload
                        data.append(byte)
                byte = buffer['raw'][start:]
                if byte:    # strip empty payload
                    data.append(byte)
                if data:    # strip empty buffer
                    packet = Info(dict(
                        NotImplemented = True,
                        index = tuple(buffer['ind']),
                        payload = tuple(data) or None,
                    ))
                    datagram.append(packet)
            # if this buffer is implemented
            # export payload data & convert into bytes
            else:
                data = buffer['raw']
                if data:    # strip empty buffer
                    packet = Info(dict(
                        NotImplemented = False,
                        index = tuple(buffer['ind']),
                        payload = bytes(data) or None,
                    ))
                    datagram.append(packet)
        return tuple(datagram)

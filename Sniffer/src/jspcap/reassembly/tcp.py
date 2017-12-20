#!/usr/bin/python3
# -*- coding: utf-8 -*-


import copy
import sys


# Reassembly TCP Datagram
# Reconstruct application layer packets


from .reassembly import Reassembly
from ..protocols import Info


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

    Terminology:
     - info : list, contains TCP fragments
        |--> fragment : Info, utitlity for reassembly
        |       |--> bufid : tuple, unique seesion descriptor
        |       |       |--> ip.src : source IP address
        |       |       |--> tcp.srcport : source TCP port
        |       |       |--> ip.dst : destination IP address
        |       |       |--> tcp.dstport : destination TCP port
        |       |--> tcp : Info, extracted TCP infomation
        |       |--> raw : bytearray, raw TCP payload
        |       |--> first : int, DSN of current TCP, i.e. tcp.seq
        |       |--> last : int, DSN of next TCP
        |       |--> len : int, length of raw TCP payload
        |--> fragment ...
        |--> ...
     - buffer : dict, memory buffer for reassembly
        |--> hdl : list, hole descriptor list
        |       |--> hole : Info, hole descriptor
        |               |--> first : int, start of this hole
        |               |--> last : int, stop of this hole
        |--> ack : dict, ACK of current TCP, i.e. tcp.ack
        |       |--> isn : int, ISN of this payload buffer
        |       |--> len : int, length of this payload buffer
        |       |--> raw : bytearray, reassembled payload (zero for holes)
        |--> ack ...
        |--> ...
     - datagram : tuple, contains reassembly results
        |--> data : Info, reassembled application layer datagram
        |       |--> NotImplemented : bool, if this datagram is implemented
        |       |--> payload
        |               |--> Implemented : bytes, original datagram
        |               |--> Not Implemented : tuple, datagram fragments
        |                       |--> fragment : bytes, partially reassembled data
        |                       |--> fragment ...
        |                       |--> ...
        |--> data ...
        |--> ...

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
        buffer = {}         # buffer field
        datagram = ()       # reassembled datagram

        # examine every fragment in info
        for buf in info:
            BUFID = buf.bufid       # Buffer ID
            DSN = buf.tcp.seq       # Data Sequence Number
            ACK = buf.tcp.ack       # Acknowledgement Number
            FIN = buf.tcp.flags.fin # Finish Flag (Termination)
            SYN = buf.tcp.flags.syn # Synchronise Flag (Establishment)

            # when SYN is set, reset buffer of this session
            # initialise buffer with BUFID & ACK then recurse
            if SYN or BUFID not in buffer:
                buffer[BUFID] = {
                    'hdl' : [Info(dict(first=buf.len, last=sys.maxsize)),],
                    ACK : dict(
                        isn=buf.tcp.seq,
                        len=buf.len,
                        raw=buf.raw,
                    ),
                }
                continue

            # initialise buffer with ACK
            if ACK not in buffer[BUFID]:
                buffer[BUFID][ACK] = dict(
                    isn=buf.tcp.seq,
                    len=buf.len,
                    raw=buf.raw,
                )

            # record fragment payload
            ISN = buffer[BUFID][ACK]['isn'] # Initial Sequence Number
            RAW = buffer[BUFID][ACK]['raw'] # Raw Payload Data
            if DSN >= ISN:  # if fragment goes after exsisting payload
                LEN = buffer[BUFID][ACK]['len']
                GAP = DSN - (ISN + LEN)     # gap length between payloads
                if GAP >= 0:    # if fragment goes after exsisting payload
                    RAW += bytearray(GAP) + buf.raw
                else:           # if fragment partially overlaps exsisting payload
                    RAW[DSN:] = buf.raw
            else:           # if fragment exceeds exsisting payload
                LEN = buf.len
                GAP = ISN - (DSN + LEN)     # gap length between payloads
                buffer[BUFID][ACK]['isn'] = DSN
                if GAP >= 0:    # if fragment exceeds exsisting payload
                    RAW += bytearray(GAP) + buf.raw
                else:           # if fragment partially overlaps exsisting payload
                    RAW = buf.raw + RAW[-GAP:]
            buffer[BUFID][ACK]['raw'] = RAW         # update payload datagram
            buffer[BUFID][ACK]['len'] = len(RAW)    # update payload length

            # update hole descriptor list
            HDL = copy.deepcopy(buffer[BUFID]['hdl'])
            for (index, hole) in enumerate(buffer[BUFID]['hdl']):   # step one
                if buf.first > hole.last:                           # step two
                    continue
                if buf.last < hole.first:                           # step three
                    continue
                del HDL[index]                                      # step four
                if buf.first > hole.first:                          # step five
                    new_hole = Info(dict(
                        first = hole.first,
                        last = buf.first - 1,
                    ))
                    HDL.insert(index, new_hole)
                if buf.last < hole.last and not FIN:                # step six
                    new_hole = Info(dict(
                        first = buf.last + 1,
                        last = hole.last
                    ))
                    HDL.insert(index+1, new_hole)
                break                                               # step seven
            buffer[BUFID]['hdl'] = HDL  # update HDL

            # when FIN is set, submit buffer of this session
            if FIN:
                datagram += self.submit(buffer[BUFID])
                del buffer[BUFID]

        # submit all buffers after processed every packet
        for buf in buffer:
            datagram += self.submit(buffer[buf])

        return datagram

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
                        payload = tuple(data),
                    ))
                    datagram.append(packet)
            # if this buffer is implemented
            # export payload data & convert into bytes
            else:
                data = buffer['raw']
                if data:    # strip empty buffer
                    packet = Info(dict(
                        NotImplemented = False,
                        payload = bytes(data),
                    ))
                    datagram.append(packet)
        return tuple(datagram)

# -*- coding: utf-8 -*-
"""reassembly TCP datagram

`pcapkit.reassembly.tcp` contains `TCP_Reassembly` only,
which reconstructs fragmented TCP packets back to origin.
The algorithm for TCP reassembly is described as below.

Notations:

    DSN     - Data Sequence Number
    ACK     - TCP Acknowledgement
    FIN     - TCP Finish Flag
    SYN     - TCP Synchronisation Flag
    BUFID   - Buffer Identifier
    HDL     - Hole Discriptor List
    ISN     - Initial Sequence Number
    src     - source IP
    dst     - destination IP
    srcport - source TCP port
    dstport - destination TCP port

Algorithm:

    DO {
        BUFID <- src|dst|srcport|dstport|ACK;
        IF (SYN is true) {
            IF (buffer with BUFID is allocated) {
                flush all reassembly for this BUFID;
                submit datagram to next step;
            }
        }

        IF (no buffer with BUFID is allocated) {
            allocate reassembly resources with BUFID;
            ISN <- DSN;
            put data from fragment into data buffer with BUFID
                [from octet fragment.first to octet fragment.last];
            update HDL;
        }

        IF (FIN is true) {
            submit datagram to next step;
            free all reassembly resources for this BUFID;
            BREAK.
        }
    } give up until (next fragment);

    update HDL: {
        DO {
            select the next hole descriptor from HDL;

            IF (fragment.first >= hole.first) CONTINUE.
            IF (fragment.last <= hole.first) CONTINUE.

            delete the current entry from HDL;

            IF (fragment.first >= hole.first) {
                create new entry "new_hole" in HDL;
                new_hole.first <- hole.first;
                new_hole.last <- fragment.first - 1;
                BREAK.
            }

            IF (fragment.last <= hole.last) {
                create new entry "new_hole" in HDL;
                new_hole.first <- fragment.last + 1;
                new_hole.last <- hole.last;
                BREAK.
            }
        } give up until (no entry from HDL)
    }

The following algorithm implement is based on `IP Datagram
Reassembly Algorithm` introduced in RFC 815. It described an
algorithm dealing with `RCVBT` (fragment received bit table)
appeared in RFC 791. And here is the process:

1. Select the next hole descriptor from the hole descriptor
  list. If there are no more entries, go to step eight.
2. If fragment.first is greater than hole.last, go to step one.
3. If fragment.last is less than hole.first, go to step one.
4. Delete the current entry from the hole descriptor list.
5. If fragment.first is greater than hole.first, then create a
  new hole descriptor "new_hole" with new_hole.first equal to
  hole.first, and new_hole.last equal to fragment.first minus
  one.
6. If fragment.last is less than hole.last and
  fragment.more_fragments is true, then create a new hole descriptor
  "new_hole", with new_hole.first equal to fragment.last plus
  one and new_hole.last equal to hole.last.
7. Go to step one.
8. If the hole descriptor list is now empty, the datagram is now
  complete. Pass it on to the higher level protocol processor
  for further handling. Otherwise, return.

"""
import copy
import io
import sys

from pcapkit.corekit.infoclass import Info
from pcapkit.foundation.analysis import analyse
from pcapkit.reassembly.reassembly import Reassembly

__all__ = ['TCP_Reassembly']


class TCP_Reassembly(Reassembly):
    """Reassembly for TCP payload.

    Usage:
        >>> from pcapkit.reassembly import TCP_Reassembly
        # Initialise instance:
        >>> tcp_reassembly = TCP_Reassembly()
        # Call reassembly:
        >>> tcp_reassembly(packet_dict)
        # Fetch result:
        >>> result = tcp_reassembly.datagram

    Properties:
        * name -- str, protocol of current packet
        * count -- int, total number of reassembled packets
        * datagram -- tuple, reassembled datagram, which structure may vary
                        according to its protocol
        * protocol -- str, protocol of current reassembly object

    Methods:
        * reassembly -- perform the reassembly procedure
        * submit -- submit reassembled payload
        * fetch -- fetch datagram
        * index -- return datagram index
        * run -- run automatically

    Attributes:
        * _strflg -- bool, strict mode flag
        * _buffer -- dict, buffer field
        * _dtgram -- tuple, reassembled datagram

    Terminology:
        - packet_dict = Info(
            bufid = tuple(
                ip.src,                     # source IP address
                ip.dst,                     # destination IP address
                tcp.srcport,                # source port
                tcp.dstport,                # destination port
            ),
            num = frame.number,             # original packet range number
            syn = tcp.flags.syn,            # synchronise flag
            fin = tcp.flags.fin,            # finish flag
            len = tcp.raw_len,              # payload length, header excludes
            first = tcp.seq,                # this sequence number
            last = tcp.seq + tcp.raw_len,   # next (wanted) sequence number
            payload = tcp.raw,              # raw bytearray type payload
         )
        - (tuple) datagram
           |--> (Info) data
           |       |--> 'NotImplemented' : (bool) True --> implemented
           |       |--> 'id' : (Info) original packet identifier
           |       |                |--> 'src' --> (tuple)
           |       |                |                |--> (str) ip.src
           |       |                |                |--> (int) tcp.srcport
           |       |                |--> 'dst' --> (tuple)
           |       |                |                |--> (str) ip.dst
           |       |                |                |--> (int) tcp.dstport
           |       |                |--> 'ack' --> (int) original packet ACK number
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (bytes/None) reassembled application layer data
           |       |--> 'packets' : (tuple<Analysis>) analysed payload
           |--> (Info) data
           |       |--> 'NotImplemented' : (bool) False --> not implemented
           |       |--> 'id' : (Info) original packet identifier
           |       |                |--> 'src' --> (tuple)
           |       |                |                |--> (str) ip.src
           |       |                |                |--> (int) tcp.srcport
           |       |                |--> 'dst' --> (tuple)
           |       |                |                |--> (str) ip.dst
           |       |                |                |--> (int) tcp.dstport
           |       |                |--> 'ack' --> (int) original packet ACK number
           |       |--> 'ack' : (int) original packet ACK number
           |       |--> 'index' : (tuple) packet numbers
           |       |                |--> (int) original packet range number
           |       |--> 'payload' : (tuple/None) partially reassembled payload
           |       |                |--> (bytes/None) payload fragment
           |       |--> 'packets' : (tuple<Analysis>) analysed payloads
           |--> (Info) data ...
        - (dict) buffer --> memory buffer for reassembly
           |--> (tuple) BUFID : (dict)
           |       |--> ip.src      |
           |       |--> ip.dst      |
           |       |--> tcp.srcport |
           |       |--> tcp.dstport |
           |                        |--> 'hdl' : (list) hole descriptor list
           |                        |               |--> (Info) hole --> hole descriptor
           |                        |                       |--> "first" --> (int) start of hole
           |                        |                       |--> "last" --> (int) stop of hole
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
        """Protocol of current packet."""
        return 'Transmission Control Protocol'

    @property
    def protocol(self):
        """Protocol of current reassembly object."""
        return 'TCP'

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info):
        """Reassembly procedure.

        Positional arguments:
            * info -- Info, info dict of packets to be reassembled

        """
        BUFID = info.bufid  # Buffer Identifier
        DSN = info.dsn      # Data Sequence Number
        ACK = info.ack      # Acknowledgement Number
        FIN = info.fin      # Finish Flag (Termination)
        SYN = info.syn      # Synchronise Flag (Establishment)

        # when SYN is set, reset buffer of this session
        if SYN and BUFID in self._buffer:
            self._dtgram += self.submit(self._buffer[BUFID], bufid=BUFID)
            del self._buffer[BUFID]

        # initialise buffer with BUFID & ACK
        if BUFID not in self._buffer:
            self._buffer[BUFID] = {
                'hdl': [Info(first=info.len, last=sys.maxsize)],
                ACK: dict(
                    ind=list(),
                    isn=info.dsn,
                    len=info.len,
                    raw=info.payload,
                ),
            }

        # initialise buffer with ACK
        if ACK not in self._buffer[BUFID]:
            self._buffer[BUFID][ACK] = dict(
                ind=list(),
                isn=info.dsn,
                len=info.len,
                raw=info.payload,
            )

        # append packet index
        self._buffer[BUFID][ACK]['ind'].append(info.num)

        # record fragment payload
        ISN = self._buffer[BUFID][ACK]['isn']   # Initial Sequence Number
        RAW = self._buffer[BUFID][ACK]['raw']   # Raw Payload Data
        if DSN >= ISN:  # if fragment goes after existing payload
            LEN = self._buffer[BUFID][ACK]['len']
            GAP = DSN - (ISN + LEN)     # gap length between payloads
            if GAP >= 0:    # if fragment goes after existing payload
                RAW += bytearray(GAP) + info.payload
            else:           # if fragment partially overlaps existing payload
                RAW[DSN-ISN:] = info.payload
        else:           # if fragment exceeds existing payload
            LEN = info.len
            GAP = ISN - (DSN + LEN)     # gap length between payloads
            self._buffer[BUFID][ACK]['isn'] = DSN
            if GAP >= 0:    # if fragment exceeds existing payload
                RAW = info.payload + bytearray(GAP) + RAW
            else:           # if fragment partially overlaps existing payload
                RAW = info.payload + RAW[ISN-GAP:]
        self._buffer[BUFID][ACK]['raw'] = RAW       # update payload datagram
        self._buffer[BUFID][ACK]['len'] = len(RAW)  # update payload length

        # update hole descriptor list
        HDL = copy.deepcopy(self._buffer[BUFID]['hdl'])
        for (index, hole) in enumerate(self._buffer[BUFID]['hdl']):     # step one
            if info.first > hole.last:                                  # step two
                continue
            if info.last < hole.first:                                  # step three
                continue
            del HDL[index]                                              # step four
            if info.first > hole.first:                                 # step five
                new_hole = Info(
                    first=hole.first,
                    last=info.first - 1,
                )
                HDL.insert(index, new_hole)
            if info.last < hole.last and not FIN:                       # step six
                new_hole = Info(
                    first=info.last + 1,
                    last=hole.last
                )
                HDL.insert(index+1, new_hole)
            break                                                       # step seven
        self._buffer[BUFID]['hdl'] = HDL                                # update HDL

        # when FIN is set, submit buffer of this session
        if FIN:
            self._dtgram += self.submit(self._buffer[BUFID], bufid=BUFID)
            del self._buffer[BUFID]

    def submit(self, buf, *, bufid):
        """Submit reassembled payload.

        Positional arguments:
            * buf -- dict, buffer dict of reassembled packets

        Keyword arguments:
            * bufid -- tuple, buffer identifier

        Returns:
            * list -- reassembled packets

        """
        datagram = []           # reassembled datagram
        HDL = buf.pop('hdl')    # hole descriptor list (remove from dict)

        # check through every buffer with ACK
        for (ack, buffer) in buf.items():
            # if this buffer is not implemented
            # go through every hole and extract received payload
            if len(HDL) > 2 and self._strflg:
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
                    packet = Info(
                        NotImplemented=True,
                        id=Info(
                            src=(bufid[0], bufid[2]),
                            dst=(bufid[1], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer['ind']),
                        payload=tuple(data) or None,
                        packets=tuple([analyse(io.BytesIO(frag), len(frag)) for frag in data]),
                    )
                    datagram.append(packet)
            # if this buffer is implemented
            # export payload data & convert into bytes
            else:
                data = buffer['raw']
                if data:    # strip empty buffer
                    packet = Info(
                        NotImplemented=False,
                        id=Info(
                            src=(bufid[0], bufid[2]),
                            dst=(bufid[1], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer['ind']),
                        payload=bytes(data) or None,
                        packets=(analyse(io.BytesIO(data), len(data)),),
                    )
                    datagram.append(packet)
        return datagram

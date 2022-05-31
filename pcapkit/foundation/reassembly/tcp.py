# -*- coding: utf-8 -*-
r"""TCP datagram reassembly

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which reconstructs fragmented TCP packets back to origin.
The algorithm for TCP reassembly is described as below.

Notations::

    DSN     - Data Sequence Number
    ACK     - TCP Acknowledgement
    SYN     - TCP Synchronisation Flag
    FIN     - TCP Finish Flag
    RST     - TCP Reset Connection Flag
    BUFID   - Buffer Identifier
    HDL     - Hole Discriptor List
    ISN     - Initial Sequence Number
    src     - source IP
    dst     - destination IP
    srcport - source TCP port
    dstport - destination TCP port

Algorithm::

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

        IF (FIN is true or RST is true) {
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

The following algorithm implement is based on **IP Datagram
Reassembly Algorithm** introduced in :rfc:`815`. It described an
algorithm dealing with ``RCVBT`` (fragment received bit table)
appeared in :rfc:`791`. And here is the process:

1. Select the next hole descriptor from the hole descriptor
   list. If there are no more entries, go to step eight.
2. If ``fragment.first`` is greater than ``hole.last``, go to step one.
3. If ``fragment.last`` is less than ``hole.first``, go to step one.
4. Delete the current entry from the hole descriptor list.
5. If ``fragment.first`` is greater than ``hole.first``, then create a
   new hole descriptor ``new_hole`` with ``new_hole.first`` equal to
   ``hole.first``, and ``new_hole.last`` equal to ``fragment.first``
   minus one (``-1``).
6. If ``fragment.last`` is less than ``hole.last`` and
   ``fragment.more_fragments`` is ``true``, then create a new hole
   descriptor ``new_hole``, with ``new_hole.first`` equal to
   ``fragment.last`` plus one (``+1``) and ``new_hole.last`` equal to
   ``hole.last``.
7. Go to step one.
8. If the hole descriptor list is now empty, the datagram is now
   complete. Pass it on to the higher level protocol processor
   for further handling. Otherwise, return.

Glossary
--------

tcp.packet
    Data structure for **TCP datagram reassembly**
    (:meth:`~pcapkit.foundation.reassembly.reassembly.Reassembly.reassembly`) is as following:

    .. code-block:: python

       packet_dict = Info(
         bufid = tuple(
             ip.src,                     # source IP address
             tcp.srcport,                # source port
             ip.dst,                     # destination IP address
             tcp.dstport,                # destination port
         ),
         dsn = tcp.seq,                  # data sequence number
         ack = tcp.ack,                  # acknowledgement number
         num = frame.number,             # original packet range number
         syn = tcp.flags.syn,            # synchronise flag
         fin = tcp.flags.fin,            # finish flag
         rst = tcp.flags.rst,            # reset connection flag
         len = tcp.raw_len,              # payload length, header excludes
         first = tcp.seq,                # this sequence number
         last = tcp.seq + tcp.raw_len,   # next (wanted) sequence number
         header = tcp.packet.header,     # raw bytes type header
         payload = tcp.raw,              # raw bytearray type payload
       )

tcp.datagram
    Data structure for **reassembled TCP datagram** (element from
    :attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly.datagram` *tuple*)
    is as following:

    .. code-block:: python

       (tuple) datagram
        |--> (Info) data
        |     |--> 'completed' : (bool) True --> implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (tuple)
        |     |            |               |--> (IPv4Address) ip.src
        |     |            |               |--> (int) tcp.srcport
        |     |            |--> 'dst' --> (tuple)
        |     |            |               |--> (IPv4Address) ip.dst
        |     |            |               |--> (int) tcp.dstport
        |     |            |--> 'ack' --> (int) original packet ACK number
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |               |--> ...
        |     |--> 'header' : (bytes) initial TCP header
        |     |--> 'payload' : (bytes) reassembled payload
        |     |--> 'packet' : (Protocol) parsed reassembled payload
        |--> (Info) data
        |     |--> 'completed' : (bool) False --> not implemented
        |     |--> 'id' : (Info) original packet identifier
        |     |            |--> 'src' --> (tuple)
        |     |            |               |--> (IPv4Address) ip.src
        |     |            |               |--> (int) tcp.srcport
        |     |            |--> 'dst' --> (tuple)
        |     |            |               |--> (IPv4Address) ip.dst
        |     |            |               |--> (int) tcp.dstport
        |     |            |--> 'ack' --> (int) original packet ACK number
        |     |--> 'index' : (tuple) packet numbers
        |     |               |--> (int) original packet range number
        |     |               |--> ...
        |     |--> 'header' : (bytes) initial TCP header
        |     |--> 'payload' : (tuple) partially reassembled payload
        |     |                 |--> (bytes) payload fragment
        |     |                 |--> ...
        |     |--> 'packet' : (None) not implemented
        |--> (Info) data ...

tcp.buffer
    Data structure for internal buffering when performing reassembly algorithms
    (:attr:`~pcapkit.foundation.reassembly.reassembly.Reassembly._buffer`) is as following:

    .. code-block:: python

       (dict) buffer --> memory buffer for reassembly
        |--> (tuple) BUFID : (dict)
        |       |--> ip.src      |
        |       |--> ip.dst      |
        |       |--> tcp.srcport |
        |       |--> tcp.dstport |
        |                        |--> 'hdl' : (list) hole descriptor list
        |                        |             |--> (Info) hole --> hole descriptor
        |                        |                   |--> "first" --> (int) start of hole
        |                        |                   |--> "last" --> (int) stop of hole
        |                        |--> 'hdr' : (bytes) initial TCP header
        |                        |--> 'ack' : (dict) ACK list
        |                                      |--> (int) ACK : (dict)
        |                                      |                 |--> 'ind' : (list) list of reassembled packets
        |                                      |                 |             |--> (int) packet range number
        |                                      |                 |--> 'isn' : (int) ISN of payload buffer
        |                                      |                 |--> 'len' : (int) length of payload buffer
        |                                      |                 |--> 'raw' : (bytearray) reassembled payload,
        |                                      |                                          holes set to b'\x00'
        |                                      |--> (int) ACK ...
        |                                      |--> ...
        |--> (tuple) BUFID ...

"""
import sys
from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.infoclass import Info
from pcapkit.foundation.reassembly.reassembly import Reassembly
from pcapkit.protocols.transport.tcp import TCP

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional, Type, overload

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import Protocol

__all__ = ['TCP_Reassembly']

IPAddress = TypeVar('IPAddress', 'IPv4Address', 'IPv6Address')

###############################################################################
# Data Models
###############################################################################

BufferID = tuple[IPAddress, int, IPAddress, int]


class Packet(Info):
    """Data model for :term:`tcp.packet`."""

    #: Buffer ID.
    bufid: 'BufferID'
    #: Data sequence number.
    dsn: 'int'
    #: Acknowledgment number.
    ack: 'int'
    #: Original packet range number.
    num: 'int'
    #: Synchronise flag.
    syn: 'bool'
    #: Finish flag.
    fin: 'bool'
    #: Reset connection flag.
    rst: 'bool'
    #: Payload length, header excludes.
    len: 'int'
    #: This sequence number.
    first: 'int'
    #: Next (wanted) sequence number.
    last: 'int'
    #: Raw :obj:`bytes` type header.
    header: 'bytes'
    #: Raw :obj:`bytearray` type payload.
    payload: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, bufid: 'BufferID', dsn: 'int', ack: 'int', num: 'int', syn: 'bool', fin: 'bool', rst: 'bool', len: 'int', first: 'int', last: 'int', header: 'bytes', payload: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class DatagramID(Info, Generic[IPAddress]):
    """Data model for :term:`tcp.datagram` original packet identifier."""

    #: Source address.
    src: 'tuple[IPAddress, int]'
    #: Destination address.
    dst: 'tuple[IPAddress, int]'
    #: Original packet ACK number.
    ack: 'int'

    if TYPE_CHECKING:
        def __init__(self, src: 'tuple[IPAddress, int]', dst: 'tuple[IPAddress, int]', ack: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Datagram(Info, Generic[IPAddress]):
    """Data model for :term:`tcp.datagram`."""

    #: Completed flag.
    completed: 'bool'
    #: Original packet identifier.
    id: 'DatagramID[IPAddress]'
    #: Packet numbers.
    index: 'tuple[int, ...]'
    #: Initial TCP header.
    header: 'bytes'
    #: Reassembled payload (application layer data).
    payload: 'bytes | tuple[bytes, ...]'
    #: Parsed reassembled payload.
    packet: 'Optional[Protocol]'

    if TYPE_CHECKING:
        @overload  # pylint: disable=used-before-assignment
        def __init__(self, completed: 'Literal[True]', id: 'DatagramID[IPAddress]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes', packet: 'Protocol') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        @overload
        def __init__(self, completed: 'Literal[False]', id: 'DatagramID[IPAddress]', index: 'tuple[int, ...]', header: 'bytes', payload: 'tuple[bytes, ...]', packet: 'None') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

        def __init__(self, completed: 'bool', id: 'DatagramID[IPAddress]', index: 'tuple[int, ...]', header: 'bytes', payload: 'bytes | tuple[bytes, ...]', packet: 'Optional[Protocol]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class HoleDiscriptor(Info):
    """Data model for :term:`tcp.buffer` hole descriptor."""

    #: Start of hole.
    first: 'int'
    #: Stop of hole.
    last: 'int'

    if TYPE_CHECKING:
        def __init__(self, first: 'int', last: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Fragment(Info):
    """Data model for :term:`tcp.buffer` ACK list fragment item."""

    #: List of reassembled packets.
    ind: 'list[int]'
    #: ISN of payload buffer.
    isn: 'int'
    #: Length of payload buffer.
    len: 'int'
    #: Reassembled payload holes set to b'\x00'.
    raw: 'bytearray'

    if TYPE_CHECKING:
        def __init__(self, ind: 'list[int]', isn: 'int', len: 'int', raw: 'bytearray') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Buffer(Info):
    """Data model for :term:`tcp.buffer`."""

    #: Hole descriptor list.
    hdl: 'list[HoleDiscriptor]'
    #: Initial TCP header.
    hdr: 'bytes'
    #: ACK list.
    ack: 'dict[int, Fragment]'

    if TYPE_CHECKING:
        def __init__(self, hdl: 'list[HoleDiscriptor]', hdr: 'bytes', ack: 'dict[int, Fragment]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


###############################################################################
# Algorithm Implementation
###############################################################################


class TCP_Reassembly(Reassembly[Packet, Datagram, BufferID, Buffer]):
    """Reassembly for TCP payload.

    Example:
        >>> from pcapkit.reassembly import TCP_Reassembly
        # Initialise instance:
        >>> tcp_reassembly = TCP_Reassembly()
        # Call reassembly:
        >>> tcp_reassembly(packet_dict)
        # Fetch result:
        >>> result = tcp_reassembly.datagram

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Transmission Control Protocol"]':
        """Protocol of current packet."""
        return 'Transmission Control Protocol'

    @property
    def protocol(self) -> 'Type[TCP]':
        """Protocol of current reassembly object."""
        return TCP

    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info: 'Packet') -> 'None':
        """Reassembly procedure.

        Arguments:
            info: :term:`info <tcp.packet>` dict of packets to be reassembled

        """
        BUFID = info.bufid  # Buffer Identifier
        DSN = info.dsn      # Data Sequence Number
        ACK = info.ack      # Acknowledgement Number
        FIN = info.fin      # Finish Flag (Termination)
        RST = info.rst      # Reset Connection Flag (Termination)
        SYN = info.syn      # Synchronise Flag (Establishment)

        # when SYN is set, reset buffer of existing session
        if SYN and BUFID in self._buffer:
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

        # initialise buffer with BUFID & ACK
        if BUFID not in self._buffer:
            self._buffer[BUFID] = Buffer(
                hdl=[
                    HoleDiscriptor(
                        first=info.len,
                        last=sys.maxsize,
                    ),
                ],
                hdr=info.header if SYN else b'',
                ack={
                    ACK: Fragment(
                        ind=[
                            info.num,
                        ],
                        isn=info.dsn,
                        len=info.len,
                        raw=info.payload,
                    ),
                },
            )
        else:
            # initialise buffer with ACK
            if ACK not in self._buffer[BUFID].ack:
                self._buffer[BUFID].ack[ACK] = Fragment(
                    ind=[
                        info.num,
                    ],
                    isn=info.dsn,
                    len=info.len,
                    raw=info.payload,
                )
            else:
                # put header into header buffer
                if SYN:
                    self._buffer[BUFID].__update__(hdr=info.header)

                # append packet index
                self._buffer[BUFID].ack[ACK].ind.append(info.num)

                # record fragment payload
                ISN = self._buffer[BUFID].ack[ACK].isn       # Initial Sequence Number
                RAW = self._buffer[BUFID].ack[ACK].raw       # Raw Payload Data
                if DSN >= ISN:  # if fragment goes after existing payload
                    LEN = self._buffer[BUFID].ack[ACK].len
                    GAP = DSN - (ISN + LEN)     # gap length between payloads
                    if GAP >= 0:    # if fragment goes after existing payload
                        RAW += bytearray(GAP) + info.payload
                    else:           # if fragment partially overlaps existing payload
                        RAW[DSN-ISN:] = info.payload
                else:           # if fragment exceeds existing payload
                    LEN = info.len
                    GAP = ISN - (DSN + LEN)     # gap length between payloads
                    self._buffer[BUFID].ack[ACK].__update__(
                        isn=DSN,
                    )
                    if GAP >= 0:    # if fragment exceeds existing payload
                        RAW = info.payload + bytearray(GAP) + RAW
                    else:           # if fragment partially overlaps existing payload
                        RAW = info.payload + RAW[ISN-GAP:]
                #self._buffer[BUFID].ack[ACK].raw = RAW       # update payload datagram
                #self._buffer[BUFID].ack[ACK].len = len(RAW)  # update payload length
                self._buffer[BUFID].ack[ACK].__update__(
                    raw=RAW,       # update payload datagram
                    len=len(RAW),  # update payload length
                )

            # update hole descriptor list
            HDL = self._buffer[BUFID].hdl                          # HDL alias
            for (index, hole) in enumerate(HDL):                   # step one
                if info.first > hole.last:                         # step two
                    continue
                if info.last < hole.first:                         # step three
                    continue
                del HDL[index]                                     # step four
                if info.first > hole.first:                        # step five
                    new_hole = HoleDiscriptor(
                        first=hole.first,
                        last=info.first - 1,
                    )
                    HDL.insert(index, new_hole)
                    index += 1
                if info.last < hole.last and not FIN and not RST:  # step six
                    new_hole = HoleDiscriptor(
                        first=info.last + 1,
                        last=hole.last
                    )
                    HDL.insert(index, new_hole)
                break                                              # step seven
            #self._buffer[BUFID].hdl = HDL                         # update HDL

        # when FIN/RST is set, submit buffer of this session
        if FIN or RST:
            self._dtgram.extend(
                self.submit(self._buffer.pop(BUFID), bufid=BUFID)
            )

    def submit(self, buf: 'Buffer', *, bufid: 'BufferID') -> 'list[Datagram]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Submit reassembled payload.

        Arguments:
            buf: :term:`buffer <tcp.buffer>` dict of reassembled packets

        Keyword Arguments:
            bufid: buffer identifier

        Returns:
            Reassembled :term:`packets <tcp.datagram>`.

        """
        datagram = []  # type: list[Datagram] # reassembled datagram
        HDL = buf.hdl                         # hole descriptor list

        # check through every buffer with ACK
        for (ack, buffer) in buf.ack.items():
            # if this buffer is not implemented
            # go through every hole and extract received payload
            if len(HDL) > 2 and self._strflg:
                data = []  # type: list[bytes]
                start = stop = 0
                for hole in HDL:
                    stop = hole.first
                    byte = buffer.raw[start:stop]
                    start = hole.last
                    if byte:    # strip empty payload
                        data.append(byte)
                byte = buffer.raw[start:]
                if byte:    # strip empty payload
                    data.append(bytes(byte))
                if data:    # strip empty buffer
                    packet = Datagram(
                        completed=False,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=tuple(data),
                        packet=None,
                    )
                    datagram.append(packet)

            # if this buffer is implemented
            # export payload data & convert into bytes
            else:
                payload = buffer.raw
                if payload:    # strip empty buffer
                    packet = Datagram(
                        completed=True,
                        id=DatagramID(
                            src=(bufid[0], bufid[1]),
                            dst=(bufid[2], bufid[3]),
                            ack=ack,
                        ),
                        index=tuple(buffer.ind),
                        header=buf.hdr,
                        payload=bytes(payload),
                        packet=self.protocol.analyze((bufid[1], bufid[3]), bytes(payload)),
                    )
                    datagram.append(packet)
        return datagram

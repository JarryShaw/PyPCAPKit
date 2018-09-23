# -*- coding: utf-8 -*-
"""reassembly IP fragments

`pcapkit.reassembly.ip` contains `IP_Reassembly` only,
which is the base class for IPv4 and IPv6 reassembly.
The following algorithm implement is based on IP
reassembly procedure introduced in RFC 791, using
`RCVBT` (fragment receivedbit table). Though another
algorithm is explained in RFC 815, replacing `RCVBT`,
however, this implement still used the elder one.
And here is the pseudo-code:

Notations:

    FO    - Fragment Offset
    IHL   - Internet Header Length
    MF    - More Fragments flag
    TTL   - Time To Live
    NFB   - Number of Fragment Blocks
    TL    - Total Length
    TDL   - Total Data Length
    BUFID - Buffer Identifier
    RCVBT - Fragment Received Bit Table
    TLB   - Timer Lower Bound

Algorithm:

    DO {
        BUFID <- source|destination|protocol|identification;

        IF (FO = 0 AND MF = 0) {
            IF (buffer with BUFID is allocated) {
                flush all reassembly for this BUFID;
                Submit datagram to next step;
                DONE.
            }
        }

        IF (no buffer with BUFID is allocated) {
            allocate reassembly resources with BUFID;
            TIMER <- TLB;
            TDL <- 0;
            put data from fragment into data buffer with BUFID
                [from octet FO*8 to octet (TL-(IHL*4))+FO*8];
            set RCVBT bits [from FO to FO+((TL-(IHL*4)+7)/8)];
        }

        IF (MF = 0) {
            TDL <- TL-(IHL*4)+(FO*8)
        }

        IF (FO = 0) {
            put header in header buffer
        }

        IF (TDL # 0 AND all RCVBT bits [from 0 to (TDL+7)/8] are set) {
            TL <- TDL+(IHL*4)
            Submit datagram to next step;
            free all reassembly resources for this BUFID;
            DONE.
        }

        TIMER <- MAX(TIMER,TTL);

    } give up until (next fragment or timer expires);

    timer expires: {
        flush all reassembly with this BUFID;
        DONE.
    }

"""
import copy

from pcapkit.corekit.infoclass import Info
from pcapkit.reassembly.reassembly import Reassembly


__all__ = ['IP_Reassembly']


class IP_Reassembly(Reassembly):
    """Reassembly for IP payload.

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

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info):
        """Reassembly procedure.

        Positional arguments:
            * info -- Info, info dict of packets to be reassembled

        """
        BUFID = info.bufid  # Buffer Identifier
        FO = info.fo        # Fragment Offset
        IHL = info.ihl      # Internet Header Length
        MF = info.mf        # More Fragments flag
        TL = info.tl        # Total Length

        # when non-fragmented (possibly discarded) packet received
        if not FO and not MF:
            if BUFID in self._buffer:
                self._dtgram += self.submit(self._buffer[BUFID])
                del self._buffer[BUFID]
                return

        # initialise buffer with BUFID
        if BUFID not in self._buffer:
            self._buffer[BUFID] = dict(
                TDL=0,                          # Total Data Length
                RCVBT=bytearray(8191),          # Fragment Received Bit Table
                index=list(),                   # index record
                header=bytearray(),             # header buffer
                datagram=bytearray(65535),      # data buffer
            )

        # append packet index
        self._buffer[BUFID]['index'].append(info.num)

        # put data into data buffer
        start = FO
        stop = TL - IHL + FO
        self._buffer[BUFID]['datagram'][start:stop] = info.payload

        # set RCVBT bits (in 8 octets)
        start = FO // 8
        stop = FO // 8 + (TL - IHL + 7) // 8
        self._buffer[BUFID]['RCVBT'][start:stop] = b'\x01' * (stop - start + 1)

        # get total data length (header excludes)
        if not MF:
            TDL = TL - IHL + FO

        # put header into header buffer
        if not FO:
            self._buffer[BUFID]['header'] = info.header

        # when datagram is reassembled in whole
        start = 0
        stop = (TDL + 7) // 8
        if TDL and all(self._buffer[BUFID]['RCVBT'][start:stop]):
            self._dtgram += self.submit(self._buffer[BUFID], checked=True)
            del self._buffer[BUFID]

    def submit(self, buf, *, checked=False):
        """Submit reassembled payload.

        Positional arguments:
            * buf -- dict, buffer dict of reassembled packets

        Keyword arguments:
            * bufid -- tuple, buffer identifier

        Returns:
            * list -- reassembled packets

        """
        TDL = buf['TDL']
        RCVBT = buf['RCVBT']
        index = buf['index']
        header = buf['header']
        datagram = buf['datagram']

        start = 0
        stop = (TDL + 7) // 8
        flag = checked or (TDL and all(RCVBT[start:stop]))
        # if datagram is not implemented
        if not flag and self._strflg:
            data = list()
            byte = bytearray()
            # extract received payload
            for (bctr, bit) in enumerate(RCVBT):
                if bit:     # received bit
                    this = bctr * 8
                    that = this + 8
                    byte += datagram[this:that]
                else:       # missing bit
                    if byte:    # strip empty payload
                        data.append(bytes(byte))
                    byte = bytearray()
            # strip empty packets
            if data or header:
                packet = Info(
                    NotImplemented=True,
                    index=tuple(index),
                    header=header or None,
                    payload=tuple(data) or None,
                )
        # if datagram is reassembled in whole
        else:
            payload = datagram[:TDL]
            packet = Info(
                NotImplemented=False,
                index=tuple(index),
                packet=(bytes(header) + bytes(payload)) or None,
            )
        return [packet]

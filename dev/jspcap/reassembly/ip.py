#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Reassembly IP Fragments
# Base class for IPv4 & IPv6 reassembly


from .reassembly import Reassembly
from ..protocols import Info


abstractmethod = abc.abstractmethod


class IP_Reassembly(Reassembly):
    """Reassembly for IP payload.

    The following algorithm implementment is based on IP reassembly procedure
    introduced in RFC 791, using `RCVBT` (fragment receivedbit table). Though
    another algorithm is explained in RFC 815, replacing `RCVBT`, however,
    this implementment still used the elder one. And here is the pseudo-code:

    Notation:
        FO    -  Fragment Offset
        IHL   -  Internet Header Length
        MF    -  More Fragments flag
        TTL   -  Time To Live
        NFB   -  Number of Fragment Blocks
        TL    -  Total Length
        TDL   -  Total Data Length
        BUFID -  Buffer Identifier
        RCVBT -  Fragment Received Bit Table
        TLB   -  Timer Lower Bound

    Procedure:
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
    ##########################################################################
    # Methods.
    ##########################################################################

    def reassembly(self, info):
        buffer = {}         # buffer field
        datagram = []       # reassembled datagram
        for buf in info:
            # get descriptors
            FO, IHL, MF, TL, BUFID = self._ip_reassembly(buf)

            # when unfragmented (possibly discarded) packet received
            if not FO and not MF:
                if BUFID in buffer:
                    header = buffer[BUFID]['header']
                    data = buffer[BUFID]['data'][IHL:TL]
                    packet = Info(dict(
                        NotImplemented = False,
                        packet = bytes(header) + bytes(data),
                    ))
                    datagram.append(packet)
                    del buffer[BUFID]
                    continue

            # initialise buffer with BUFID
            if BUFID not in buffer:
                buffer[BUFID] = dict(
                    TDL = 0,                    # Total Data Length
                    RCVBT = bytearray(8191),    # Fragment Received Bit Table
                    data = bytearray(65535),    # data buffer
                    header = bytearray(),       # header buffer
                )

            # put data into data buffer
            start = FO
            stop = TL - IHL + FO
            buffer[BUFID]['data'][start:stop] = buf.raw

            # set RCVBT bits (in 8 octets)
            start = FO // 8
            stop = FO // 8 + (TL - IHL + 7) // 8
            buffer[BUFID][RCVBT][start:stop] = b'\x01' * (stop - start + 1)

            # get total data length (header excludes)
            if not MF:
                TDL = TL - IHL + FO

            # put header into header buffer
            if not FO:
                buffer[BUFID]['header'] = buf.header

            # when datagram is reassembled in whole
            start = 0
            stop = (TDL + 7) // 8
            if TDL and all(RCVBT[start:stop]):
                TL = TDL + IHL
                header = buffer[BUFID]['header']
                data = buffer[BUFID]['data'][IHL:TL]
                packet = Info(dict(
                    NotImplemented = False,
                    packet = bytes(header) + bytes(data),
                ))
                datagram.append(packet)
                del buffer[BUFID]

        # after processed every packet
        for buf in buffer.values():
            data = []
            byte = bytearray()
            # extract received payload
            for (bctr, bit) in enumerate(RCVBT):
                if bit: # received bit
                    this = bctr * 8
                    that = this + 8
                    byte += buf['data'][this:that]
                else:   # unreceived bit
                    if byte:    # strip empty payload
                        data.append(bytes(byte))
                    byte = bytearray()
            # strip empty datagram
            if data and buf['header']:
                packet = Info(dict(
                    NotImplemented = True,
                    header = buf['header'] or None,
                    payload = tuple(data),
                ))
                datagram.append(packet)

        return tuple(datagram)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @abstractmethod
    def _ip_reassembly(self, buf):
        pass

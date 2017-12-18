#!/usr/bin/python3
# -*- coding: utf-8 -*-


import abc


# Reassembly IP Fragments
# Base class for IPv4 & IPv6 reassembly


from .reassembler import Reassembler


abstractmethod = abc.abstractmethod


class IP_Reassembly(Reassembler):

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
            if FO == 0 and MF == 0:
                if BUFID in buffer:
                    header = buffer[BUFID]['header'][:IHL+1] or None
                    data = buffer[BUFID]['data'][:TL]
                    datagram.append((bytes(header), bytes(data)))
                    del buffer[BUFID]
                    continue

            # initialise buffer with BUFID
            if BUFID not in buffer:
                buffer[BUFID] = dict(
                    TDL = 0,                    # Total Data Length
                    RCVBT = bytearray(8191),    # Fragment Received Bit Table
                    data = bytearray(65535),    # data buffer
                    header = bytearray(64),     # header buffer
                )

            # put data into data buffer
            start = FO
            stop = TL - IHL + FO
            buffer[BUFID][data][start:stop] = buf.raw

            # set RCVBT bits (in 8 octets)
            start = FO // 8
            stop = FO // 8 + (TL - IHL + 7) // 8
            buffer[BUFID][RCVBT][start:stop] = b'\x01' * (stop - start + 1)

            # get total data length (header excludes)
            if MF == 0:
                TDL = TL - IHL + FO

            # put header into header buffer
            if FO == 0:
                buffer[BUFID][header] = buf.header

            # when datagram is reassembled
            start = 0
            stop = (TDL + 7) // 8
            if TDL != 0 and all(RCVBT[start:stop]):
                TL = TDL + IHL
                header = buffer[BUFID]['header'][:IHL+1] or None
                data = buffer[BUFID]['data'][:TL]
                datagram.append((bytes(header), bytes(data)))
                del buffer[BUFID]

        return tuple(datagram)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @abstractmethod
    def _ip_reassembly(self, buf):
        pass

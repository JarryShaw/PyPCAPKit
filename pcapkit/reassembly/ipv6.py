# -*- coding: utf-8 -*-
"""reassembly IPv6 fragments

`pcapkit.reassembly.ipv6` contains `IPv6_Reassembly`
only, which reconstructs fragmented IPv4 packets back to
origin. The following algorithm implement is based on IP
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
from pcapkit.reassembly.ip import IP_Reassembly


__all__ = ['IPv6_Reassembly']


class IPv6_Reassembly(IP_Reassembly):
    """Reassembly for IPv6 payload.

    Usage:
        >>> from pcapkit.reassembly import IPv6_Reassembly
        # Initialise instance:
        >>> ipv6_reassembly = IPv6_Reassembly()
        # Call reassembly:
        >>> ipv6_reassembly(packet_dict)
        # Fetch result:
        >>> result = ipv6_reassembly.datagram

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
        * packet_dict = dict(
            bufid = tuple(
                ipv6.src,                   # source IP address
                ipv6.dst,                   # destination IP address
                ipv6.label,                 # label
                ipv6_frag.next,             # next header field in IPv6 Fragment Header
            ),
            num = frame.number,             # original packet range number
            fo = ipv6_frag.offset,          # fragment offset
            ihl = ipv6.hdr_len,             # header length, only headers before IPv6-Frag
            mf = ipv6_frag.mf,              # more fragment flag
            tl = ipv6.len,                  # total length, header includes
            header = ipv6.header,           # raw bytearray type header before IPv6-Frag
            payload = ipv6.payload,         # raw bytearray type payload after IPv6-Frag
          )
        * (tuple) datagram
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) True --> implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'packet' : (bytes/None) reassembled IPv6 packet
            |--> (dict) data
            |       |--> 'NotImplemented' : (bool) False --> not implemented
            |       |--> 'index' : (tuple) packet numbers
            |       |                |--> (int) original packet range number
            |       |--> 'header' : (bytes/None) IPv4 header
            |       |--> 'payload' : (tuple/None) partially reassembled IPv6 payload
            |                        |--> (bytes/None) IPv4 payload fragment
            |--> (dict) data ...
        * (dict) buffer --> memory buffer for reassembly
            |--> (tuple) BUFID : (dict)
            |       |--> ipv6.src       |
            |       |--> ipc6.dst       |
            |       |--> ipv6.label     |
            |       |--> ipv6_frag.next |
            |                           |--> 'TDL' : (int) total data length
            |                           |--> RCVBT : (bytearray) fragment received bit table
            |                           |               |--> (bytes) b\x00' not received
            |                           |               |--> (bytes) b\x01' received
            |                           |               |--> (bytes) ...
            |                           |--> 'index' : (list) list of reassembled packets
            |                           |               |--> (int) packet range number
            |                           |--> 'header' : (bytearray) header buffer
            |                           |--> 'datagram' : (bytearray) data buffer,
            |                                               holes set to b'\x00'
            |--> (tuple) BUFID ...

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Protocol of current packet."""
        return 'Internet Protocol version 6'

    @property
    def protocol(self):
        """Protocol of current reassembly object."""
        return 'IPv6'

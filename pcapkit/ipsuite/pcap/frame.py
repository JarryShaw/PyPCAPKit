# -*- coding: utf-8 -*-
"""

"""
import datetime
import time

from pcapkit.ipsuite.protocol import Protocol

__all__ = ['Frame']


class Frame(Protocol):
    """PCAP frame header constructor.

    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;     /* timestamp seconds */
        guint32 ts_usec;    /* timestamp microseconds */
        guint32 incl_len;   /* number of octets of packet saved in file */
        guint32 orig_len;   /* actual length of packet */
    } pcaprec_hdr_t;

    Keywords:
        * timestamp -- float, UNIX-Epoch timestamp (default: time at run)
            - ts_sec -- int, timestamp seconds (default: time at run)
            - ts_usec -- int, timestamp microseconds (default: time at run)
        * incl_len -- int, number of octets of packet saved in file (default: length of packet)
        * orig_len -- int, actual length of packet (default: length of packet)
        * packet -- bytes, raw packet data (default: b'')
        * nanosecond -- bool, nanosecond-resolution file flag (default: False)

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * data -- bytes, binary packet data if current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * index -- return first index of value from a dict
        * pack -- pack integers to bytes

    Utilities:
        * __make__ -- make packet data

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    def __make__(self):
        """Make packet data."""
        def __make_timestamp__():
            """Make timestamp."""
            nanosecond = self.__args__.get('nanosecond', False)         # nanosecond-resolution file flag
            timestamp = self.__args__.get('timestamp', time.time())     # timestamp
            now = datetime.datetime.fromtimestamp(timestamp)            # timestamp datetime instance
            ts_sec = self.__args__.get('ts_sec', now.second)            # timestamp seconds
            ts_usec = self.__args__.get(
                'ts_usec', now.microsecond * (1_000 if nanosecond else 1)
            )                                                           # timestamp microseconds
            return ts_sec, ts_usec

        # fetch values
        ts_sec, ts_usec = __make_timestamp__()
        packet = self.__args__.get('packet', bytes())                   # raw packet data
        incl_len = self.__args__.get('incl_len', len(packet))           # number of octets of packet saved in file
        orig_len = self.__args__.get('orig_len', len(packet))           # actual length of packet

        # make packet
        return b'%s%s%s%s%s' % (
            self.pack(ts_sec, size=4, lilendian=True),
            self.pack(ts_usec, size=4, lilendian=True),
            self.pack(incl_len, size=4, lilendian=True),
            self.pack(orig_len, size=4, lilendian=True),
            packet,
        )

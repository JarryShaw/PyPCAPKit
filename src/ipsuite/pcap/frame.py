# -*- coding: utf-8 -*-
"""

"""
import datetime
import time

from pcapkit.ipsuite.protocol import Protocol


__all__ = ['Frame']


class Frame(Protocol):
    """PCAP frame header constructor.

    Keywords:
        * timestamp -- float, UNIX-Epoch timestamp (default: time at run)
        * ts_sec -- int, timestamp seconds (default: time at run)
        * ts_usec -- int, timestamp microseconds (default: time at run)
        * incl_len -- int, number of octets of packet saved in file (default: length of packet)
        * orig_len -- int, actual length of packet (default: length of packet)
        * packet -- bytes, raw packet data (default: empty bytes string)

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
        # fetch values
        timestamp = self.__args__.get('timestamp', time.time())     # timestamp
        now = datetime.datetime.fromtimestamp(timestamp)            # timestamp datetime instance

        packet = self.__args__.get('packet', bytes())               # raw packet data
        ts_sec = self.__args__.get('ts_sec', now.second)            # timestamp seconds
        ts_usec = self.__args__.get('ts_usec', now.microsecond)     # timestamp microseconds
        incl_len = self.__args__.get('incl_len', len(packet))       # number of octets of packet saved in file
        orig_len = self.__args__.get('orig_len', len(packet))       # actual length of packet

        # make packet
        self.__data__ = b'%s%s%s%s%s' % (
            self.pack(ts_sec, size=4, lilendian=True),
            self.pack(ts_usec, size=4, lilendian=True),
            self.pack(incl_len, size=4, lilendian=True),
            self.pack(orig_len, size=4, lilendian=True),
            packet,
        )

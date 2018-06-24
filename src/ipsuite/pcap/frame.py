# -*- coding: utf-8 -*-
"""

"""
import time

from jspcap.ipsuite.protocol import Protocol


__all__ = ['Frame']


class Frame(Protocol):
    """PCAP frame header constructor.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * data -- bytes, binary packet data if current instance
        * alias -- str, acronym of corresponding protocol

    Methods:
        * index -- return first index of value from a dict
        * pack -- pack integers to bytes
        * update -- update packet data

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    def update(self, **kwargs):
        """Update packet data."""
        # update dict
        self.__dict__.update(kwargs)

        # fetch values
        packet = self.__dict__.pop('packet', bytes())               # raw packet data
        frame_info = self.__dict__.pop('frame_info')                # extracted frame info
        if frame_info and isinstance(frame_info, dict):
            now = [ int(x or 0) for x in str(time.time()).split('.') ]
            ts_sec = frame_info.pop('ts_sec', now[0])               # timestamp seconds
            ts_usec = frame_info.pop('ts_usec', now[1])             # timestamp microseconds
            incl_len = frame_info.pop('incl_len', len(packet))      # number of octets of packet saved in file
            orig_len = frame_info.pop('orig_len', len(packet))      # actual length of packet
        else:
            timestamp = self.__dict__.pop('timestamp', time.time()) # timestamp
            now = [ int(x or 0) for x in str(timestamp).split('.') ]
            ts_sec = self.__dict__.pop('ts_sec', now[0])            # timestamp seconds
            ts_usec = self.__dict__.pop('ts_usec', now[1])          # timestamp microseconds
            incl_len = self.__dict__.pop('incl_len', len(packet))   # number of octets of packet saved in file
            orig_len = self.__dict__.pop('orig_len', len(packet))   # actual length of packet

        # update packet
        data = self.pack(ts_sec, size=4, lilendian=True)
        data += self.pack(ts_usec, size=4, lilendian=True)
        data += self.pack(incl_len, size=4, lilendian=True)
        data += self.pack(orig_len, size=4, lilendian=True)
        data += packet

        # update data
        self.__data__ = data

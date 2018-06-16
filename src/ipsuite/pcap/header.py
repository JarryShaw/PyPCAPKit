# -*- coding: utf-8 -*-
"""

"""
from jspcap.ipsuite.protocol import Protocol
from jspcap.protocols.link.link import LINKTYPE
from jspcap.utilities.exceptions import ProtocolNotImplemented


__all__ = ['Header']


class Header(Protocol):
    """PCAP global header constructor.

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
        version_major = self.__dict__.pop('version_major', 2)   # major version number
        version_minor = self.__dict__.pop('version_minor', 4)   # minor version number
        thiszone = self.__dict__.pop('thiszone', 0)             # GMT to local correction
        sigfigs = self.__dict__.pop('sigfigs', 0)               # accuracy of timestamps
        snaplen = self.__dict__.pop('snaplen', 262144)          # max length of captured packets, in octets
        network = self.__dict__.pop('network', 'Ethernet')      # data link type

        # update packet
        data = b'\xd4\xc3\xb2\xa1'
        data += self.pack(version_major, size=2, lilendian=True)
        data += self.pack(version_minor, size=2, lilendian=True)
        data += self.pack(thiszone, size=4, lilendian=True)
        data += self.pack(sigfigs, size=4, lilendian=True)
        data += self.pack(snaplen, size=4, lilendian=True)
        data += self.index(LINKTYPE, network, pack=True, lilendian=True)

        # update data
        self.__data__ = data

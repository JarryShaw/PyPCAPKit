# -*- coding: utf-8 -*-
"""

"""
from pcapkit.ipsuite.protocol import Protocol
from pcapkit.protocols.link.link import LINKTYPE


__all__ = ['Header']


class Header(Protocol):
    """PCAP global header constructor.

    Keywords:
        * version_major -- int, major version number (default: 2)
        * version_minor -- int, minor version number (default: 4)
        * thiszone -- int, GMT to local correction (default: 0)
        * sigfigs -- int, accuracy of timestamps (default: 0)
        * snaplen -- int, max length of captured packets, in octets (default: 262144)
        * network -- LINKTYPE / IntEnum / str / int, data link type (default: DLT_NULL)
        * network_default -- int, default value for unknown data link type
        * network_namespace -- LINKTYPE / IntEnum / dict, data link type namespace (default: LINKTYPE)
        * network_reversed -- bool, if namespace is [str -> int] pairs (default: False)

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
    # Utilities.
    ##########################################################################

    def __make__(self):
        """Make packet data."""
        # fetch values
        version_major = self.__args__.get('version_major', 2)       # major version number
        version_minor = self.__args__.get('version_minor', 4)       # minor version number
        thiszone = self.__args__.get('thiszone', 0)                 # GMT to local correction
        sigfigs = self.__args__.get('sigfigs', 0)                   # accuracy of timestamps
        snaplen = self.__args__.get('snaplen', 262144)              # max length of captured packets, in octets
        network = self.__args__.get('network', LINKTYPE['NULL'])    # data link type
        network_default = self.__args__.get('network_default')      # default value for unknown data link type
        network_namespace = self.__args__.get('network_namespace', LINKTYPE)
                                                                    # data link type namespace
        network_reversed = self.__args__.get('network_reversed', False)
                                                                    # if namespace is [str -> int] pairs

        # make packet
        self.__data__ = b'\xd4\xc3\xb2\xa1%s%s%s%s%s%s' % (
            self.pack(version_major, size=2, lilendian=True),
            self.pack(version_major, size=2, lilendian=True),
            self.pack(thiszone, size=4, lilendian=True),
            self.pack(sigfigs, size=4, lilendian=True),
            self.pack(snaplen, size=4, lilendian=True),
            self.index(network, network_default, namespace=network_namespace,
                        reversed=network_reversed, pack=True, lilendian=True),
        )

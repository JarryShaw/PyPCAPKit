# -*- coding: utf-8 -*-
"""

"""
import sys

from pcapkit.ipsuite.protocol import Protocol
from pcapkit.protocols.link.link import LINKTYPE
from pcapkit.utilities.exceptions import EndianError


__all__ = ['Header']


_MAGIC_NUM = {
    ('big', True):      b'\xa1\xb2\x3c\x4d',
    ('big', False):     b'\xa1\xb2\xc3\xd4',
    ('little', True):   b'\x4d\x3c\xb2\xa1',
    ('little', False):  b'\xd4\xc3\xb2\xa1',
}


class Header(Protocol):
    """PCAP global header constructor.

    typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
    } pcap_hdr_t;

    Keywords:
        * byteorder -- str, header byte order (default: depends on platform)
            - lilendian -- bool, little-endian flag (default: depends on platform)
            - bigendian -- bool, big-endian flag (default: depends on platform)
        * nanosecond -- bool, nanosecond-resolution file flag (default: False)
        * version -- tuple<int>, version information (default: (2, 4))
        * version_major -- int, major version number (default: 2)
        * version_minor -- int, minor version number (default: 4)
        * thiszone -- int, GMT to local correction (default: 0)
        * sigfigs -- int, accuracy of timestamps (default: 0)
        * snaplen -- int, max length of captured packets, in octets (default: 262144)
        * network -- LINKTYPE / IntEnum / str / int, data link type (default: DLT_NULL)
            - network_default -- int, default value for unknown data link type
            - network_namespace -- LINKTYPE / IntEnum / dict, data link type namespace (default: LINKTYPE)
            - network_reversed -- bool, if namespace is dict<str: int> pairs (default: False)

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
        def __make_magic__():
            nanosecond = bool(self.__args__.get('nanosecond', False))   # nanosecond-resolution file flag
            byteorder = self.__args__.get('byteorder', sys.byteorder)   # header byte order
            lilendian = self.__args__.get('lilendian')                  # little-endian flag
            bigendian = self.__args__.get('bigendian')                  # big-endian flag

            if lilendian is not None and bigendian is not None:
                if lilendian == bigendian:
                    raise EndianError('unresolved byte order')
                if bigendian:
                    return _MAGIC_NUM[('big', False)], False
                if lilendian:
                    return _MAGIC_NUM[('little', True)], True

            if byteorder.lower() not in ('little', 'big'):
                raise EndianError("unknown byte order: {!r}".format(byteorder))

            magic_number = _MAGIC_NUM[(byteorder.lower(), nanosecond)]
            return magic_number, (byteorder.lower() == 'little')

        # fetch values
        magic_number, lilendian = __make_magic__()                            # make magic number
        version = self.__args__.get('version', (2, 4))                        # version information
        version_major = self.__args__.get('version_major', version[0])        # major version number
        version_minor = self.__args__.get('version_minor', version[1])        # minor version number
        thiszone = self.__args__.get('thiszone', 0)                           # GMT to local correction
        sigfigs = self.__args__.get('sigfigs', 0)                             # accuracy of timestamps
        snaplen = self.__args__.get('snaplen', 262144)                        # max length of cap. packets, in octets
        network = self.__args__.get('network', LINKTYPE['NULL'])              # data link type
        network_default = self.__args__.get('network_default')                # default val. for unknown data link type
        network_reversed = self.__args__.get('network_reversed', False)       # if namespace is dict<str: int> pairs
        network_namespace = self.__args__.get('network_namespace', LINKTYPE)  # data link type namespace

        # make packet
        return b'%s%s%s%s%s%s%s' % (
            magic_number,
            self.pack(version_major, size=2, lilendian=lilendian),
            self.pack(version_minor, size=2, lilendian=lilendian),
            self.pack(thiszone, size=4, lilendian=lilendian),
            self.pack(sigfigs, size=4, lilendian=lilendian),
            self.pack(snaplen, size=4, lilendian=lilendian),
            self.index(network, network_default, namespace=network_namespace,
                       reversed=network_reversed, pack=True, lilendian=lilendian),
        )

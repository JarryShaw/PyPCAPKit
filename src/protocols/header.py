# -*- coding: utf-8 -*-
"""global header

`jspcap.protocols.header` contains `Header` only,
which implements extractor for global headers of PCAP,
whose structure is described as below.

typedef struct pcap_hdr_s {
    guint32 magic_number;   /* magic number */
    guint16 version_major;  /* major version number */
    guint16 version_minor;  /* minor version number */
    gint32  thiszone;       /* GMT to local correction */
    guint32 sigfigs;        /* accuracy of timestamps */
    guint32 snaplen;        /* max length of captured packets, in octets */
    guint32 network;        /* data link type */
} pcap_hdr_t;

"""
# Global Header
# Analyser for PCAP global headers


from jspcap.exceptions import FileError, UnsupportedCall
from jspcap.utilities import Info, VersionInfo
from jspcap.validations import int_check
from jspcap.protocols.link import LINKTYPE
from jspcap.protocols.protocol import Protocol


__all__ = ['Header']


class Header(Protocol):
    """PCAP file global header extractor.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * length -- int, header length of global header, i.e. 24
        * version -- VersionInfo, version infomation of input PCAP file
        * protocol -- str, data link type

    Methods:
        * index -- call `ProtoChain.index`
        * read_header -- read global header of PCAP file

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding procotol."""
        return 'Global Header'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 24

    @property
    def version(self):
        """Version infomation of input PCAP file."""
        return VersionInfo(self._info.version_major, self._info.version_minor)

    @property
    def protocol(self):
        """Data link type."""
        return self._info.network

    @property
    def protochain(self):
        """NotImplemented"""
        raise UnsupportedCall("'Header' object has no attribute 'protochain'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_header(self):
        """Read global header of PCAP file.

        Structure of global header (C):
            typedef struct pcap_hdr_s {
                guint32 magic_number;   /* magic number */
                guint16 version_major;  /* major version number */
                guint16 version_minor;  /* minor version number */
                gint32  thiszone;       /* GMT to local correction */
                guint32 sigfigs;        /* accuracy of timestamps */
                guint32 snaplen;        /* max length of captured packets, in octets */
                guint32 network;        /* data link type */
            } pcap_hdr_t;

        """
        _temp = self._read_fileng(4)
        if _temp != b'\xd4\xc3\xb2\xa1':
            raise FileError('Unknown file format.')

        _magn = _temp
        _vmaj = self._read_unpack(2, lilendian=True)
        _vmin = self._read_unpack(2, lilendian=True)
        _zone = self._read_unpack(4, lilendian=True, signed=True)
        _acts = self._read_unpack(4, lilendian=True)
        _slen = self._read_unpack(4, lilendian=True)
        _type = self._read_protos(4)

        header = dict(
            magic_number = _magn,
            version_major = _vmaj,
            version_minor = _vmin,
            thiszone = _zone,
            sigfigs = _acts,
            snaplen = _slen,
            network = _type,
        )

        return header

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file):
        self._file = file
        self._info = Info(self.read_header())

    def __len__(self):
        return 24

    def __length_hint__(self):
        return 24

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Positional arguments:
            * size  -- int, buffer size

        Returns:
            * str -- link layer protocol name

        """
        _byte = self._read_unpack(4, lilendian=True)
        _prot = LINKTYPE.get(_byte)
        return _prot

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, proto, length):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")

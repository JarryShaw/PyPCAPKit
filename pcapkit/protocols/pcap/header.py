# -*- coding: utf-8 -*-
"""global header

:mod:`pcapkit.protocols.pcap.header` contains
:class:`~pcapkit.protocols.pcap.header.Header`
only, which implements extractor for global
headers of PCAP, whose structure is described
as below:

.. code:: c

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
import io

from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import FileError, UnsupportedCall

__all__ = ['Header']


class Header(Protocol):
    """PCAP file global header extractor.

    Attributes:
        name (str): name of corresponding protocol
        info (Info): info dict of current instance
        alias (str): acronym of corresponding protocol
        length (int): header length of global header, i.e. 24
        version (VersionInfo): version infomation of input PCAP file
        protocol (str): data link type
        nanosecond (bool): nanosecond-resolution flag

        _file (io.BytesIO): bytes to be extracted
        _info (Info): info dict of current instance

    Methods:
        decode_bytes: try to decode ``bytes`` into ``str``
        decode_url: decode URLs into Unicode
        read_header: read global header of PCAP file

        _read_protos: read next layer protocol type
        _read_fileng: read file buffer
        _read_unpack: read bytes and unpack to integers
        _read_binary: read bytes and convert into binaries
        _read_packet: read raw packet data

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol."""
        return 'Global Header'

    @property
    def length(self):
        """Header length of corresponding protocol."""
        return 24

    @property
    def version(self):
        """Version infomation of input PCAP file."""
        return VersionInfo(self._info.version_major, self._info.version_minor)  # pylint: disable=E1101

    @property
    def payload(self):
        """Payload of current instance.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`payload`.

        """
        raise UnsupportedCall("'Header' object has no attribute 'payload'")

    @property
    def protocol(self):
        """Data link type."""
        return self._info.network  # pylint: disable=E1101

    @property
    def protochain(self):
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`protochain`.

        """
        raise UnsupportedCall("'Header' object has no attribute 'protochain'")

    @property
    def byteorder(self):
        """Header byte order."""
        return self._byte

    @property
    def nanosecond(self):
        """Nanosecond-resolution flag."""
        return self._nsec

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_header(self):
        """Read global header of PCAP file.

        Structure of global header (C):

        .. code:: c

            typedef struct pcap_hdr_s {
                guint32 magic_number;   /* magic number */
                guint16 version_major;  /* major version number */
                guint16 version_minor;  /* minor version number */
                gint32  thiszone;       /* GMT to local correction */
                guint32 sigfigs;        /* accuracy of timestamps */
                guint32 snaplen;        /* max length of captured packets, in octets */
                guint32 network;        /* data link type */
            } pcap_hdr_t;

        Notes:
            PCAP file has **four** different valid magic numbers.

            * ``d4 c3 b2 a1`` -- Little-endian microsecond-timestamp PCAP file.
            * ``a1 b2 c3 d4`` -- Big-endian microsecond-timestamp PCAP file.
            * ``4d 3c b2 a1`` -- Little-endian nanosecond-timestamp PCAP file.
            * ``a1 b2 3c 4d`` -- Big-endian nano-timestamp PCAP file.

        Returns:
            dict: Parsed packet data, as following structure::

                class MagicNumber(TypedDict):
                    \"\"\"PCAP magic number.\"\"\"

                    #: original magic number
                    data: bytes
                    #: byte order (``big`` / ``little``)
                    byteorder: str
                    #: nanosecond-timestamp support
                    nanosecond: bool

                class Header(TypedDict):
                    \"\"\"PCAP global header.\"\"\"

                    #: magic number
                    magic_number: MagicNumber
                    #: major version number
                    version_major: int
                    #: minor version number
                    version_minor: int
                    #: GMT to local correction
                    thiszone: int
                    #: accuracy of timestamps
                    sigfigs: int
                    #: max length of captured packets, in octets
                    snaplen: int
                    #: data link type
                    network: pcapkit.const.reg.linktype.LinkType

        Raises:
            FileError: If the magic number is invalid.

        """
        _magn = self._read_fileng(4)
        if _magn == b'\xd4\xc3\xb2\xa1':
            lilendian = True
            self._nsec = False
            self._byte = 'little'
        elif _magn == b'\xa1\xb2\xc3\xd4':
            lilendian = False
            self._nsec = False
            self._byte = 'big'
        elif _magn == b'\x4d\x3c\xb2\xa1':
            lilendian = True
            self._nsec = True
            self._byte = 'little'
        elif _magn == b'\xa1\xb2\x3c\x4d':
            lilendian = False
            self._nsec = True
            self._byte = 'big'
        else:
            raise FileError(5, 'Unknown file format', self._file.name)

        _vmaj = self._read_unpack(2, lilendian=lilendian)
        _vmin = self._read_unpack(2, lilendian=lilendian)
        _zone = self._read_unpack(4, lilendian=lilendian, signed=True)
        _acts = self._read_unpack(4, lilendian=lilendian)
        _slen = self._read_unpack(4, lilendian=lilendian)
        _type = self._read_protos(4)

        _byte = self._read_packet(24)
        self._file = io.BytesIO(_byte)

        header = dict(
            magic_number=dict(
                data=_magn,
                byteorder=self._byte,
                nanosecond=self._nsec,
            ),
            version_major=_vmaj,
            version_minor=_vmin,
            thiszone=_zone,
            sigfigs=_acts,
            snaplen=_slen,
            network=_type,
            packet=_byte,
        )

        return header

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, *args, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            *args: Arbitrary positional arguments.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        """
        self._file = file
        self._info = Info(self.read_header())

    def __len__(self):
        """Total length of corresponding protocol."""
        return 24

    def __length_hint__(self):
        """Return an estimated length for the object."""
        return 24

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Arguments:
            size (int) buffer size

        Returns:
            LinkType: link layer protocol enumeration

        """
        _byte = self._read_unpack(4, lilendian=True)
        _prot = LINKTYPE.get(_byte)
        return _prot

    def _decode_next_layer(self, *args, **kwargs):  # pylint: disable=arguments-differ
        """Decode next layer protocol.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_decode_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, *args, **kwargs):  # pylint: disable=arguments-differ
        """Import next layer extractor.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_import_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")

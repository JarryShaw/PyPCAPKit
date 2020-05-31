# -*- coding: utf-8 -*-
#: pylint: disable=line-too-long
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
import sys

from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import EndianError, FileError, UnsupportedCall

__all__ = ['Header']

#: Mapping of PCAP file magic numbers.
_MAGIC_NUM = {
    ('big', True):      b'\xa1\xb2\x3c\x4d',
    ('big', False):     b'\xa1\xb2\xc3\xd4',
    ('little', True):   b'\x4d\x3c\xb2\xa1',
    ('little', False):  b'\xd4\xc3\xb2\xa1',
}

class Header(Protocol):
    """PCAP file global header extractor."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: Literal['Global Header']
        """
        return 'Global Header'

    @property
    def length(self):
        """Header length of corresponding protocol.

        :rtype: Literal[24]
        """
        return 24

    @property
    def version(self):
        """Version infomation of input PCAP file.

        :rtype: pcapkit.corekit.version.VersionInfo
        """
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
        """Data link type.

        :rtype: pcapkit.const.reg.linktype.LinkType
        """
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
        """Header byte order.

        :rtype: Literal['big', 'little']
        """
        return self._byte

    @property
    def nanosecond(self):
        """Nanosecond-resolution flag.

        :rtype: bool
        """
        return self._nsec

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read global header of PCAP file.

        Notes:
            PCAP file has **four** different valid magic numbers.

            * ``d4 c3 b2 a1`` -- Little-endian microsecond-timestamp PCAP file.
            * ``a1 b2 c3 d4`` -- Big-endian microsecond-timestamp PCAP file.
            * ``4d 3c b2 a1`` -- Little-endian nanosecond-timestamp PCAP file.
            * ``a1 b2 3c 4d`` -- Big-endian nano-timestamp PCAP file.

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_Header: Parsed packet data.

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
            raise FileError(5, 'Unknown file format', self._file.name)  # pylint: disable=no-member

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

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            byteorder (str): header byte order
            lilendian (bool): little-endian flag
            bigendian (bool): big-endian flag
            nanosecond (bool): nanosecond-resolution file flag (default: :data:`False`)
            version (Tuple[int, int]): version information (default: ``(2, 4)``)
            version_major (int): major version number (default: ``2``)
            version_minor (int): minor version number (default: ``4``)
            thiszone (int): GMT to local correction (default: ``0``)
            sigfigs (int): accuracy of timestamps (default: ``0``)
            snaplen (int): max length of captured packets, in octets (default: ``262_144``)
            network (Union[pcapkit.const.reg.linktype.LinkType, enum.IntEnum, str, int]): data link type
                (default: :attr:`DLT_NULL <pcapkit.const.reg.linktype.LinkType.NULL>`)
            network_default (int): default value for unknown data link type
            network_namespace (Union[pcapkit.const.reg.linktype.LinkType, enum.IntEnum, Dict[str, int], Dict[int, str]): data link type namespace
                (default: :class:`~pcapkit.const.reg.linktype.LinkType`)
            network_reversed (bool): if namespace is ``str -> int`` pairs (default: :data:`False`)
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        # fetch values
        magic_number, lilendian = self._make_magic(**kwargs)           # make magic number
        version = kwargs.get('version', (2, 4))                        # version information
        version_major = kwargs.get('version_major', version[0])        # major version number
        version_minor = kwargs.get('version_minor', version[1])        # minor version number
        thiszone = kwargs.get('thiszone', 0)                           # GMT to local correction
        sigfigs = kwargs.get('sigfigs', 0)                             # accuracy of timestamps
        snaplen = kwargs.get('snaplen', 262144)                        # max length of cap. packets, in octets
        network = kwargs.get('network', LINKTYPE['NULL'])              # data link type
        network_default = kwargs.get('network_default')                # default val. for unknown data link type
        network_reversed = kwargs.get('network_reversed', False)       # if namespace is ``str -> int`` pairs
        network_namespace = kwargs.get('network_namespace', LINKTYPE)  # data link type namespace

        # make packet
        return b'%s%s%s%s%s%s%s' % (
            magic_number,
            self._make_pack(version_major, size=2, lilendian=lilendian),
            self._make_pack(version_minor, size=2, lilendian=lilendian),
            self._make_pack(thiszone, size=4, lilendian=lilendian),
            self._make_pack(sigfigs, size=4, lilendian=lilendian),
            self._make_pack(snaplen, size=4, lilendian=lilendian),
            self._make_index(network, network_default, namespace=network_namespace,
                             reversed=network_reversed, pack=True, lilendian=lilendian),
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file=None, length=None, **kwargs):  # pylint: disable=unused-argument
        """Post initialisation hook.

        Args:
            file (Optional[io.BytesIO]): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        if file is None:
            _data = self.make(**kwargs)
        else:
            _data = file.read(self.__len__())

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        if hasattr(file, 'name'):  # set back source filename
            self._file.name = file.name
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = Info(self.read())

    def __len__(self):
        """Total length of corresponding protocol.

        :rtype: Literal[24]
        """
        return 24

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[24]
        """
        return 24

    @classmethod
    def __index__(cls):
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size):
        """Read next layer protocol type.

        Arguments:
            size (int) buffer size

        Returns:
            pcapkit.const.reg.linktype.LinkType: link layer protocol enumeration

        """
        _byte = self._read_unpack(4, lilendian=True)
        _prot = LINKTYPE.get(_byte)
        return _prot

    def _make_magic(self, **kwargs):  # pylint: disable=no-self-use
        """Generate magic number.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Tuple[bytes, bool]: Magic number and little-endian flag.

        """
        nanosecond = bool(kwargs.get('nanosecond', False))   # nanosecond-resolution file flag
        byteorder = kwargs.get('byteorder', sys.byteorder)   # header byte order
        lilendian = kwargs.get('lilendian')                  # little-endian flag
        bigendian = kwargs.get('bigendian')                  # big-endian flag

        if lilendian is not None and bigendian is not None:
            if lilendian == bigendian:
                raise EndianError('unresolved byte order')
            if bigendian:
                return _MAGIC_NUM[('big', False)], False
            if lilendian:
                return _MAGIC_NUM[('little', True)], True

        if byteorder.lower() not in ('little', 'big'):
            raise EndianError(f"unknown byte order: {byteorder!r}")

        magic_number = _MAGIC_NUM[(byteorder.lower(), nanosecond)]
        return magic_number, (byteorder.lower() == 'little')

    def _decode_next_layer(self, *args, **kwargs):  # pylint: disable=signature-differs
        """Decode next layer protocol.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_decode_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, *args, **kwargs):  # pylint: disable=signature-differs
        """Import next layer extractor.

        Args:
            *args: arbitrary positional arguments

        Keyword Args:
            **kwargs: arbitrary keyword arguments

        Raises:
            UnsupportedCall: This protocol doesn't support :meth:`_import_next_layer`.

        """
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")

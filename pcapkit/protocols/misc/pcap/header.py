# -*- coding: utf-8 -*-
"""Global Header
===================

:mod:`pcapkit.protocols.misc.pcap.header` contains
:class:`~pcapkit.protocols.misc.pcap.Header` only,
which implements extractor for global headers [*]_
of PCAP, whose structure is described as below:

.. code-block:: c

    typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
    } pcap_hdr_t;

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header

"""
import io
import operator
import sys
from typing import TYPE_CHECKING, overload

from pcapkit.const.reg.linktype import LinkType as RegType_LinkType
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.data.misc.pcap.header import Header as DataType_Header
from pcapkit.protocols.data.misc.pcap.header import MagicNumber as DataType_MagicNumber
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import EndianError, FileError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, BinaryIO, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

__all__ = ['Header']

#: dict[tuple[str, bool], bytes]: Mapping of PCAP file magic numbers. The key
#: is a :obj:`tuple` of endianness (``big`` or ``little``) and nanosecond-
#: timestamp resolution flag (:data:`True` refers to nanosecond-resolution
#: timestamp, :data:`False` refers to microsecond-resolution timestamp); the
#: value is the corresponding PCAP file magic number sequence.
_MAGIC_NUM = {
    ('big', True):      b'\xa1\xb2\x3c\x4d',
    ('big', False):     b'\xa1\xb2\xc3\xd4',
    ('little', True):   b'\x4d\x3c\xb2\xa1',
    ('little', False):  b'\xd4\xc3\xb2\xa1',
}


class Header(Protocol[DataType_Header]):
    """PCAP file global header extractor."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Global Header"]':
        """Name of corresponding protocol."""
        return 'Global Header'

    @property
    def length(self) -> 'Literal[24]':
        """Header length of corresponding protocol."""
        return 24

    @property
    def version(self) -> 'VersionInfo':
        """Version infomation of input PCAP file."""
        return self._info.version

    @property
    def payload(self) -> 'NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`payload`.

        """
        raise UnsupportedCall("'Header' object has no attribute 'payload'")

    @property
    def protocol(self) -> 'RegType_LinkType':
        """Data link type."""
        return self._info.network

    @property
    def protochain(self) -> 'NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`protochain`.

        """
        raise UnsupportedCall("'Header' object has no attribute 'protochain'")

    @property
    def byteorder(self) -> 'Literal["big", "little"]':
        """Header byte order."""
        return self._byte

    @property
    def nanosecond(self) -> bool:
        """Nanosecond-resolution flag."""
        return self._nsec

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_Header':  # pylint: disable=unused-argument
        """Read global header of PCAP file.

        Notes:
            PCAP file has **four** different valid magic numbers.

            * ``d4 c3 b2 a1`` -- Little-endian microsecond-timestamp PCAP file.
            * ``a1 b2 c3 d4`` -- Big-endian microsecond-timestamp PCAP file.
            * ``4d 3c b2 a1`` -- Little-endian nanosecond-timestamp PCAP file.
            * ``a1 b2 3c 4d`` -- Big-endian nano-timestamp PCAP file.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            FileError: If the magic number is invalid.

        """
        if TYPE_CHECKING:
            self._byte: 'Literal["big", "little"]'

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

        header = DataType_Header(
            magic_number=DataType_MagicNumber(
                data=_magn,
                byteorder=self._byte,
                nanosecond=self._nsec,
            ),
            version=VersionInfo(_vmaj, _vmin),
            thiszone=_zone,
            sigfigs=_acts,
            snaplen=_slen,
            network=_type,
        )

        return header

    def make(self, *, byteorder: 'Literal["big", "little"]' = sys.byteorder,  # pylint: disable=arguments-differ
             lilendian: 'Optional[bool]' = None, bigendian: 'Optional[bool]' = None,
             nanosecond: bool = False, version: 'tuple[int, int] | VersionInfo' = (2, 4),
             version_major: 'Optional[int]' = None, version_minor: 'Optional[int]' = None,
             thiszone: int = 0, sigfigs: int = 0, snaplen: int = 0x40_000,
             network: 'RegType_LinkType | StdlibEnum | AenumEnum | str | int' = RegType_LinkType.NULL,
             network_default: 'Optional[int]' = None,
             network_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,
             network_reversed: bool = False, **kwargs: 'Any') -> 'bytes':
        """Make (construct) packet data.

        Args:
            byteorder: header byte order
            lilendian: little-endian flag
            bigendian: big-endian flag
            nanosecond: nanosecond-resolution file flag
            version: version information
            version_major: major version number
            version_minor: minor version number
            thiszone: GMT to local correction
            sigfigs: accuracy of timestamps
            snaplen: max length of captured packets, in octets
            network: data link type
            network_default: default value for unknown data link type
            network_namespace: data link type namespace
            network_reversed: if namespace is ``str -> int`` pairs
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        magic_number, lilendian = self._make_magic(                    # make magic number
            byteorder, lilendian, bigendian, nanosecond)

        if version_major is None:
            version_major = version[0]
        if version_minor is None:
            version_minor = version[1]

        # make packet
        return b'%s%s%s%s%s%s%s' % (
            magic_number,
            self._make_pack(version_major, size=2, lilendian=lilendian),
            self._make_pack(version_minor, size=2, lilendian=lilendian),
            self._make_pack(thiszone, size=4, lilendian=lilendian),
            self._make_pack(sigfigs, size=4, lilendian=lilendian),
            self._make_pack(snaplen, size=4, lilendian=lilendian),
            self._make_index(network, network_default, namespace=network_namespace,  # type: ignore[call-overload]
                             reversed=network_reversed, pack=True, lilendian=lilendian),
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        if file is None:
            _data = self.make(**kwargs)
        else:
            _data = file.read(operator.length_hint(self))

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        if file is not None and hasattr(file, 'name'):  # set back source filename
            self._file.name = file.name
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.read()

    def __len__(self) -> 'Literal[24]':
        """Total length of corresponding protocol."""
        return 24

    def __length_hint__(self) -> 'Literal[24]':
        """Return an estimated length for the object."""
        return 24

    @classmethod
    def __index__(cls) -> 'NoReturn':
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: int) -> 'RegType_LinkType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            Link layer protocol enumeration.

        """
        _byte = self._read_unpack(4, lilendian=True)
        _prot = RegType_LinkType.get(_byte)
        return _prot

    def _make_magic(self, byteorder: 'Literal["big", "little"]' = sys.byteorder,
                    lilendian: 'Optional[bool]' = None, bigendian: 'Optional[bool]' = None,
                    nanosecond: bool = False) -> 'tuple[bytes, bool]':
        """Generate magic number.

        Args:
            byteorder: header byte order
            lilendian: little-endian flag
            bigendian: big-endian flag
            nanosecond: nanosecond-resolution file flag

        Returns:
            Magic number and little-endian flag.

        """
        if lilendian is not None and bigendian is not None:
            if lilendian == bigendian:
                raise EndianError('unresolved byte order')
            if bigendian:
                return _MAGIC_NUM[('big', False)], False
            if lilendian:
                return _MAGIC_NUM[('little', True)], True

        if byteorder not in ('little', 'big'):
            raise EndianError(f"unknown byte order: {byteorder!r}")

        magic_number = _MAGIC_NUM[(byteorder, nanosecond)]
        return magic_number, (byteorder == 'little')

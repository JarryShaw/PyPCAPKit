# -*- coding: utf-8 -*-
"""Global Header
===================

.. module:: pcapkit.protocols.misc.pcap.header

:mod:`pcapkit.protocols.misc.pcap.header` contains
:class:`~pcapkit.protocols.misc.pcap.header.Header` only,
which implements an extractor for global headers [*]_
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

.. versionchanged:: 1.5.0

   A global header cut short rebuilds as captured, where it rebuilt at full
   width (:issue:`1470`).

"""
import io
import operator
import sys
from typing import TYPE_CHECKING, overload

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.version import VersionInfo
from pcapkit.protocols.data.misc.pcap.header import Header as Data_Header
from pcapkit.protocols.data.misc.pcap.header import MagicNumber as Data_MagicNumber
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.misc.pcap.header import GLOBAL_HEADER_LEN, MAGIC_NUMBER
from pcapkit.protocols.schema.misc.pcap.header import Header as Schema_Header
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities.exceptions import EndianError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import IO, Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal, Self

__all__ = ['Header']

#: The PCAP magic number for each byte order and nanosecond flag, the reverse of
#: :data:`~pcapkit.protocols.schema.misc.pcap.header.MAGIC_NUMBER`, so that
#: :meth:`Header._make_magic` looks one up rather than searching for it -- an
#: undeclared pair raises :exc:`KeyError`.
_DECLARED_MAGIC = {declared: magic for magic, declared in MAGIC_NUMBER.items()}


class Header(ProtocolBase[Data_Header, Schema_Header],
             schema=Schema_Header, data=Data_Header):
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
        return GLOBAL_HEADER_LEN  # type: ignore[return-value]

    @property
    def version(self) -> 'VersionInfo':
        """Version information of input PCAP file."""
        return self._info.version

    @property
    def payload(self) -> 'NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: This protocol doesn't support :attr:`payload`.

        """
        raise UnsupportedCall("'Header' object has no attribute 'payload'")

    @property
    def protocol(self) -> 'Enum_LinkType':
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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Header':  # pylint: disable=unused-argument
        """Read global header of PCAP file.

        Notes:
            PCAP file has **four** different valid magic numbers.

            * ``d4 c3 b2 a1`` -- Little-endian microsecond-timestamp PCAP file.
            * ``a1 b2 c3 d4`` -- Big-endian microsecond-timestamp PCAP file.
            * ``4d 3c b2 a1`` -- Little-endian nanosecond-timestamp PCAP file.
            * ``a1 b2 3c 4d`` -- Big-endian nanosecond-timestamp PCAP file.

        Args:
            length: Length of data to be read.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the magic number is invalid. Parsing does not get
                this far with one: the schema's
                :func:`~pcapkit.protocols.schema.misc.pcap.header.magic_number_callback`
                raises it while the header is unpacked.

        """
        if TYPE_CHECKING:
            self._byte: 'Literal["big", "little"]'
        schema = self.__header__

        _magn = schema.magic_number
        # NOTE: looked up as :obj:`bytes`, so that a :obj:`bytearray` magic
        # number is matched rather than rejected as unhashable. The lookup
        # cannot miss: ``magic_number_callback`` has already raised for a magic
        # number this mapping does not hold.
        self._byte, self._nsec = MAGIC_NUMBER[bytes(_magn)]

        header = Data_Header(
            magic_number=Data_MagicNumber(
                data=_magn,
                byteorder=self._byte,
                nanosecond=self._nsec,
            ),
            version=VersionInfo(schema.version_major, schema.version_minor),
            thiszone=schema.thiszone,
            sigfigs=schema.sigfigs,
            snaplen=schema.snaplen,
            network=schema.network,
        )

        return header

    def make(self,
             byteorder: 'Literal["big", "little"]' = sys.byteorder,
             lilendian: 'Optional[bool]' = None,
             bigendian: 'Optional[bool]' = None,
             nanosecond: bool = False,
             version: 'tuple[int, int] | VersionInfo' = (2, 4),
             version_major: 'Optional[int]' = None,
             version_minor: 'Optional[int]' = None,
             thiszone: int = 0, sigfigs: int = 0,
             snaplen: int = 0x40_000,
             network: 'Enum_LinkType | StdlibEnum | AenumEnum | str | int' = Enum_LinkType.NULL,
             network_default: 'Optional[int]' = None,
             network_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,
             network_reversed: bool = False,
             **kwargs: 'Any') -> 'Schema_Header':
        """Make (construct) packet data.

        Args:
            byteorder: header byte order
            lilendian: little-endian flag; overrides ``byteorder`` if given
            bigendian: big-endian flag; overrides ``byteorder`` if given
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
        # make magic number
        magic_number, lilendian = self._make_magic(byteorder, lilendian, bigendian, nanosecond)

        if version_major is None:
            version_major = version[0]
        if version_minor is None:
            version_minor = version[1]

        return Schema_Header(
            magic_number=magic_number,
            version_major=version_major,
            version_minor=version_minor,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=self._make_index(network, network_default, namespace=network_namespace,
                                     reversed=network_reversed, pack=False),
        )

    @classmethod
    def from_data(cls, data: 'Data_Header | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: Construction keywords, as for :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance, cut back to what was captured when the header
            it was parsed from was cut short (:issue:`1470`).

        """
        return replay_short_read(super().from_data(data, **kwargs), data)

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction arguments, please refer to :meth:`make`.

        Notes:
            A header the data ends inside keeps that in its
            :attr:`~pcapkit.protocols.protocol.Protocol.info`, so that
            :meth:`~pcapkit.protocols.protocol.Protocol.from_data` rebuilds only what was captured
            (:issue:`1470`).

        """
        if file is None:
            _data = self.pack(**kwargs)
        else:
            _data = file if isinstance(file, bytes) else file.read(operator.length_hint(self))

        #: bytes: Raw packet data.
        self._data = _data
        #: io.BytesIO: Source packet stream.
        self._file = io.BytesIO(self._data)
        if file is not None and hasattr(file, 'name'):  # set back source filename
            self._file.name = file.name
        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.unpack(length, **kwargs)
        keep_short_read(self)

    def __len__(self) -> 'Literal[24]':
        """Total length of corresponding protocol."""
        return GLOBAL_HEADER_LEN  # type: ignore[return-value]

    def __length_hint__(self) -> 'Literal[24]':
        """Return an estimated length for the object."""
        return GLOBAL_HEADER_LEN  # type: ignore[return-value]

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

    @classmethod
    def _make_data(cls, data: 'Data_Header') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'byteorder': data.magic_number.byteorder,
            'nanosecond': data.magic_number.nanosecond,
            'version_major': data.version.major,
            'version_minor': data.version.minor,
            'thiszone': data.thiszone,
            'sigfigs': data.sigfigs,
            'snaplen': data.snaplen,
            'network': data.network,
        }

    def _read_protos(self, size: int) -> 'Enum_LinkType':
        """Read next layer protocol type.

        Reads ``size`` octets as an unsigned integer in the file's byte order
        (:attr:`byteorder`), falling back to little-endian before :meth:`read`
        has set it (:issue:`2312`).

        Arguments:
            size: buffer size

        Returns:
            Link layer protocol enumeration.

        """
        _byte = self._read_unpack(size, lilendian=getattr(self, '_byte', 'little') == 'little')
        _prot = Enum_LinkType.get(_byte)
        return _prot

    def _make_magic(self, byteorder: 'Literal["big", "little"]' = sys.byteorder,
                    lilendian: 'Optional[bool]' = None, bigendian: 'Optional[bool]' = None,
                    nanosecond: bool = False) -> 'tuple[bytes, bool]':
        """Generate magic number.

        Args:
            byteorder: header byte order
            lilendian: little-endian flag; overrides ``byteorder`` if given
            bigendian: big-endian flag; overrides ``byteorder`` if given
            nanosecond: nanosecond-resolution file flag

        Returns:
            Magic number and little-endian flag.

        """
        if lilendian is not None and bigendian is not None and lilendian == bigendian:
            raise EndianError('PCAP: unresolved byte order')
        if bigendian is not None:
            byteorder = 'big' if bigendian else 'little'
        elif lilendian is not None:
            byteorder = 'little' if lilendian else 'big'

        if byteorder not in ('little', 'big'):
            raise EndianError(f'PCAP: unknown byte order: {byteorder!r}')

        magic_number = _DECLARED_MAGIC[(byteorder, nanosecond)]
        return magic_number, (byteorder == 'little')

# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Frame Header
==================

.. module:: pcapkit.protocols.misc.pcap.frame

:mod:`pcapkit.protocols.misc.pcap.frame` contains
:class:`~pcapkit.protocols.misc.pcap.frame.Frame` only,
which implements extractor for frame headers [*]_ of PCAP,
whose structure is described as below:

.. code-block:: c

    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;     /* timestamp seconds */
        guint32 ts_usec;    /* timestamp microseconds */
        guint32 incl_len;   /* number of octets of packet saved in file */
        guint32 orig_len;   /* actual length of packet */
    } pcaprec_hdr_t;

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header

"""
import collections
import datetime
import decimal
import io
import sys
import time
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.misc.pcap.frame import Frame as Data_Frame
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.protocols.schema.misc.pcap.frame import Frame as Schema_Frame
from pcapkit.utilities.compat import localcontext
from pcapkit.utilities.exceptions import RegistryError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from decimal import Decimal
    from typing import IO, Any, DefaultDict, Optional, Type

    from typing_extensions import Literal

    from pcapkit.protocols.data.misc.pcap.header import Header as Data_Header
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['Frame']

# check Python version
py37 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 7)


class Frame(Protocol[Data_Frame, Schema_Frame],
            schema=Schema_Frame, data=Data_Frame):
    """Per packet frame header extractor.

    This class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.misc.pcap.frame.Frame.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`pcapkit.const.reg.linktype.LinkType.ETHERNET`
         - :class:`pcapkit.protocols.link.ethernet.Ethernet`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV4`
         - :class:`pcapkit.protocols.internet.ipv4.IPv4`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV6`
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_LinkType, ModuleDescriptor[Protocol] | Type[Protocol]]: Protocol index mapping for
    #: decoding next layer, c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name, or
    #: a :class:`~pcapkit.protocols.protocol.Protocol` subclass.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_LinkType.ETHERNET: ModuleDescriptor('pcapkit.protocols.link', 'Ethernet'),
            Enum_LinkType.IPV4:     ModuleDescriptor('pcapkit.protocols.internet', 'IPv4'),
            Enum_LinkType.IPV6:     ModuleDescriptor('pcapkit.protocols.internet', 'IPv6'),
        },
    )  # type: DefaultDict[Enum_LinkType | int, ModuleDescriptor[Protocol] | Type[Protocol]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of corresponding protocol."""
        return f'Frame {self._fnum}'

    @property
    def length(self) -> 'Literal[16]':
        """Header length of corresponding protocol."""
        return 16

    @property
    def header(self) -> 'Data_Header':
        """Global header of the PCAP file."""
        return self._ghdr

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'Enum_LinkType', protocol: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
            module: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, Protocol):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
        cls.__proto__[code] = protocol

    def index(self, name: 'str | Protocol | Type[Protocol]') -> 'int':
        """Call :meth:`ProtoChain.index <pcapkit.corekit.protochain.ProtoChain.index>`.

        Args:
            name: ``name`` to be searched

        Returns:
            First index of ``name``.

        Raises:
            IndexNotFound: if ``name`` is not present

        """
        return self._protos.index(name)

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        self.__header__ = self.make(**kwargs)
        packet = kwargs.get('__packet__', {})  # packet data
        packet['byteorder'] = self._ghdr.magic_number.byteorder
        return self.__header__.pack(packet)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Frame':
        """Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            We used a special keyword argument ``__packet__`` to pass the
            global packet data to underlying methods. This is useful when
            the packet data is not available in the current instance.

        """
        if cast('Optional[Schema_Frame]', self.__header__) is None:
            packet = kwargs.get('__packet__', {})  # packet data
            packet['bytesorder'] = self._ghdr.magic_number.byteorder
            self.__header__ = cast('Schema_Frame', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        return self.read(length, **kwargs)

    def read(self, length: 'Optional[int]' = None, *, _read: 'bool' = True, **kwargs: 'Any') -> 'Data_Frame':
        r"""Read each block after global header.

        Args:
            length: Length of data to be read.
            \_read: If the class is called in a parsing scenario.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Data_Frame: Parsed packet data.

        """
        schema = self.__header__

        _tsss = schema.ts_sec
        _tsus = schema.ts_usec
        _ilen = schema.incl_len
        _olen = schema.orig_len

        with localcontext(prec=64):
            if self._nsec:
                _epch = _tsss + decimal.Decimal(_tsus) / 1_000_000_000
            else:
                _epch = _tsss + decimal.Decimal(_tsus) / 1_000_000
        _irat = _epch.as_integer_ratio()

        try:
            _time = datetime.datetime.fromtimestamp(_irat[0] / _irat[1])
        except ValueError:
            warn(f'PCAP: invalid timestamp: {_epch}', ProtocolWarning, stacklevel=stacklevel())
            _time = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)

        frame = Data_Frame(
            frame_info=Data_FrameInfo(
                ts_sec=_tsss,
                ts_usec=_tsus,
                incl_len=_ilen,
                orig_len=_olen,
            ),
            time=_time,
            number=self._fnum,
            time_epoch=_epch,
            len=_ilen,
            cap_len=_olen,
        )

        if not _read:
            # move backward to the beginning of the packet
            self._file.seek(0, io.SEEK_SET)
        else:
            # NOTE: We create a copy of the frame data here for parsing
            # scenarios to keep the original frame data intact.
            seek_cur = self._file.tell()

            # move backward to the beginning of the frame
            self._file.seek(-self.length, io.SEEK_CUR)

            #: bytes: Raw frame data.
            self._data = self._read_fileng(self.length + _ilen)

            # move backward to the beginning of frame's payload
            self._file.seek(seek_cur, io.SEEK_SET)

            #: io.BytesIO: Source data stream.
            self._file = io.BytesIO(self._data)

        return self._decode_next_layer(frame, self._ghdr.network, frame.len)

    def make(self,
             timestamp: 'Optional[float | Decimal | int | dt_type]' = None,
             ts_sec: 'Optional[int]' = None,
             ts_usec: 'Optional[int]' = None,
             incl_len: 'Optional[int]' = None,
             orig_len: 'Optional[int]' = None,
             packet: 'bytes | Protocol | Schema' = b'',
             nanosecond: 'bool' = False,
             **kwargs: 'Any') -> 'Schema_Frame':
        """Make frame packet data.

        Args:
            timestamp: UNIX-Epoch timestamp
            ts_sec: timestamp seconds
            ts_usec: timestamp microseconds
            incl_len: number of octets of packet saved in file
            orig_len: actual length of packet
            packet: raw packet data
            nanosecond: nanosecond-resolution file flag
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        ts_sec, ts_usec = self._make_timestamp(timestamp, ts_sec, ts_usec, nanosecond)

        if incl_len is None:
            incl_len = min(len(packet), self._ghdr.snaplen)
        if orig_len is None:
            orig_len = len(packet)

        return Schema_Frame(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
            packet=packet,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      num: 'int', header: 'Data_Header', **kwargs: 'Any') -> 'None': ...
    @overload
    def __post_init__(self, *, num: 'int', header: 'Data_Header',  # pylint: disable=arguments-differ
                      **kwargs: 'Any') -> 'None': ...

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      num: 'int', header: 'Data_Header', **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            num: Frame index number.
            header: Global header of the PCAP file.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: int: frame index number
        self._fnum = num
        #: pcapkit.protocols.misc.pcap.header.Header: Global header of the PCAP file.
        self._ghdr = header

        #: pcapkit.const.reg.linktype.LinkType: next layer protocol index
        self._prot = header.network
        #: bool: nanosecond-timestamp PCAP flag
        self._nsec = header.magic_number.nanosecond

        if file is None:
            _read = False
            #: bytes: Raw packet data.
            self._data = self.pack(**kwargs)
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)
        else:
            _read = True
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(file) if isinstance(file, bytes) else file

        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.unpack(length, _read=_read, **kwargs)

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    # NOTE: This is a hack to make the ``__index__`` method work both as a
    # class method and an instance method.
    def __index__(self: 'Optional[Frame]' = None) -> 'int':  # type: ignore[override]
        """Index of the frame.

        Args:
            self: :class:`Frame` object or :obj:`None`.

        Returns:
            If the object is initiated, i.e. :attr:`self._fnum <pcapkit.protocols.misc.pcap.frame.Frame._fnum>`
            exists, returns the frame index number of itself; else raises :exc:`UnsupportedCall`.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        if self is None:
            raise UnsupportedCall("'Frame' object cannot be interpreted as an integer")
        return self._fnum

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Frame') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'ts_src': data.frame_info.ts_sec,
            'ts_usec': data.frame_info.ts_usec,
            'incl_len': data.frame_info.incl_len,
            'orig_len': data.frame_info.orig_len,
            'packet': cls._make_payload(data),
        }

    def _make_timestamp(self, timestamp: 'Optional[float | Decimal | dt_type | int]' = None, ts_sec: 'Optional[int]' = None,
                        ts_usec: 'Optional[int]' = None, nanosecond: 'bool' = False) -> 'tuple[int, int]':
        """Make timestamp.

        Args:
            timestamp: UNIX-Epoch timestamp
            ts_sec: timestamp seconds
            ts_usec: timestamp microseconds
            nanosecond: nanosecond-resolution file flag

        Returns:
            Second and microsecond/nanosecond value of timestamp.

        """
        with localcontext(prec=64):
            if timestamp is None:
                if py37 and nanosecond:
                    timestamp = decimal.Decimal(time.time_ns()) / 1_000_000_000
                else:
                    timestamp = decimal.Decimal(time.time())
            else:
                if isinstance(timestamp, datetime.datetime):
                    timestamp = timestamp.timestamp()
                timestamp = decimal.Decimal(timestamp)

        if ts_sec is None:
            ts_sec = int(timestamp)

        if ts_usec is None:
            ts_usec = int((timestamp - ts_sec) * (1_000_000_000 if nanosecond else 1_000_000))

        return ts_sec, ts_usec

    def _decode_next_layer(self, dict_: 'Data_Frame', proto: 'Optional[int]' = None,
                           length: 'Optional[int]' = None, *, packet: 'Optional[dict[str, Any]]' = None) -> 'Data_Frame':  # pylint: disable=arguments-differ
        r"""Decode next layer protocol.

        Arguments:
            dict\_: info buffer
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with packet extracted.

        Notes:
            We added a new key ``__next_type__`` to ``dict_`` to store the
            next layer protocol type, and a new key ``__next_name__`` to
            store the next layer protocol name. These two keys will **NOT**
            be included when :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` is called.

            We also added a new key ``protocols`` to ``dict_`` to store the
            protocol chain of the current packet (frame).

        """
        next_ = cast('Protocol', self._import_next_layer(proto, length, packet=packet))  # type: ignore[misc,call-arg,redundant-cast]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__({
            layer: info,
            'protocols': chain.chain if chain else '',
            '__next_type__': type(next_),
            '__next_name__': layer,
        })
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = chain  # pylint: disable=attribute-defined-outside-init
        return dict_

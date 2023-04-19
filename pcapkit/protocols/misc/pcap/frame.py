# -*- coding: utf-8 -*-
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
from pcapkit.protocols.data.misc.pcap.frame import Frame as Data_Frame
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.protocols.protocol import Protocol
from pcapkit.protocols.schema.misc.pcap.frame import Frame as Schema_Frame
from pcapkit.utilities.exceptions import UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from decimal import Decimal
    from typing import IO, Any, Optional, Type

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

    #: DefaultDict[int, tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: The values should be a tuple representing the module name and class name.
    __proto__ = collections.defaultdict(
        lambda: ('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_LinkType.ETHERNET: ('pcapkit.protocols.link', 'Ethernet'),
            Enum_LinkType.IPV4:     ('pcapkit.protocols.internet', 'IPv4'),
            Enum_LinkType.IPV6:     ('pcapkit.protocols.internet', 'IPv6'),
        },
    )

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
    def register(cls, code: 'Enum_LinkType', module: 'str', class_: 'str') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
            module: module name
            class\_: class name

        """
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
        cls.__proto__[code] = (module, class_)

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

        if self._nsec:
            _epch = _tsss + decimal.Decimal(_tsus) / 1_000_000_000
        else:
            _epch = _tsss + decimal.Decimal(_tsus) / 1_000_000
        _time = datetime.datetime.fromtimestamp(float(_epch))

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
            # NOTE: We create a copy of the frame packet data here for parsing
            # scenarios to keep the original packet data intact.

            #: bytes: Raw packet data.
            self._data = schema.packet
            #: io.BytesIO: Source packet stream.
            self._file = io.BytesIO(self._data)

            # move forward to the beginning of frame's first packet
            self._file.seek(self.length, io.SEEK_CUR)

        return self._decode_next_layer(frame, self._ghdr.network, frame.len)

    def make(self,
             timestamp: 'Optional[float | Decimal]' = None,
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

    @overload  # type: ignore[override]
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

    def _make_timestamp(self, timestamp: 'Optional[float | Decimal]' = None, ts_sec: 'Optional[int]' = None,
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
        if timestamp is None:
            if py37 and nanosecond:
                timestamp = decimal.Decimal(time.time_ns()) / 1_000_000_000
            else:
                timestamp = decimal.Decimal(time.time())
        else:
            timestamp = decimal.Decimal(timestamp)

        if ts_sec is None:
            ts_sec = int(timestamp)

        if ts_usec is None:
            ts_usec = int(timestamp - ts_sec) * (1_000_000_000 if nanosecond else 1_000_000)

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

        """
        next_ = cast('Protocol', self._import_next_layer(proto, length, packet=packet))  # type: ignore[misc,call-arg,redundant-cast]
        info, chain = next_.info, next_.protochain

        # make next layer protocol name
        layer = next_.info_name
        # proto = next_.__class__.__name__

        # write info and protocol chain into dict
        dict_.__update__({
            layer: info,
            'protocols': chain.chain,
            '__next_type__': type(next_),
            '__next_name__': layer,
        })
        self._next = next_  # pylint: disable=attribute-defined-outside-init
        self._protos = chain  # pylint: disable=attribute-defined-outside-init
        return dict_

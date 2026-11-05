# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Frame Header
==================

.. module:: pcapkit.protocols.misc.pcap.frame.protocol

:mod:`pcapkit.protocols.misc.pcap.frame.protocol` contains
:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` only,
which implements an extractor for frame headers [*]_ of PCAP,
whose structure is described as below:

.. code-block:: c

    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;     /* timestamp seconds */
        guint32 ts_usec;    /* timestamp microseconds */
        guint32 incl_len;   /* number of octets of packet saved in file */
        guint32 orig_len;   /* actual length of packet */
    } pcaprec_hdr_t;

.. [*] https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header

.. versionchanged:: 1.5.0

   ``bytes(frame)`` and :attr:`~pcapkit.protocols.protocol.Protocol.packet`
   hold this frame's own octets, where they held the next frame's
   (:issue:`357`), and the parsed ``time`` is timezone-aware UTC. The parsed
   ``len`` is the on-wire length and ``cap_len`` the captured one, where the
   two were swapped (:issue:`618`).

"""
import collections
import datetime
import decimal
import io
import sys
import time
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.io import advance
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame
from pcapkit.protocols.misc.pcap.frame.data import FrameInfo as Data_FrameInfo
from pcapkit.protocols.misc.pcap.frame.schema import RECORD_HEADER_LEN
from pcapkit.protocols.misc.pcap.frame.schema import Frame as Schema_Frame
from pcapkit.protocols.misc.pcap.header.schema import RESOLUTION
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.utilities.compat import localcontext
from pcapkit.utilities.contextvars import frame_length
from pcapkit.utilities.datetime import fromtimestamp, totimestamp
from pcapkit.utilities.exceptions import StreamEOFError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from decimal import Decimal
    from typing import IO, Any, ClassVar, DefaultDict, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.misc.pcap.header.data import Header as Data_Header
    from pcapkit.protocols.schema import Schema

__all__ = ['Frame']


class Frame(ProtocolBase[Data_Frame, Schema_Frame],
            schema=Schema_Frame, data=Data_Frame):
    """Per packet frame header extractor.

    This class supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.misc.pcap.frame.protocol.Frame.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`pcapkit.const.reg.linktype.LinkType.NULL`
         - :class:`pcapkit.protocols.link.loopback.protocol.Loopback`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.ETHERNET`
         - :class:`pcapkit.protocols.link.ethernet.protocol.Ethernet`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IEEE802_11`
         - :class:`pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.FRELAY`
         - :class:`pcapkit.protocols.link.frad.protocol.FRAD`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.LOOP`
         - :class:`pcapkit.protocols.link.loopback.protocol.Loopback`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.LINUX_SLL`
         - :class:`pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IEEE802_11_RADIOTAP`
         - :class:`pcapkit.protocols.link.radiotap.protocol.Radiotap`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV4`
         - :class:`pcapkit.protocols.internet.ipv4.protocol.IPv4`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.IPV6`
         - :class:`pcapkit.protocols.internet.ipv6.protocol.IPv6`
       * - :attr:`pcapkit.const.reg.linktype.LinkType.LINUX_SLL2`
         - :class:`pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2`

    :attr:`pcapkit.const.reg.linktype.LinkType.RAW` has no entry of its own:
    its data is dispatched as ``IPV4`` or ``IPV6`` by the version nibble of
    its first octet, see :meth:`_dispatch_linktype`.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding the next layer; see
    #: :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: and :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: Each value is a :class:`~pcapkit.corekit.module.ModuleDescriptor` naming the
    #: module and class, or a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
        {
            Enum_LinkType.NULL:                ModuleDescriptor('pcapkit.protocols.link', 'Loopback'),
            Enum_LinkType.ETHERNET:            ModuleDescriptor('pcapkit.protocols.link', 'Ethernet'),
            Enum_LinkType.IEEE802_11:          ModuleDescriptor('pcapkit.protocols.link', 'IEEE802_11'),
            Enum_LinkType.FRELAY:              ModuleDescriptor('pcapkit.protocols.link', 'FRAD'),
            Enum_LinkType.LOOP:                ModuleDescriptor('pcapkit.protocols.link', 'Loopback'),
            Enum_LinkType.LINUX_SLL:           ModuleDescriptor('pcapkit.protocols.link', 'LinuxSLL1'),
            Enum_LinkType.IEEE802_11_RADIOTAP: ModuleDescriptor('pcapkit.protocols.link', 'Radiotap'),
            Enum_LinkType.IPV4:                ModuleDescriptor('pcapkit.protocols.internet', 'IPv4'),
            Enum_LinkType.IPV6:                ModuleDescriptor('pcapkit.protocols.internet', 'IPv6'),
            Enum_LinkType.LINUX_SLL2:          ModuleDescriptor('pcapkit.protocols.link', 'LinuxSLL2'),
        },
    )  # type: DefaultDict[Enum_LinkType | int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by: the enum a key must be a member of,
    #: and whether a bare :class:`int` is a valid key too. Declared by the class
    #: *owning* the registry, so
    #: :func:`~pcapkit.foundation.registry.protocols.protocol.register_protocol_code`
    #: checks a ``code=`` key as
    #: :func:`~pcapkit.foundation.registry.protocols.misc.register_pcap` does;
    #: :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG`, whose registry
    #: is keyed by the same enum, declares its own (:issue:`2268`).
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_LinkType, False)

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
        return RECORD_HEADER_LEN  # type: ignore[return-value]

    @property
    def header(self) -> 'Data_Header':
        """Global header of the PCAP file."""
        return self._ghdr

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'Enum_LinkType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.linktype.LinkType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this link type holds
                a different entry for PCAP frames, naming the displaced one and
                its replacement; see :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the guard and
                for the shipped descriptor a restore puts back (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    def index(self, name: 'str | ProtocolBase | Type[ProtocolBase]') -> 'int':
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
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods, for when the current instance
            does not have it.

            As in :meth:`Protocol.pack <pcapkit.protocols.protocol.Protocol.pack>`,
            the header is made on a copy outside construction, so the instance
            keeps its own (:issue:`1769`).

        """
        # pylint: disable=protected-access
        target = self._packing_target()
        target.__header__ = target.make(**kwargs)
        packet = kwargs.get('__packet__', {})  # packet data
        packet['byteorder'] = target._ghdr.magic_number.byteorder
        return target.__header__.pack(packet)

    def unpack(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Frame':
        r"""Unpack (parse) packet data.

        Args:
            length: Length of packet data.
            \_seek_set (int): File offset before reading, forwarded to
                :meth:`self.read <read>` through ``**kwargs``.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Notes:
            The special keyword argument ``__packet__`` passes the global
            packet data to underlying methods, for when the current instance
            does not have it.

        """
        if cast('Optional[Schema_Frame]', self.__header__) is None:
            packet = kwargs.get('__packet__', {})  # packet data

            # NOTE: Reached on the parsing path only; the construction path
            # sets ``__header__`` before unpacking its own buffer.
            self._check_record_floor(length)

            packet['byteorder'] = self._ghdr.magic_number.byteorder
            self.__header__ = cast('Schema_Frame', self.__schema__.unpack(self._file, length, packet))  # type: ignore[call-arg,misc]
        return self.read(length, **kwargs)

    def read(self, length: 'Optional[int]' = None, *, _read: 'bool' = True,
             _seek_set: 'int' = 0, **kwargs: 'Any') -> 'Data_Frame':
        r"""Read each block after global header.

        Args:
            length: Length of data to be read.
            \_read: If the class is called in a parsing scenario.
            \_seek_set: File offset of the record's own first octet, i.e. where
                the stream stood before :meth:`self.unpack <unpack>` consumed
                the record. It cannot be recovered from the stream here, since
                that unpack has consumed the whole record, packet data included.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Data_Frame: Parsed packet data.

        Warns:
            pcapkit.utilities.warnings.ProtocolWarning: If the timestamp is out
                of range, or if the record's ``incl_len`` runs past the end of
                the data being parsed, in which case the record is kept as
                captured.

        """
        schema = self.__header__

        _tsss = schema.ts_sec
        _tsus = schema.ts_usec
        _ilen = schema.incl_len
        _olen = schema.orig_len

        with localcontext(prec=64):
            _epch = _tsss + decimal.Decimal(_tsus) / RESOLUTION[bool(self._nsec)]
        _irat = _epch.as_integer_ratio()

        try:
            # NOTE: Aware UTC, not the reading host's zone, as in the ``except`` below and the
            # PCAP-NG reader; converted without the C library, as it is there (#2099).
            _time = fromtimestamp(_irat[0] / _irat[1], datetime.timezone.utc)
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
            # NOTE: On-wire ``len`` (``orig_len``) and captured ``cap_len`` (``incl_len``), as
            # Wireshark's ``frame.len``/``frame.cap_len`` and the PCAP-NG reader name them.
            len=_olen,
            cap_len=_ilen,
        )

        if not _read:
            # move backward to the beginning of the packet
            self._file.seek(0, io.SEEK_SET)
        else:
            # NOTE: Copied, to keep the original frame data intact. ``unpack`` has consumed
            # the whole record, packet data included, so seek to the start ``__post_init__``
            # recorded, as ``PCAPNG.read`` does, not back over ``self.length``.
            seek_cur = _seek_set + self.length + _ilen

            # move backward to the beginning of the frame
            self._file.seek(_seek_set, io.SEEK_SET)

            #: bytes: Raw frame data.
            #
            # NOTE: Bounded at ``sys.maxsize``, past which the read raises OverflowError
            # rather than reaching the overrun handling below (#1975).
            bound = min(self.length + _ilen, sys.maxsize)
            self._data = self._read_fileng(bound)

            # NOTE: An ``incl_len`` past the data is kept as declared, as in PCAP-NG (#1405), so
            # the record rebuilds byte-exactly; a writer must not copy it (see ``PCAPIO``, #1541).
            held = len(self._data) - self.length
            if held < _ilen:
                warn(f'PCAP: [Frame {self._fnum}] captured length {_ilen} runs past the data, '
                     f'which holds {held} octet(s); kept as captured',
                     ProtocolWarning, stacklevel=stacklevel())

            # NOTE: A whole read at the bound skips the rest of the record (#1975); a shorter
            # one met the end of the data, where the next frame then starts.
            if len(self._data) == bound < self.length + _ilen:
                advance(self._file, self.length + _ilen - bound)
            else:
                if seek_cur > sys.maxsize:
                    seek_cur = _seek_set + len(self._data)

                # move forward to the beginning of the next frame
                self._file.seek(seek_cur, io.SEEK_SET)

            #: io.BytesIO: Source data stream.
            self._file = io.BytesIO(self._data)

        # NOTE: The octets *present*, ``cap_len``, never the on-wire ``len`` a snapshot cut
        # exceeds; ``test_truncated_ipv4_header_is_raw_with_its_error`` pins it (#2236).
        #
        # NOTE: A layer that states no length cannot see the cut, so the layers
        # below are told both lengths (#2653).
        token = frame_length.set((_ilen, _olen))
        try:
            return self._decode_next_layer(frame, self._ghdr.network, frame.cap_len)
        finally:
            frame_length.reset(token)

    def make(self,
             timestamp: 'Optional[float | Decimal | int | dt_type]' = None,
             ts_sec: 'Optional[int]' = None,
             ts_usec: 'Optional[int]' = None,
             incl_len: 'Optional[int]' = None,
             orig_len: 'Optional[int]' = None,
             packet: 'bytes | ProtocolBase | Schema' = b'',
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
            # NOTE: A snaplen of 0 is no limit: draft-ietf-opsawg-pcap section 4 forbids it, and
            # libpcap (``pcapint_adjust_snapshot``) and the PCAP-NG reader read it as none.
            snaplen = self._ghdr.snaplen
            incl_len = min(len(packet), snaplen) if snaplen else len(packet)
        if orig_len is None:
            orig_len = len(packet)
        # NOTE: The record holds exactly ``incl_len`` octets of packet data, so a
        # packet longer than that -- e.g. than the snaplen -- is cut to it rather
        # than written out whole behind a clipped length.
        if len(packet) > incl_len:
            packet = bytes(packet)[:incl_len]

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

    @overload  # pragma: no cover
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      num: 'int', header: 'Data_Header', **kwargs: 'Any') -> 'None': ...
    @overload  # pragma: no cover
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
            For construction arguments, please refer to :meth:`make`.

        """
        #: int: frame index number
        self._fnum = num
        #: pcapkit.protocols.misc.pcap.header.data.Header: Global header of the PCAP file.
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
        # NOTE: Taken *before* the unpack, which advances the stream past the
        # whole record; :meth:`self.read <read>` needs the record's own start and
        # cannot work it out afterwards. See the note there.
        _seek_set = self._file.tell()

        #: pcapkit.corekit.infoclass.Info: Parsed packet data.
        self._info = self.unpack(length, _read=_read, _seek_set=_seek_set, **kwargs)

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return RECORD_HEADER_LEN  # type: ignore[return-value]

    # NOTE: This is a hack to make the ``__index__`` method work both as a
    # class method and an instance method.
    def __index__(self: 'Optional[Frame]' = None) -> 'int':  # type: ignore[override]
        """Index of the frame.

        Args:
            self: :class:`Frame` object or :obj:`None`.

        Returns:
            If the object is initialised, i.e. ``self._fnum`` exists, returns the
            frame index number of itself; else raises
            :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`.

        Raises:
            UnsupportedCall: If called on the class rather than on a frame.

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

        Notes:
            The frame index and the global header are context of the PCAP file
            rather than fields of the frame, so they are not returned here: pass
            them to :meth:`~pcapkit.protocols.protocol.Protocol.from_data` as
            ``num`` and ``header``.

        """
        return {
            'ts_sec': data.frame_info.ts_sec,
            'ts_usec': data.frame_info.ts_usec,
            'incl_len': data.frame_info.incl_len,
            'orig_len': data.frame_info.orig_len,
            'packet': cls._make_payload(data),
        }

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
            store the next layer protocol name. :meth:`Info.to_dict
            <pcapkit.corekit.infoclass.Info.to_dict>` carries both, and the
            dumpers leave them out.

            We also added a new key ``protocols`` to ``dict_`` to store the
            protocol chain of the current packet (frame).

            ``proto`` is dispatched as :meth:`_dispatch_linktype` says, so
            ``LINKTYPE_RAW`` data is read as IPv4 or IPv6 (:issue:`1502`).

        """
        proto = self._dispatch_linktype(proto, length)
        next_ = cast('ProtocolBase', self._import_next_layer(proto, length, packet=packet))  # type: ignore[misc,call-arg,redundant-cast]
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
                if nanosecond:
                    timestamp = decimal.Decimal(time.time_ns()) / 1_000_000_000
                else:
                    timestamp = decimal.Decimal(time.time())
            else:
                if isinstance(timestamp, datetime.datetime):
                    timestamp = totimestamp(timestamp)
                timestamp = decimal.Decimal(timestamp)

        if ts_sec is None:
            ts_sec = int(timestamp)

        if ts_usec is None:
            ts_usec = int((timestamp - ts_sec) * RESOLUTION[bool(nanosecond)])

        return ts_sec, ts_usec

    def _check_record_floor(self, length: 'Optional[int]') -> 'None':
        """Refuse a tail too short to hold a record header.

        Args:
            length: Length of packet data, as the caller declared it, or
                :obj:`None` to measure what is left in
                :attr:`self._file <pcapkit.protocols.protocol.Protocol._file>`.

        Raises:
            StreamEOFError: If fewer than sixteen octets are left to read.

        A PCAP record header is sixteen octets, which is what
        :meth:`__length_hint__` reports. A shorter tail is not a record, so
        parsing one would only invent fields from zero padding. Reporting the
        end of the stream instead lets :meth:`Extractor.record_frames
        <pcapkit.foundation.extraction.Extractor.record_frames>` stop with the
        frames read so far, as the PCAP-NG reader does for a truncated block
        (:issue:`678`). See :issue:`1265`.

        """
        if length is None:
            current = self._file.tell()
            length = self._file.seek(0, io.SEEK_END) - current
            self._file.seek(current, io.SEEK_SET)

        if length < RECORD_HEADER_LEN:
            raise StreamEOFError(f'PCAP: record truncated: {length} octet(s) left, '
                                 f'fewer than the {RECORD_HEADER_LEN} a record header needs',
                                 quiet=True)

    def _dispatch_linktype(self, proto: 'Optional[int]', length: 'Optional[int]' = None) -> 'Optional[int]':
        """Link type a frame's data is dispatched under.

        Arguments:
            proto: link type of the capture
            length: valid (*non-padding*) length

        Returns:
            For :attr:`LinkType.RAW <pcapkit.const.reg.linktype.LinkType.RAW>`
            data whose first octet carries IP version 4 or 6,
            :attr:`LinkType.IPV4 <pcapkit.const.reg.linktype.LinkType.IPV4>` or
            :attr:`LinkType.IPV6 <pcapkit.const.reg.linktype.LinkType.IPV6>`;
            otherwise ``proto``.

        Note:
            ``LINKTYPE_RAW`` (101) carries a bare IPv4 or IPv6 datagram, and
            only the version nibble of its first octet tells which, so it has no
            entry of its own in :attr:`__proto__` (:issue:`1502`). Dispatched as
            ``IPV4`` or ``IPV6``, it reaches whatever those link types are
            registered against. An entry registered under ``RAW`` itself is used
            as it stands, and data of any other version is kept as
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.
            :meth:`PCAPNG._dispatch_linktype
            <pcapkit.protocols.misc.pcapng.protocol.PCAPNG._dispatch_linktype>` does the
            same for PCAP-NG.

        """
        if proto != Enum_LinkType.RAW or Enum_LinkType.RAW in self.__proto__:
            return proto
        data = self._get_payload()[:length]
        version = data[0] >> 4 if data else None
        if version == 4:
            return Enum_LinkType.IPV4
        if version == 6:
            return Enum_LinkType.IPV6
        return proto

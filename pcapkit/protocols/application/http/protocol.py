# -*- coding: utf-8 -*-
"""HTTP - Hypertext Transfer Protocol
========================================

.. module:: pcapkit.protocols.application.http.protocol

:mod:`pcapkit.protocols.application.http.protocol` holds
:class:`~pcapkit.protocols.application.http.protocol.HTTP`, the base class of the
Hypertext Transfer Protocol (HTTP) [*]_ family --
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.protocol.HTTPv1>` and
:class:`HTTP/2 <pcapkit.protocols.application.httpv2.protocol.HTTPv2>` -- and
:func:`~pcapkit.protocols.application.http.protocol.test_start_line`, which tells
whether a payload opens with an HTTP/1.* start line.

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol

.. versionchanged:: 1.6.0

   A payload a transport port binds to
   :class:`~pcapkit.protocols.application.http.protocol.HTTP`, and constructing or
   rebuilding that class, give
   :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
   :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` rather than an instance
   of it, so the data sits under ``httpv1`` or ``httpv2`` rather than ``http``
   (:issue:`2524`). Building it from fields takes ``version`` and is refused
   without it, where it built HTTP/1.*, and its
   :meth:`~pcapkit.protocols.application.http.protocol.HTTP.from_data` refuses a
   :obj:`dict`, where it read the ``receipt`` or ``sid`` key (:issue:`2628`).

"""
import contextlib
import re
import struct
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.const.reg.apptype.tcp import TCP as AppType_TCP
    from pcapkit.protocols.application.httpv1.data import HTTPv1 as Data_HTTPv1
    from pcapkit.protocols.application.httpv1.protocol import HTTPv1
    from pcapkit.protocols.application.httpv2.data import HTTPv2 as Data_HTTPv2
    from pcapkit.protocols.application.httpv2.protocol import HTTPv2
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['HTTP', 'test_start_line']

#: The TCP port registry :meth:`HTTP.__index__` reads its port from, resolved
#: there rather than imported, as ``import pcapkit`` leaves it unloaded
#: (:issue:`1538`), so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_TCP: 'ModuleDescriptor[AppType_TCP]' = ModuleDescriptor('pcapkit.const.reg.apptype.tcp', 'TCP')

#: The HTTP/2 connection preface (:rfc:`9113#section-3.4`), which opens every
#: HTTP/2 connection. Its method ``PRI`` is registered as one no actual client
#: uses (:rfc:`7540#section-11.6`), so a prefix match identifies HTTP/2, and
#: :meth:`HTTP._guess_version` tests it before any parse.
_HTTP2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

#: What :rfc:`9113#section-6` allows a sender to put in the frame header of each
#: frame type it defines: the flags that type defines, and the stream identifier
#: it is sent on -- ``True`` for a non-zero stream, ``False`` for stream 0 and
#: :obj:`None` for either. :meth:`HTTP._guess_version` checks a bare frame
#: against this before its HTTP/2 trial parse; see :func:`_test_http2_frame`.
_HTTP2_FRAME_RULES = {
    0x0: (0x09, True),    # DATA: END_STREAM, PADDED (Section 6.1)
    0x1: (0x2D, True),    # HEADERS: END_STREAM, END_HEADERS, PADDED, PRIORITY (Section 6.2)
    0x2: (0x00, True),    # PRIORITY (Section 6.3)
    0x3: (0x00, True),    # RST_STREAM (Section 6.4)
    0x4: (0x01, False),   # SETTINGS: ACK (Section 6.5)
    0x5: (0x0C, True),    # PUSH_PROMISE: END_HEADERS, PADDED (Section 6.6)
    0x6: (0x01, False),   # PING: ACK (Section 6.7)
    0x7: (0x00, False),   # GOAWAY (Section 6.8)
    0x8: (0x00, None),    # WINDOW_UPDATE: either stream (Section 6.9)
    0x9: (0x04, True),    # CONTINUATION: END_HEADERS (Section 6.10)
}  # type: dict[int, tuple[int, Optional[bool]]]


def _test_http2_frame(data: 'bytes') -> 'bool':
    """Test whether ``data`` opens with a frame header a conforming sender could write.

    A plausibility test for :meth:`HTTP._guess_version`'s fall-through only:
    :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` itself parses
    every frame :rfc:`9113` lets a receiver accept, including frames this refuses.

    Args:
        data: Payload, starting at the frame header.

    Returns:
        :data:`True` if the nine-octet header carries a frame type defined by
        :rfc:`9113#section-6`, sets no flag that type leaves undefined, leaves the
        reserved bit clear, and names a stream that type may be sent on.

    Notes:
        No frame a conforming peer sends fails: undefined flags and the reserved
        bit "MUST be left unset (0x00) when sending" (:rfc:`9113#section-4.1`),
        and breaking a stream rule is a connection error (e.g. ``DATA`` on
        stream 0, :rfc:`9113#section-6.1`). Frame types :rfc:`9113` does not
        define are legal (:rfc:`9113#section-5.5`) but not guessed: on a payload
        with no other evidence they are mostly arbitrary binary.

    """
    if len(data) < 9:
        return False
    rules = _HTTP2_FRAME_RULES.get(data[3])
    if rules is None:
        return False
    flags, stream = rules
    if data[4] & ~flags:
        return False
    if data[5] & 0x80:
        return False
    if stream is None:
        return True
    return any(data[5:9]) is stream


# HTTP method token, case-sensitive (RFC 9110, section 9.1). Anchored at the end
# too, as ``re.match`` anchors only at the start and would take ``G`` of ``Get``.
_RE_METHOD = re.compile(rb"(?P<method>[A-Z][A-Z-]*)\Z")  # RFC 9110, section 16.1.1, 9.1, 5.6.2
# Regular expression to match HTTP version string.
_RE_VERSION = re.compile(rb"HTTP/(?P<version>\d\.\d)")
# HTTP status code, ``3DIGIT`` (RFC 9112, section 4). Anchored as ``_RE_METHOD``
# is: ``HTTPv1`` takes ``int()`` of the raw token, so a prefix match would let
# ``200x`` through to a bare ``ValueError`` rather than a ``ProtocolError``.
_RE_STATUS = re.compile(rb'\d{3}\Z')

# The HTTP/2 preface's header block, ``PRI * HTTP/2.0``, as ``HTTPv1.read`` splits
# it off at the first CRLFCRLF. The patterns above accept it, so
# ``HTTPv1._read_http_header`` and ``test_start_line`` refuse it by name.
_HTTP2_PREFACE_HEADER = _HTTP2_PREFACE.split(b'\r\n\r\n', maxsplit=1)[0]

#: The member :class:`HTTP` hands an HTTP/1.* message to; it, the HTTP/2 member and
#: their data models are resolved where used rather than imported, so a member's first
#: import holds :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_HTTPV1: 'ModuleDescriptor[HTTPv1]' = \
    ModuleDescriptor('pcapkit.protocols.application.httpv1.protocol', 'HTTPv1')
_HTTPV2: 'ModuleDescriptor[HTTPv2]' = \
    ModuleDescriptor('pcapkit.protocols.application.httpv2.protocol', 'HTTPv2')
_DATA_HTTPV1: 'ModuleDescriptor[Data_HTTPv1]' = \
    ModuleDescriptor('pcapkit.protocols.application.httpv1.data', 'HTTPv1')
_DATA_HTTPV2: 'ModuleDescriptor[Data_HTTPv2]' = \
    ModuleDescriptor('pcapkit.protocols.application.httpv2.data', 'HTTPv2')


def test_start_line(data: 'bytes') -> 'bool':
    """Whether ``data`` opens with an HTTP/1.* start line.

    A classification predicate for :meth:`HTTP._guess_version
    <pcapkit.protocols.application.http.protocol.HTTP._guess_version>`; it parses
    nothing. Trial-parsing every version instead would classify a non-HTTP payload
    by which parser failed less loudly.

    Args:
        data: Payload to classify.

    Returns:
        Whether the payload's first line is a ``request-line`` or a
        ``status-line`` (:rfc:`9112#section-2.1`).

    Note:
        It accepts exactly what :meth:`HTTPv1._read_http_header
        <pcapkit.protocols.application.httpv1.protocol.HTTPv1._read_http_header>`
        accepts -- ``_RE_METHOD`` with ``_RE_VERSION`` for a request,
        ``_RE_VERSION`` with ``_RE_STATUS`` for a response -- which is why
        :mod:`~pcapkit.protocols.application.httpv1.protocol` imports those patterns
        from here. A looser predicate classifies payloads the parser refuses; a
        tighter one hands real HTTP/1 to a later arm.
        ``test_start_line_predicate_agrees_with_the_httpv1_parser`` pins the
        agreement.

        It mirrors the parser's earlier checks too, which keep out the HTTP/2
        connection preface, itself a well-formed HTTP/1.1 request line
        (:rfc:`9113#section-3.4`). Split at the header/body separator, as
        :meth:`HTTPv1.read
        <pcapkit.protocols.application.httpv1.protocol.HTTPv1.read>` does, the
        preface's header is exactly ``PRI * HTTP/2.0``
        (``_HTTP2_PREFACE_HEADER``), which both refuse by name. Any other header
        with no CRLF is a start line with zero field lines, which
        :rfc:`9112#section-2.1` allows and both accept (:issue:`1041`).

        An HTTP/0.9 request line has only two tokens, so both refuse it.

    """
    header = data.split(b'\r\n\r\n', maxsplit=1)[0]
    if header == data:  # no header/body separator -- ``read`` raises
        return False

    if header == _HTTP2_PREFACE_HEADER:  # the preface -- ``_read_http_header`` raises
        return False

    startline = header.split(b'\r\n', maxsplit=1)[0]
    try:
        para1, para2, para3 = re.split(rb'\s+', startline, maxsplit=2)
    except ValueError:
        return False

    return bool(
        (re.match(_RE_METHOD, para1) and re.match(_RE_VERSION, para3))     # request-line
        or (re.match(_RE_VERSION, para1) and re.match(_RE_STATUS, para2))  # status-line
    )


class HTTP(Application[_PT, _ST], Generic[_PT, _ST]):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [:rfc:`7230`]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [:rfc:`7540`]

    It dispatches on both paths: constructing it, from octets or from fields,
    and :meth:`from_data` give
    :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
    :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`, never an instance of
    this class (:issue:`2524`). ``version`` names the member; without it, octets
    give the one :meth:`_dispatch_version` identifies, and fields are refused,
    since no field picks a member (:issue:`2574`). :meth:`from_data` gives the
    member whose data model it is handed, and refuses a :obj:`dict`. See
    :meth:`__new__`.

    """

    if TYPE_CHECKING:
        #: Saved subclass protocol data (only for HTTP base class).
        _http: 'HTTP[_PT, _ST]'

    #: Octets consumed ahead of the identified version's header -- the HTTP/2
    #: connection preface, when :meth:`_guess_version` found one. They are header,
    #: so :meth:`read` adds them to :attr:`length`; otherwise
    #: :meth:`Protocol.__init__ <pcapkit.protocols.protocol.Protocol.__init__>`
    #: would report the tail of the preface as the packet payload.
    _preface_length = 0

    #: :obj:`None`, opting out of the construction keyword check of
    #: :meth:`Protocol.__init__ <pcapkit.protocols.protocol.Protocol.__init__>`:
    #: :meth:`make` declares only ``version`` and forwards the rest to
    #: :meth:`HTTPv1.make <pcapkit.protocols.application.httpv1.protocol.HTTPv1.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.protocol.HTTPv2.make>`,
    #: so the valid names depend on an argument. The versioned classes are
    #: checked when constructed directly.
    __keywords__ = None

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Hypertext Transfer Protocol"]':
        """Name of current protocol."""
        return 'Hypertext Transfer Protocol'

    @property
    def alias(self) -> 'Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2"]':
        """Acronym of current protocol."""
        return f'HTTP/{self.version}'  # type: ignore[return-value]

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._length

    @property
    def version(self) -> 'Literal["0.9", "1.0", "1.1", "2"]':
        """Version of current protocol."""
        return self._version

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTP/1"], Literal["HTTP/2"]]':
        """Index ID of the protocol.

        The family base lists its members' names alone, as
        :meth:`IP.id() <pcapkit.protocols.internet.ip.protocol.IP.id>` does: ``HTTP/1``
        for :rfc:`9112`'s HTTP/1.1 and the versions before it, and :rfc:`9113`'s
        ``HTTP/2``. A dispatched layer is the member :meth:`_dispatch_version`
        picks, so each name selects its own version, and the ``HTTP`` key
        selects either through this tuple.

        Returns:
            Index ID of the protocol; the versioned classes narrow it to their
            own name.

        .. versionchanged:: 1.6.0

           ``('HTTP/1', 'HTTP/2')``, where it was ``('HTTP', 'HTTPv1', 'HTTPv2')``
           (:issue:`2524`).

        """
        return ('HTTP/1', 'HTTP/2')

    def read(self, length: 'Optional[int]' = None, *,
             version: 'Optional[Literal[1, 2]]' = None,
             preface: 'bool' = False,  # pylint: disable=unused-argument
             **kwargs: 'Any') -> '_PT':
        """Read (parse) packet data.

        Args:
            length: Length of packet data.
            version: Version of HTTP.
            preface: Construction keyword of :meth:`make`; whether a preface is
                parsed is decided by the octets alone.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data. When the payload opens with the HTTP/2
            connection preface, its 24 octets are recorded as ``preface``.

        """
        if length is None:
            length = len(self)

        # An explicit ``version=2`` -- what :meth:`_make_data` hands back for a
        # rebuild -- may still open with the connection preface, and the
        # identification in :meth:`_guess_version` is what skips it.
        if version is None or (version == 2 and self._test_preface(length)):
            http = self._guess_version(length, **kwargs)
        else:
            if version == 1:
                protocol = _HTTPV1.klass  # type: Type[HTTP]
            elif version == 2:
                protocol = _HTTPV2.klass
            else:
                raise ProtocolError(f'HTTP: invalid version: {version!r}')

            try:
                http = protocol(self._data, length, **kwargs)
            except ProtocolError:
                raise
            # NOTE: ``struct.error`` is no ``ValueError``, and a payload too
            # short for a versioned parser's fixed header can raise it.
            except (ValueError, struct.error) as error:
                raise ProtocolError(f'HTTP/{version}: invalid format') from error

        self._version = http.version
        self._length = http.length + self._preface_length
        self._http = http

        info = http.info
        if self._preface_length:
            info.__update__({
                'preface': _HTTP2_PREFACE,
            })

        # The versioned parser may have kept octets after its message as the
        # next layer, e.g. the frames after an HTTP/2 frame.
        next_ = getattr(http, '_next', None)
        if next_ is not None and not isinstance(next_, NoPayload):
            self._next = next_
            self._protos = ProtoChain(self.__class__, self.alias, basis=next_.protochain)
        return info

    def make(self,
             version: 'Optional[Literal[1, 2]]' = None, *,
             preface: 'bool' = False,
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        Args:
            version: Version of HTTP, ``1`` or ``2``. There is no default: no
                field picks a member (:issue:`2574`).
            preface: Whether the HTTP/2 connection preface goes ahead of the
                frame; :meth:`pack` writes it.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            The header schema the versioned ``make`` constructs.

        Raises:
            ProtocolError: If ``version`` is missing or names neither member, or
                if ``preface`` is requested for a version other than HTTP/2.

        """
        if version is None:
            raise ProtocolError('HTTP: no version to build with; pass version=1 or version=2')
        protocol = self._member_of_version(version)
        if preface and version != 2:
            raise ProtocolError(f'HTTP/{version}: connection preface is HTTP/2 only')

        # NOTE: With no file to build from, versioned ``make`` runs on a bare ``__new__``
        # instance, which is safe while neither version's ``make`` reads ``__init__`` state.
        return protocol.__new__(protocol).make(**kwargs)  # type: ignore[return-value]

    def pack(self, **kwargs: 'Any') -> 'bytes':
        """Pack (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data, with the HTTP/2 connection preface ahead
            of the frame if ``preface`` is set.

        """
        data = super().pack(**kwargs)
        if kwargs.get('preface', False):
            return _HTTP2_PREFACE + data
        return data

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member whose data
            model ``data`` is (:issue:`2524`).

        Raises:
            ProtocolError: If ``data`` is neither member's data model, on this
                class. A :obj:`dict` is refused: it carries no version, and no
                key picks a member (:issue:`2574`).

        """
        if cls is not HTTP:
            return super().from_data(data, **kwargs)

        HTTPv1 = _HTTPV1.klass  # pylint: disable=invalid-name
        HTTPv2 = _HTTPV2.klass  # pylint: disable=invalid-name
        Data_HTTPv1, Data_HTTPv2 = _DATA_HTTPV1.klass, _DATA_HTTPV2.klass  # pylint: disable=invalid-name

        if isinstance(data, Data_HTTPv1):
            return cast('Self', HTTPv1.from_data(data, **kwargs))
        if isinstance(data, Data_HTTPv2):
            return cast('Self', HTTPv2.from_data(data, **kwargs))
        raise ProtocolError('HTTP: invalid data: must be an HTTPv1 or HTTPv2 data model')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: TCP port 80, i.e.
            :attr:`TCP.http <pcapkit.const.reg.apptype.tcp.TCP.http>` as an
            :class:`int` (:ref:`registry-protocol-index`). The versioned classes
            inherit it.

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        .. versionchanged:: 1.6.0

           Returns TCP port 80, where it raised
           :exc:`~pcapkit.utilities.exceptions.IntError` (:issue:`2627`).

        """
        return int(_TCP.klass.http)  # type: ignore[call-overload]

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                 length: 'Optional[int]' = None, *,
                 version: 'Optional[Literal[1, 2]]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: Version of HTTP, ``1`` or ``2``: the member :meth:`__new__`
                picks. Building from fields, it must be this class's own. Parsing,
                it is handed on unread.
            **kwargs: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If, building from fields, ``version`` names neither
                member, or is not this class's own version: that of the member
                it is or derives from, which a subclass outside the members
                does not have; or if ``preface`` is asked of HTTP/1.

        """
        if file is not None:
            if version is not None:
                kwargs['version'] = version
        else:
            HTTPv1, HTTPv2 = _HTTPV1.klass, _HTTPV2.klass  # pylint: disable=invalid-name

            if version is not None and not isinstance(self, self._member_of_version(version)):
                if not isinstance(self, (HTTPv1, HTTPv2)):
                    raise ProtocolError(f'{type(self).__name__}: no version of its own to match '
                                        f'version={version!r}')
                raise ProtocolError(f'{type(self).__name__}: version={version!r} '
                                    'names another member')
            # NOTE: ``pack`` writes the preface for any member, so HTTP/1 refuses it here.
            if kwargs.get('preface') and isinstance(self, HTTPv1):
                raise ProtocolError('HTTP/1: connection preface is HTTP/2 only')
        super().__init__(file, length, **kwargs)  # type: ignore[arg-type]

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,  # type: ignore[misc]
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'HTTP':
        """Create the member a construction of this class describes.

        The ``version`` keyword names the member, on either path. Without it,
        parsing octets gives the member :meth:`_dispatch_version` identifies,
        since HTTP octets carry their own version, and building from fields is
        refused, since no field picks a member (:issue:`2574`). That member's
        ``__init__`` then runs with the same arguments. A subclass of this class
        is created as itself.

        Args:
            file: Source packet stream, read here without being consumed.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            ProtocolError: If ``version`` names neither member; or, without it,
                if building from fields, or if the octets are neither version's,
                including an HTTP/2 connection preface with no frame after it.

        """
        if cls is not HTTP:
            return super().__new__(cls, file, length, **kwargs)  # type: ignore[call-arg]
        if kwargs.get('version') is not None:
            member = cls._member_of_version(kwargs['version'])
        elif file is None:
            raise ProtocolError('HTTP: no version to build with; pass version=1 or version=2')
        else:
            if isinstance(file, bytes):
                data = file
            else:
                offset = file.tell()
                data = file.read(length)  # type: ignore[arg-type]
                file.seek(offset)
            from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel

            data = data[:length]
            member = cls._dispatch_version(data, len(data))
            if member is Raw:
                if data == _HTTP2_PREFACE:
                    raise ProtocolError('HTTP/2: connection preface with no frame')
                raise ProtocolError('HTTP: unknown version')
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: '_PT') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction, including the ``version``
            that :meth:`make` dispatches on.

        Raises:
            ProtocolError: If ``data`` is neither HTTP/1.* nor HTTP/2 data.

        """
        # NOTE: Neither versioned data model has a ``version`` field, so the
        # version is the class of ``data``.
        HTTPv1 = _HTTPV1.klass  # pylint: disable=invalid-name
        HTTPv2 = _HTTPV2.klass  # pylint: disable=invalid-name
        Data_HTTPv1, Data_HTTPv2 = _DATA_HTTPV1.klass, _DATA_HTTPV2.klass  # pylint: disable=invalid-name

        if isinstance(data, Data_HTTPv1):
            return {'version': 1, **HTTPv1._make_data(data)}
        if isinstance(data, Data_HTTPv2):
            return {'version': 2, 'preface': bool(data.get('preface')), **HTTPv2._make_data(data)}
        raise ProtocolError(f'HTTP: invalid data: must be HTTP/1.* or HTTP/2 data, '
                            f'not {type(data).__name__}')

    def _test_preface(self, length: 'int') -> 'bool':
        """Test whether the first ``length`` octets open with the HTTP/2 connection preface.

        Args:
            length: Length of packet data.

        Returns:
            :data:`True` if they do.

        """
        preface_len = len(_HTTP2_PREFACE)
        return length >= preface_len and self._data[:preface_len] == _HTTP2_PREFACE

    def _guess_version(self, length: 'int', **kwargs: 'Any') -> 'HTTP':
        """Identify the HTTP version of the payload, and parse it with that version.

        The payload is *identified* first and trial-parsed only as a last resort.
        A parser accepting a payload does not make it that version: the HTTP/2
        preface reads as a frame of declared length 5,263,945 (``b'PRI'`` as a
        24-bit integer), and non-HTTP text can be accepted the same way.

        Neither HTTP/1 arm absorbs :exc:`struct.error`, so it and its subclass
        ``StructError``, whose ``eof`` ``NoPayload`` handling reads, reach the
        caller. Absorbed on the trial arm, they would hand valid HTTP/1 to the
        HTTP/2 arm, mislabelling it; escaping, they make it ``Raw`` under
        ``beholder`` instead. The final HTTP/2 trial absorbs it only as a backstop:
        ``HTTPv2.unpack`` and ``FieldBase.length`` already raise
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` for a short buffer.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If no version in the family accepts the payload, or if
                an identified version's own parser refuses it. Only a
                :exc:`~pcapkit.utilities.exceptions.ProtocolError` from a trial parse falls through to the next
                version, and the final HTTP/2 trial also absorbs
                :exc:`struct.error`; any other exception from either HTTP/1
                arm, or from that HTTP/2 trial, propagates unconverted.

        Note:
            One payload with no flow context cannot decide these, so this does
            not:

            * **An** ``Upgrade: h2c`` **exchange** (:rfc:`7540#section-3.2`,
              deprecated by :rfc:`9113#section-3.1`) parses as the HTTP/1.1 it is
              on the wire. HTTP/2 starts only after the ``101 Switching
              Protocols`` response, and telling that needs per-connection state
              keyed on the 4-tuple.
            * **A mid-stream segment** -- a bare HTTP/2 frame header with no
              preface, or an opaque HTTP/1 body -- is undecidable, and becomes
              the :class:`~pcapkit.protocols.misc.raw.protocol.Raw` an escaping
              :exc:`~pcapkit.utilities.exceptions.ProtocolError` turns into under
              :func:`~pcapkit.corekit.decorators.beholder`. A frame header never
              identifies HTTP/2 ahead of HTTP/1, as it misfires on binary HTTP/1
              bodies and garbage text. A bare frame is parsed as HTTP/2 only by
              the fall-through, and only if ``_test_http2_frame()`` accepts its
              header, so nine zero octets -- ``DATA`` on stream 0, a protocol
              error under :rfc:`9113#section-6.1` -- are not guessed as HTTP/2.

        """
        # NOTE: Identified before any parse, as no HTTP/1 message begins with the preface;
        # ``length`` bounds the compare, so octets past the payload cannot make a preface.
        preface_len = len(_HTTP2_PREFACE)
        if self._test_preface(length):
            HTTPv2 = _HTTPV2.klass  # pylint: disable=invalid-name

            # The preface is not a frame, so it is skipped rather than parsed;
            # the frames follow it (RFC 9113, section 3.4).
            if length == preface_len:
                # HTTP/2, but the data model holds one frame per packet, so a
                # frameless segment is refused, as such rather than as unknown.
                raise ProtocolError('HTTP/2: connection preface with no frame')

            try:
                http = HTTPv2(self._data[preface_len:length], length - preface_len, **kwargs)
            except ProtocolError:
                raise
            # NOTE: Converted, unlike on the HTTP/1 arm, so a bad frame is catchable; only a
            # backstop, as the schema raises ``ProtocolError`` for a short field itself.
            except (ValueError, struct.error) as error:
                raise ProtocolError('HTTP/2: invalid format') from error

            # The preface is header, not payload -- see ``_preface_length``.
            self._preface_length = preface_len
            return http

        HTTPv1 = _HTTPV1.klass  # pylint: disable=invalid-name

        # NOTE: A start line, matched with ``HTTPv1``'s own patterns, identifies HTTP/1; a
        # malformed one is then reported, not retried as HTTP/2, which would mislabel it.
        if test_start_line(self._data[:length]):
            return HTTPv1(self._data, length, **kwargs)

        # NOTE: Trial parse for a mid-stream payload; ``struct.error`` escapes it, since
        # absorbing its subclass ``StructError`` would hand valid HTTP/1 to the HTTP/2 arm.
        with contextlib.suppress(ProtocolError):
            return HTTPv1(self._data, length, **kwargs)

        # NOTE: Nine octets with a small Length parse as a frame (RFC 9113, section 4.1), so
        # this guess, unlike an explicit ``version=2``, first needs ``_test_http2_frame``.
        if not _test_http2_frame(self._data[:length]):
            raise ProtocolError('HTTP: unknown version')

        with contextlib.suppress(ProtocolError, struct.error):
            return _HTTPV2.klass(self._data, length, **kwargs)

        raise ProtocolError('HTTP: unknown version')

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[HTTP]':
        """The member a ``version`` of ``1`` or ``2`` names.

        Args:
            version: Version of HTTP.

        Returns:
            :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
            :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`.

        Raises:
            ProtocolError: If ``version`` is neither, or is no :obj:`int`: a
                :obj:`bool` or a :obj:`float` is refused even where it equals one.

        """
        HTTPv1, HTTPv2 = _HTTPV1.klass, _HTTPV2.klass  # pylint: disable=invalid-name

        if isinstance(version, int) and not isinstance(version, bool):
            if version == 1:
                return HTTPv1
            if version == 2:
                return HTTPv2
        raise ProtocolError(f'HTTP: invalid version: {version!r}')

    @classmethod
    def _dispatch_version(cls, data: 'bytes', length: 'int') -> 'Type[ProtocolBase]':
        """Pick the class that parses the HTTP message at the start of ``data``.

        The payload is identified before any class is built, as
        :meth:`_guess_version` identifies it: the connection preface, or else a
        frame header a conforming sender could write, is HTTP/2, and an HTTP/1
        start line is HTTP/1. A transport layer whose port binds this class
        parses its payload with the class this returns, so a dispatched layer
        is :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
        :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`, never this base
        (:issue:`2524`).

        It is the counterpart of :meth:`IGMP._dispatch
        <pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch>`, named apart
        because ``_dispatch`` already names :meth:`AppType._dispatch
        <pcapkit.const.reg.apptype.apptype.AppType._dispatch>`, the port
        registries' lookup hook.

        Args:
            data: Payload of the transport layer, starting at the HTTP message.
            length: The HTTP message's length, in octets.

        Returns:
            :class:`~pcapkit.protocols.application.httpv1.protocol.HTTPv1` or
            :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2` for the version
            the payload identifies as; :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            for one it does not, which then keeps its octets undissected.

        Note:
            A connection preface with no frame after it, which a client may send
            in a segment of its own, is
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` here: the HTTP/2
            data model holds one frame per packet, with its frame header fields
            required, and :class:`~pcapkit.protocols.application.httpv2.protocol.HTTPv2`
            refuses a frameless segment.

        """
        HTTPv1, HTTPv2 = _HTTPV1.klass, _HTTPV2.klass  # pylint: disable=invalid-name
        from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel

        data = data[:length]
        if data.startswith(_HTTP2_PREFACE):
            return HTTPv2 if len(data) > len(_HTTP2_PREFACE) else Raw
        if test_start_line(data):
            return HTTPv1
        if _test_http2_frame(data):
            return HTTPv2
        return Raw

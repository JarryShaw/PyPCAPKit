# -*- coding: utf-8 -*-
"""HTTP - Hypertext Transfer Protocol
========================================

.. module:: pcapkit.protocols.application.http

:mod:`pcapkit.protocols.application.http` contains
:class:`~pcapkit.protocols.application.http.HTTP`
only, which is a base class for Hypertext Transfer
Protocol (HTTP) [*]_ family, eg.
:class:`HTTP/1.* <pcapkit.protocols.application.httpv1.HTTP>`
and :class:`HTTP/2 <pcapkit.protocols.application.httpv2.HTTP>`.

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol

"""
import contextlib
import struct
from typing import TYPE_CHECKING, Generic

from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

__all__ = ['HTTP']

#: The HTTP/2 connection preface (:rfc:`9113#section-3.4`). A client opens every
#: HTTP/2 connection -- with prior knowledge, over TLS, or after an upgrade --
#: by sending exactly these 24 octets, and the sequence is *designed* to be
#: identifiable without parsing: it is a well-formed HTTP/1.1 request line whose
#: method ``PRI`` is reserved and permanently unregistered, so no valid HTTP/1
#: message can begin with it and a prefix compare cannot false-positive on one.
#: That makes it a positive identification rather than a heuristic, which is why
#: :meth:`HTTP._guess_version` tests it before attempting any parse.
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

    This is a plausibility test for :meth:`HTTP._guess_version`'s fall-through
    only. ``httpv2.HTTP`` itself parses every frame :rfc:`9113` lets a receiver
    accept, which includes frames this test turns down.

    Args:
        data: Payload, starting at the frame header.

    Returns:
        :data:`True` if the nine-octet header carries a frame type defined by
        :rfc:`9113#section-6`, sets no flag that type leaves undefined, leaves the
        reserved bit clear, and names a stream that type may be sent on.

    Notes:
        Undefined flags and the reserved bit "MUST be left unset (0x00) when
        sending" (:rfc:`9113#section-4.1`), and each stream rule is one a
        receiver "MUST treat as a connection error" when broken (e.g. ``DATA``
        on stream 0, :rfc:`9113#section-6.1`), so no frame a conforming peer
        sends fails here. Frame types outside the ten that :rfc:`9113` defines
        are legal and ignored by a receiver (:rfc:`9113#section-5.5`), but on a
        payload with no other evidence they are what arbitrary binary looks
        like most of the time, so they are not guessed.

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


class HTTP(Application[_PT, _ST], Generic[_PT, _ST]):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [:rfc:`7230`]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [:rfc:`7540`]

    """

    if TYPE_CHECKING:
        #: Saved subclass protocol data (only for HTTP base class).
        _http: 'HTTP[_PT, _ST]'

    #: Octets consumed ahead of the identified version's own header -- in practice
    #: the 24-octet HTTP/2 connection preface, when :meth:`_guess_version`
    #: identified one and parsed the frame that follows it. They belong to this
    #: packet's header rather than to its payload, so :meth:`read` adds them to
    #: :attr:`length`; otherwise ``ProtocolBase.__init__``'s
    #: ``self._info.__update__(packet=self.packet.payload)`` would slice the
    #: payload from octet 9 of a buffer whose frame starts at octet 24 and report
    #: the tail of the preface as packet payload.
    _preface_length = 0

    #: This class is a version dispatcher rather than a protocol with a header of
    #: its own, so its construction keywords cannot be enumerated: :meth:`make`
    #: declares only ``version`` and forwards everything else to
    #: :meth:`HTTPv1.make <pcapkit.protocols.application.httpv1.HTTP.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.HTTP.make>`
    #: according to that value, so the correct set of names depends on an
    #: argument. :obj:`None` therefore opts out of the construction keyword check
    #: that :meth:`ProtocolBase.__init__
    #: <pcapkit.protocols.protocol.ProtocolBase.__init__>` performs; the two
    #: versioned classes are checked normally when constructed directly.
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
    def id(cls) -> 'tuple[Literal["HTTP"], Literal["HTTPv1"], Literal["HTTPv2"]]':
        """Index ID of the protocol."""
        return ('HTTP', 'HTTPv1', 'HTTPv2')

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
                from pcapkit.protocols.application.httpv1 import HTTP as protocol  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
            elif version == 2:
                from pcapkit.protocols.application.httpv2 import HTTP as protocol  # type: ignore[assignment] # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
            else:
                raise ProtocolError(f"invalid HTTP version: {version}")

            try:
                http = protocol(self._data, length, **kwargs)
            except ProtocolError:
                raise
            # NOTE: :exc:`struct.error` alongside :exc:`ValueError` because the
            # two are disjoint -- it derives straight from :exc:`Exception` --
            # and a payload too short for a versioned parser's fixed header can
            # raise the former from inside the schema machinery. A caller cannot
            # catch that as a protocol error, so it is converted too.
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
             version: 'Literal[1, 2]' = 1, *,
             preface: 'bool' = False,
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        Args:
            version: Version of HTTP.
            preface: Whether the HTTP/2 connection preface goes ahead of the
                frame; :meth:`pack` writes it.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        Raises:
            ProtocolError: If ``version`` is unknown, or if ``preface`` is
                requested for a version other than HTTP/2.

        """
        if preface and version != 2:
            raise ProtocolError(f'HTTP/{version}: connection preface is HTTP/2 only')

        if version == 1:
            from pcapkit.protocols.application.httpv1 import HTTP as protocol  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        elif version == 2:
            from pcapkit.protocols.application.httpv2 import HTTP as protocol  # type: ignore[assignment] # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        else:
            raise ProtocolError(f"invalid HTTP version: {version}")

        # NOTE: ``protocol.make`` is an ordinary instance method (the abstract
        # declaration at ``ProtocolBase.make`` takes ``self``, and the
        # versioned overrides use instance-bound helpers such as
        # ``self._make_index``/``self.__frame__``), so it cannot be called on the
        # class itself. There is no ``file`` or ``length`` to construct with here,
        # since building a packet from keyword arguments is the inverse of
        # parsing one, so a bare instance via ``protocol.__new__`` -- bypassing
        # ``__init__``'s parse/pack machinery entirely -- is what the versioned
        # ``make`` is called on. This is safe only while the versioned ``make``
        # reads no state that ``__init__``/``__post_init__`` would otherwise have
        # established (neither ``HTTPv1.make`` nor ``HTTPv2.make`` does); a
        # ``make`` override that did would need a different dispatch here.
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
        # NOTE: Neither versioned data class carries a ``version`` field --
        # HTTP/1.*'s lives in ``receipt`` as the start line's string, and HTTP/2
        # has none -- so the version is the class of ``data`` that :meth:`read`
        # returned from the versioned parser.
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.data.application.httpv1 import HTTP as Data_HTTPv1  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.data.application.httpv2 import HTTP as Data_HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel

        if isinstance(data, Data_HTTPv1):
            return {'version': 1, **HTTPv1._make_data(data)}
        if isinstance(data, Data_HTTPv2):
            return {'version': 2, 'preface': bool(data.get('preface')), **HTTPv2._make_data(data)}
        raise ProtocolError(f"invalid HTTP data: {type(data).__name__}")

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
        Trying each version in turn and taking whichever parser does not object
        answers "did a parser accept this?" where the question is "what is
        this?": the HTTP/2 preface reads as a frame whose declared length is
        5,265,993 (``b'PRI'`` as a 24-bit integer), and text that is not HTTP at
        all can be accepted the same way.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If no version in the family accepts the payload, or if
                an identified version's own parser refuses it. Only a
                ``ProtocolError`` from a trial parse falls through to the next
                version, and the final HTTP/2 trial also absorbs
                :exc:`struct.error`; any other exception from either HTTP/1
                arm, or from that HTTP/2 trial, propagates unconverted.

        Note:
            Two things this deliberately does **not** decide, because one payload
            with no flow context cannot:

            * **An ``Upgrade: h2c`` exchange** (:rfc:`7540#section-3.2`,
              deprecated but not removed by :rfc:`9113#section-3.1`) stays
              HTTP/1.1 here, and is *correctly* HTTP/1.1: on the wire the upgrade
              request and its ``101 Switching Protocols`` response are HTTP/1.1
              messages and parse as such. The switch takes effect only *after*
              the ``101``, so deciding that later segments of the same connection
              are HTTP/2 needs per-connection state keyed on the 4-tuple, and
              this method is handed a single payload with no such context.
              Recognising the ``Upgrade: h2c`` field is possible; acting on it is
              not, so it is left alone rather than half-implemented.
            * **A mid-stream segment** -- a bare HTTP/2 frame header with no
              preface ahead of it, or an opaque HTTP/1 message body -- is
              genuinely undecidable from one payload, and the honest answer is
              the ``Raw`` that an escaping ``ProtocolError`` becomes under
              :func:`~pcapkit.protocols.misc.raw.beholder`. The nine-octet frame
              header is therefore never used to *identify* HTTP/2 ahead of
              HTTP/1: as identification it misfires on binary HTTP/1 bodies,
              which is precisely how garbage text was classified HTTP/2 to begin
              with. A bare frame is parsed as HTTP/2 only by the fall-through
              below, and only if its header is one a conforming sender could
              write (see :func:`_test_http2_frame`): a frame type :rfc:`9113`
              defines, no undefined flag, and a stream that type may be sent on.
              Nine zero octets -- a ``DATA`` frame on stream 0, a protocol error
              under :rfc:`9113#section-6.1` -- are not guessed as HTTP/2.

        """
        # NOTE: Positive identification, before any parse attempt. The preface is
        # a fixed 24-octet sequence that only an HTTP/2 client sends and that no
        # valid HTTP/1 message can begin with (see ``_HTTP2_PREFACE``), so a
        # prefix compare is an *answer* rather than evidence: it cannot
        # false-positive on HTTP/1, and it needs no parse to reach.
        #
        # ``length`` bounds the compare as well as ``self._data``, because a
        # caller may hand this method fewer octets than the buffer holds, and a
        # preface must not be claimed out of octets outside this payload.
        preface_len = len(_HTTP2_PREFACE)
        if self._test_preface(length):
            from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel

            # The preface is not a frame -- the frames begin after it
            # (:rfc:`9113#section-3.4` requires a ``SETTINGS`` frame immediately
            # following), so it is skipped rather than fed to ``httpv2.HTTP``,
            # which would misread it as framing.
            if length == preface_len:
                # A preface with nothing after it *is* HTTP/2, but this library's
                # HTTP/2 data model is one frame per packet and has no
                # representation for a frameless segment, so there is nothing to
                # return. Refused with a message that says so -- an HTTP/2
                # connection opening truncated at the preface, not an
                # unrecognised payload -- because that distinction is the point
                # of identifying before parsing.
                raise ProtocolError('HTTP/2: connection preface with no frame')

            try:
                http = HTTPv2(self._data[preface_len:length], length - preface_len, **kwargs)
            except ProtocolError:
                raise
            # NOTE: Converted, unlike the HTTP/1 commit below, because this route
            # has no escaping-error contract to keep: a preface followed by a
            # malformed frame must reach the caller as something it can catch,
            # not as a bare stdlib error. The schema machinery raises
            # ``ProtocolError`` itself for a short inner field (e.g. a 16-octet
            # ``GOAWAY``, via ``FieldBase.length``), which the ``except
            # ProtocolError: raise`` above passes through, so this clause is a
            # backstop for any :exc:`ValueError` or :exc:`struct.error` it has
            # not been shown never to raise. Same normalisation as ``read``'s
            # explicit ``version=`` path above.
            except (ValueError, struct.error) as error:
                raise ProtocolError('HTTP/2: invalid format') from error

            # The preface is header, not payload -- see ``_preface_length``.
            self._preface_length = preface_len
            return http

        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        from pcapkit.protocols.application.httpv1 import \
            _test_start_line  # isort: skip # pylint: disable=import-outside-toplevel

        # NOTE: The second identification: an HTTP/1 ``request-line`` or
        # ``status-line``, tested with the very patterns ``httpv1.HTTP`` parses
        # with (``httpv1.py``'s ``_RE_METHOD``, ``_RE_VERSION`` and
        # ``_RE_STATUS``, all anchored), so the predicate and the parser cannot
        # disagree about what HTTP/1 looks like.
        #
        # Identified means *committed*: a malformed HTTP/1 message is reported as
        # such instead of being handed to the HTTP/2 arm, which accepts any
        # self-consistent buffer of nine octets or more whose header passes
        # :func:`_test_http2_frame`. Retrying an identified HTTP/1 payload as
        # HTTP/2 is how HTTP/1 traffic acquires a confident HTTP/2 mislabel.
        #
        # Nothing is suppressed on this arm, deliberately: it is not a candidate
        # to be declined, so there is nothing to decline *to*, and
        # ``test_guess_version_does_not_suppress_struct_error_on_the_http1_arm``
        # pins that a :exc:`struct.error` -- or pcapkit's own ``StructError``,
        # whose ``eof`` flag ``NoPayload`` handling reads -- reaches the caller
        # from this route rather than being converted or swallowed.
        if _test_start_line(self._data[:length]):
            return HTTPv1(self._data, length, **kwargs)

        # NOTE: Neither identification matched, so this is the fall-through: a
        # trial parse, kept because a *mid-stream* payload carries no start line
        # and no preface, and a self-consistent HTTP/2 frame is still the best
        # answer available for one. It is the last resort, not the whole method.
        #
        # The two arms suppress different sets, deliberately. Only the *last*
        # arm also suppresses :exc:`struct.error`, as defence in depth: a payload
        # too short for HTTP/2's nine-octet frame header, or whose frame-specific
        # fields exceed what the buffer holds, must not escape as a stdlib
        # exception that no caller of this method can catch. Such payloads raise
        # ``ProtocolError`` at the source -- ``httpv2.HTTP.unpack`` rejects a
        # buffer under nine octets, and :attr:`FieldBase.length
        # <pcapkit.corekit.fields.field.FieldBase.length>` re-raises a
        # negative-length template as
        # :exc:`~pcapkit.utilities.exceptions.ProtocolError` -- so the
        # suppression only guards whatever path is not yet known to do likewise.
        #
        # Suppressing it on the *first* arm is wrong: nine byte patterns over
        # lengths 0-24 raised only ``ProtocolError`` through ``httpv1.HTTP``, so
        # it buys nothing, and
        # :class:`~pcapkit.utilities.exceptions.StructError` *subclasses*
        # :exc:`struct.error`, so suppressing it on a non-final arm swallows
        # pcapkit's own signal and hands the payload to the arm below, which
        # accepts any self-consistent buffer whose header passes
        # :func:`_test_http2_frame`. With a fault injected at arm 1 and without
        # that test, a *valid* HTTP/1.1 request came back ``version='2'``, and
        # over UDP port 80 its ``protochain`` read ``UDP:HTTP/2``. A confident
        # HTTP/2 mislabel of HTTP/1 traffic is worse than letting the error
        # escape to ``beholder``, which turns it into ``Raw``; it would also
        # erase ``StructError.eof``, which ``NoPayload`` handling reads.
        with contextlib.suppress(ProtocolError):
            return HTTPv1(self._data, length, **kwargs)

        # NOTE: The HTTP/2 trial runs only on a header that passes
        # :func:`_test_http2_frame`. Since a frame's Length counts the payload
        # alone (:rfc:`9113#section-4.1`), any nine octets with a small enough
        # Length are self-consistent, so the parser's own checks accept most
        # zero-heavy binary as a ``DATA`` frame or a frame of unknown type. The
        # test rejects only headers that no conforming sender writes, and it
        # gates this guess alone: an explicit ``version=2`` is not affected.
        if not _test_http2_frame(self._data[:length]):
            raise ProtocolError("unknown HTTP version")

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        with contextlib.suppress(ProtocolError, struct.error):
            return HTTPv2(self._data, length, **kwargs)

        raise ProtocolError("unknown HTTP version")

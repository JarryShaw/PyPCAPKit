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

from pcapkit.protocols.application.application import Application
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
#: That is what makes it a positive identification rather than a heuristic, and
#: it is why :meth:`HTTP._guess_version` tests it before attempting any parse
#: (#800).
_HTTP2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


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
    #: :attr:`length`; without that, ``ProtocolBase.__init__``'s
    #: ``self._info.__update__(packet=self.packet.payload)`` slices the payload
    #: from octet 9 of a buffer whose frame starts at octet 24 and reports the
    #: tail of the preface as packet payload. See #800.
    _preface_length = 0

    #: This class is a version dispatcher rather than a protocol with a header of
    #: its own, so its construction keywords cannot be enumerated: :meth:`make`
    #: declares only ``version`` and forwards everything else to
    #: :meth:`HTTPv1.make <pcapkit.protocols.application.httpv1.HTTP.make>` or
    #: :meth:`HTTPv2.make <pcapkit.protocols.application.httpv2.HTTP.make>`
    #: according to that value -- so the set of names that is correct here depends
    #: on an argument. :obj:`None` therefore opts out of the construction keyword
    #: check that :meth:`ProtocolBase.__init__
    #: <pcapkit.protocols.protocol.ProtocolBase.__init__>` performs (#617); the
    #: two versioned classes are checked normally when constructed directly.
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
             version: 'Optional[Literal[1, 2]]' = None, **kwargs: 'Any') -> '_PT':
        """Read (parse) packet data.

        Args:
            length: Length of packet data.
            version: Version of HTTP.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        if version is None:
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
            # and a payload too short for a versioned parser's fixed header
            # raises the former from deep inside the schema machinery
            # (``FieldBase.length`` calls :func:`struct.calcsize` on a template
            # built from a negative length). A caller of this method cannot
            # catch that as a protocol error, which is the whole point of the
            # conversion the next line performs, so it is converted too.
            except (ValueError, struct.error) as error:
                raise ProtocolError(f'HTTP/{version}: invalid format') from error

        self._version = http.version
        self._length = http.length + self._preface_length
        self._http = http
        return http.info

    def make(self,
             version: 'Literal[1, 2]' = 1,
             **kwargs: 'Any') -> '_ST':
        """Make (construct) packet data.

        Args:
            version: Version of HTTP.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        if version == 1:
            from pcapkit.protocols.application.httpv1 import HTTP as protocol  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        elif version == 2:
            from pcapkit.protocols.application.httpv2 import HTTP as protocol  # type: ignore[assignment] # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        else:
            raise ProtocolError(f"invalid HTTP version: {version}")

        # NOTE: ``protocol.make`` is an ordinary instance method (the abstract
        # declaration at ``ProtocolBase.make`` takes ``self``, and the
        # versioned overrides use instance-bound helpers such as
        # ``self._make_index``/``self.__frame__``), so calling it on the
        # class itself -- as this used to -- left ``self`` unfilled and raised
        # ``TypeError`` for every real call; see GH-452. There is no ``file``
        # or ``length`` to construct with here, since building a packet from
        # keyword arguments is the inverse of parsing one, so a bare instance
        # via ``protocol.__new__`` -- bypassing ``__init__``'s parse/pack
        # machinery entirely -- is what the versioned ``make`` needs to be
        # called on. This is safe only as long as the versioned ``make`` never
        # reads state that ``__init__``/``__post_init__`` would otherwise have
        # established (neither ``HTTPv1.make`` nor ``HTTPv2.make`` does today);
        # a future ``make`` override that reaches for such state would need a
        # different dispatch here.
        return protocol.__new__(protocol).make(**kwargs)  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: '_PT') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        version = data.get('version', 0)
        if version == 1:
            from pcapkit.protocols.application.httpv1 import HTTP as protocol
        elif version == 2:
            from pcapkit.protocols.application.httpv2 import HTTP as protocol  # type: ignore[assignment] # isort: skip
        else:
            raise ProtocolError(f"invalid HTTP version: {version}")
        return protocol._make_data(data)  # type: ignore[arg-type]

    def _guess_version(self, length: 'int', **kwargs: 'Any') -> 'HTTP':
        """Identify the HTTP version of the payload, and parse it with that version.

        The payload is *identified* first and trial-parsed only as a last resort.
        Until #800 there was no identification step at all: both versions were
        tried in turn and whichever parser did not object was taken as the
        answer, which answers "did a parser accept this?" where the question is
        "what is this?" -- and got both directions wrong. The HTTP/2 connection
        preface came back ``version='2'`` only because ``httpv2.HTTP`` read its
        leading ``b'PRI'`` as a 24-bit declared frame length of 5,265,993, and
        ``b'foo bar baz\\r\\nX: y\\r\\n\\r\\n'`` -- not HTTP at all -- came back
        ``version='2'`` the same way. #799/#802 closed the second of those by
        requiring a frame's declared length to be backed by its buffer, but that
        left the preface *unidentifiable*: a real HTTP/2 connection opening is
        refused by both arms and reported as not-HTTP.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If no version in the family accepts the payload, or if
                an identified version's own parser refuses it. This is the
                *only* exception this method raises for an unparseable payload --
                a candidate failing in any other way, on a version that was not
                positively identified, is a fall-through and not an answer.

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
              :func:`~pcapkit.protocols.misc.raw.beholder`. In particular there
              is deliberately *no* heuristic on the nine-octet frame header
              ("type at most 9, reserved bit clear"): that misfires on binary
              HTTP/1 bodies, which is precisely how garbage text was classified
              HTTP/2 to begin with. A self-consistent bare frame is still parsed
              as HTTP/2, but by the fall-through below -- on the parser's own
              length/type consistency rules -- rather than by a guess dressed up
              as identification.

        """
        # NOTE: Positive identification, before any parse attempt. The preface is
        # a fixed 24-octet sequence that only an HTTP/2 client sends and that no
        # valid HTTP/1 message can begin with (see ``_HTTP2_PREFACE``), so a
        # prefix compare is an *answer* rather than evidence: it cannot
        # false-positive on HTTP/1, and it needs no parse to reach.
        #
        # ``length`` bounds the compare as well as ``self._data``, because a
        # caller may hand this method fewer octets than the buffer holds, and
        # claiming a preface out of octets that were not part of this payload
        # would be the same kind of accident this change removes.
        preface_len = len(_HTTP2_PREFACE)
        if length >= preface_len and self._data[:preface_len] == _HTTP2_PREFACE:
            from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel

            # The preface is not a frame -- the frames begin after it
            # (:rfc:`9113#section-3.4` requires a ``SETTINGS`` frame immediately
            # following), so it is skipped rather than fed to ``httpv2.HTTP``,
            # which is how it used to be misread as framing.
            if length == preface_len:
                # A preface with nothing after it *is* HTTP/2, but this library's
                # HTTP/2 data model is one frame per packet and has no
                # representation for a frameless segment, so there is nothing to
                # return. Refused with a message that says which of the two it
                # was -- an HTTP/2 connection opening truncated at the preface,
                # not an unrecognised payload -- because that distinction is the
                # whole point of identifying before parsing.
                raise ProtocolError('HTTP/2: connection preface with no frame')

            try:
                http = HTTPv2(self._data[preface_len:length], length - preface_len, **kwargs)
            except ProtocolError:
                raise
            # NOTE: Converted, unlike the HTTP/1 commit below, because this route
            # is new and has no escaping-error contract to keep: the old arm 2
            # suppressed :exc:`struct.error` and fell through to ``unknown HTTP
            # version``, so a preface followed by a frame that trips the #805
            # residual (an inner field shortfall, e.g. a 16-octet ``GOAWAY``)
            # must still reach the caller as something it can catch, not as a
            # bare stdlib error. Same normalisation, and the same reasoning, as
            # ``read``'s explicit ``version=`` path above.
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
        # the malformed HTTP/1 message it is, instead of being handed to the
        # HTTP/2 arm, which accepts any self-consistent nine-octet-or-longer
        # buffer. Re-trying an identified HTTP/1 payload as HTTP/2 is exactly how
        # HTTP/1 traffic acquires a confident HTTP/2 mislabel -- the failure #787
        # exists to stop -- and #682 now routes 231 real HTTP/1 frames from the
        # fixture corpus through here, TCP:80/8080 having been repointed at this
        # class.
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
        # answer available for one. It is the last resort rather than the whole
        # method, which is the #800 change.
        #
        # The two arms suppress different sets, and the asymmetry is
        # deliberate. Only the *last* arm additionally suppresses
        # :exc:`struct.error`, because a payload too short to hold HTTP/2's
        # nine-octet frame header, or one whose frame-specific fields exceed
        # what a slightly-longer buffer holds, fails inside the schema
        # machinery with that stdlib exception rather than with a protocol
        # error -- ``FieldBase.length`` calls :func:`struct.calcsize` on a
        # template built from a negative length -- and it is neither a
        # ``ProtocolError`` nor a :exc:`ValueError`, so it left this method
        # uncatchable by any caller: ``HTTP(io.BytesIO(b'\x00' * 8), 8)`` raised
        # a bare :exc:`struct.error` where the closing ``raise`` below is the
        # documented answer. Suppressing it on the last arm is safe in the
        # sense that matters here -- no arm follows, so nothing can answer in
        # place of the error.
        #
        # #799 closed the *outer*-header slice of this: ``httpv2.HTTP.unpack``
        # now rejects a buffer under nine octets before the schema layer runs
        # at all, and ``read`` requires the declared length, the available
        # buffer, and their consistency (``schema.length <= length``) all to
        # hold. That did *not* retire this suppression, only shrink what it
        # has to catch: a buffer that clears nine octets can still carry a
        # frame type whose own fixed-width fields exceed what is left after
        # the header -- a ``GOAWAY`` at 9-16 octets (``stream`` and ``error``
        # alone are eight), a ``PUSH_PROMISE`` at 9-12, or any ``PADDED``
        # ``DATA``/``HEADERS``/``PUSH_PROMISE`` whose ``pad_len`` exceeds the
        # remainder -- and those still drive ``pkt['__length__']`` negative one
        # field further in, past this guard's reach. Measured: a 16-octet
        # ``GOAWAY`` (``b'\x00\x00\x15\x07\x00\x00\x00\x00\x00' + b'\xff' * 7``)
        # still raises a bare :exc:`struct.error` through ``httpv2.HTTP``
        # directly. Closing that class needs the fix at its actual root --
        # a negative field length raising :exc:`~pcapkit.utilities.\
        # exceptions.ProtocolError` in :meth:`Schema.unpack
        # <pcapkit.protocols.schema.schema.Schema.unpack>` /
        # :attr:`FieldBase.length <pcapkit.corekit.fields.field.FieldBase.length>`
        # instead of the bare warning those currently emit -- which is generic
        # across every schema in the tree and is out of this change's scope;
        # tracked as #805 rather than attempted here.
        #
        # Widening the *first* arm the same way was measured and reverted, as it
        # buys nothing and costs a great deal. Nothing reaches a
        # :exc:`struct.error` through ``httpv1.HTTP``: nine byte patterns over
        # lengths 0-24, on this route and on ``read(version=1)``, answered
        # ``ProtocolError`` 450 times out of 450. And
        # :class:`~pcapkit.utilities.exceptions.StructError` *subclasses*
        # :exc:`struct.error`, so suppressing it on a non-final arm swallows
        # pcapkit's own signal and hands the payload to the arm below -- which
        # accepts anything of at least nine octets. With a fault injected at arm
        # 1, a *valid* HTTP/1.1 request came back ``version='2'``, and over UDP
        # port 80 its ``protochain`` read ``UDP:HTTP/2``. A confident HTTP/2
        # mislabel of HTTP/1 traffic is the exact failure #787 exists to stop, and
        # it is worse than letting the error escape to ``beholder``, which turns
        # it into ``Raw``; it would also erase ``StructError.eof``, which
        # ``NoPayload`` handling reads. ``unknown HTTP version`` is only the best
        # case, needing arm 2 to decline as well.
        with contextlib.suppress(ProtocolError):
            return HTTPv1(self._data, length, **kwargs)

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        with contextlib.suppress(ProtocolError, struct.error):
            return HTTPv2(self._data, length, **kwargs)

        raise ProtocolError("unknown HTTP version")

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


class HTTP(Application[_PT, _ST], Generic[_PT, _ST]):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [:rfc:`7230`]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [:rfc:`7540`]

    """

    if TYPE_CHECKING:
        #: Saved subclass protocol data (only for HTTP base class).
        _http: 'HTTP[_PT, _ST]'

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
        self._length = http.length
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
        """Guess HTTP version.

        Args:
            length: Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If no version in the family accepts the payload. This
                is the *only* exception this method raises for an unparseable
                payload -- a candidate failing in any other way is a fall-through
                and not an answer.

        """
        # NOTE: The two arms suppress different sets, and the asymmetry is
        # deliberate. Only the *last* arm additionally suppresses
        # :exc:`struct.error`, because a payload too short to hold HTTP/2's
        # nine-octet frame header usually fails inside the schema machinery with
        # that stdlib exception rather than with a protocol error --
        # ``FieldBase.length`` calls :func:`struct.calcsize` on a template built
        # from a negative length -- and it is neither a ``ProtocolError`` nor a
        # :exc:`ValueError`, so it used to leave this method uncatchable by any
        # caller: ``HTTP(io.BytesIO(b'\x00' * 8), 8)`` raised a bare
        # :exc:`struct.error` where the closing ``raise`` below is the documented
        # answer. ("Usually" because ``httpv2.HTTP``'s own guard tests the
        # *declared* length, not the buffer's, so a four-octet payload declaring
        # fifteen parses instead of failing.) Suppressing it on the last arm is
        # safe in the sense that matters here -- no arm follows, so nothing can
        # answer in place of the error.
        #
        # The residual, which is real and is not zero: a genuine ``httpv2``
        # schema defect that raised :exc:`struct.error` on well-formed HTTP/2
        # bytes would now be reported as ``unknown HTTP version`` rather than
        # crashing loudly, so a bug in that schema is quieter than it was. That is
        # accepted because the alternative is a dispatcher no caller can catch,
        # and it is bounded: ``httpv2.HTTP`` stays reachable directly, where
        # nothing is suppressed, and that is the documented route for a caller who
        # wants the unwrapped failure.
        #
        # This is keyed on being *last*, not on being the HTTP/2 arm. Inserting an
        # arm after this one would silently make the reasoning false, and the
        # regression test guards arm 1 specifically, so it would not catch that:
        # the new arm must take the :exc:`struct.error` suppression and this one
        # must give it up.
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
        from pcapkit.protocols.application.httpv1 import HTTP as HTTPv1  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        with contextlib.suppress(ProtocolError):
            return HTTPv1(self._data, length, **kwargs)

        from pcapkit.protocols.application.httpv2 import HTTP as HTTPv2  # isort: skip # pylint: disable=line-too-long,import-outside-toplevel
        with contextlib.suppress(ProtocolError, struct.error):
            return HTTPv2(self._data, length, **kwargs)

        raise ProtocolError("unknown HTTP version")

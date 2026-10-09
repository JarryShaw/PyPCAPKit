# -*- coding: utf-8 -*-
r"""HTTP/1.* - Hypertext Transfer Protocol
============================================

.. module:: pcapkit.protocols.application.httpv1

:mod:`pcapkit.protocols.application.httpv1` contains
:class:`~pcapkit.protocols.application.httpv1.HTTP`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/1.*) [*]_, whose structure is described
as below:

.. code-block:: text

   METHOD URL HTTP/VERSION\r\n :==: REQUEST LINE
   <key> : <value>\r\n         :==: REQUEST HEADER
   ............  (Ellipsis)    :==: REQUEST HEADER
   \r\n                        :==: REQUEST SEPARATOR
   <body>                      :==: REQUEST BODY (optional)

   HTTP/VERSION CODE DESP \r\n :==: RESPONSE LINE
   <key> : <value>\r\n         :==: RESPONSE HEADER
   ............  (Ellipsis)    :==: RESPONSE HEADER
   \r\n                        :==: RESPONSE SEPARATOR
   <body>                      :==: RESPONSE BODY (optional)

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol

"""
import re
from typing import TYPE_CHECKING

from pcapkit.const.http.method import Method as Enum_Method
from pcapkit.const.http.status_code import StatusCode as Enum_StatusCode
from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.application.http import (_HTTP2_PREFACE_HEADER, _RE_METHOD, _RE_STATUS,
                                                _RE_VERSION)
from pcapkit.protocols.application.http import HTTP as HTTPBase
from pcapkit.protocols.data.application.httpv1 import HTTP as Data_HTTP
from pcapkit.protocols.data.application.httpv1 import RequestHeader as Data_RequestHeader
from pcapkit.protocols.data.application.httpv1 import ResponseHeader as Data_ResponseHeader
from pcapkit.protocols.schema.application.httpv1 import HTTP as Schema_HTTP
from pcapkit.utilities.chardet import detect
from pcapkit.utilities.compat import StrEnum, auto
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Sequence
    from typing import Type as _Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.data.application.httpv1 import Header as Data_Header

__all__ = ['HTTP']

# NOTE: The start-line patterns ``_RE_METHOD``, ``_RE_VERSION`` and ``_RE_STATUS``,
# and ``_HTTP2_PREFACE_HEADER``, are imported from ``http.py``, where
# :func:`~pcapkit.protocols.application.http.test_start_line` classifies with
# them; one copy keeps that predicate and this parser in agreement.


class Type(EnumLookup, StrEnum):
    """HTTP packet type.

    Built on :class:`~pcapkit.corekit.enum.EnumLookup`, the lookup contract
    shared by every non-registry enumeration (:issue:`877`). The class defines
    neither ``get`` nor ``_missing_`` of its own.

    """

    #: Request packet.
    REQUEST = auto()
    #: Response packet.
    RESPONSE = auto()


class HTTP(HTTPBase[Data_HTTP, Schema_HTTP],
           data=Data_HTTP, schema=Schema_HTTP):
    """This class implements Hypertext Transfer Protocol (HTTP/1.*)."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Type: Type of HTTP receipt.
    _receipt: 'Type'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["HTTP/0.9", "HTTP/1.0", "HTTP/1.1"]':
        """Acronym of current protocol."""
        return f'HTTP/{self.version}'  # type: ignore[return-value]

    @property
    def version(self) -> 'Literal["0.9", "1.0", "1.1"]':
        """Version of current protocol."""
        return self._info.receipt.version  # type: ignore[attr-defined]

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_HTTP':  # pylint: disable=unused-argument
        """Read Hypertext Transfer Protocol (HTTP/1.*).

        Structure of HTTP/1.* packet [:rfc:`7230`]:

        .. code-block:: text

           HTTP-message    :==:    start-line
                                   *( header-field CRLF )
                                   CRLF
                                   [ message-body ]


        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        packet = schema.data

        # NOTE: A payload carrying no header/body separator at all unpacks short
        # here. It must surface as ``ProtocolError``, not a bare ``ValueError``:
        # ``HTTP._guess_version`` falls through to its HTTP/2 arm on
        # ``ProtocolError`` alone, so any other exception from an HTTP/1 attempt
        # on HTTP/2 wire bytes would abort the guess instead of failing it.
        # ``ProtocolError`` is also what the ``Raises:`` section above promises,
        # and the same conversion the explicit ``version=`` path of
        # ``HTTP.read`` performs; chained, so the unpacking error stays
        # reachable as ``__cause__``.
        try:
            header, body = packet.split(b'\r\n\r\n', maxsplit=1)
        except ValueError as error:
            raise ProtocolError('HTTP: invalid format') from error

        header_line, header_unpacked = self._read_http_header(header)
        body_unpacked = self._read_http_body(body, headers=header_unpacked) or None

        http = Data_HTTP(
            receipt=header_line,
            header=header_unpacked,
            body=body_unpacked,
            raw_header=self._split_field_lines(header.partition(b'\r\n')[2]),
        )
        self._receipt = header_line.type
        self._version = header_line.version  # type: ignore[attr-defined]
        self._length = len(header)

        return http

    def make(self,  # type: ignore[override]
             http_version: 'Literal["0.9", "1.0", "1.1", b"0.9", b"1.0", b"1.1"]' = '1.1',
             method: 'Optional[Enum_Method | str | bytes]' = None,
             uri: 'Optional[str | bytes]' = None,
             status: 'Optional[Enum_StatusCode | str | bytes | int]' = None,
             status_default: 'Optional[int]' = None,
             status_namespace: 'Optional[dict[str, int] | dict[int, str] | _Type[StdlibEnum] | _Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             status_reversed: 'bool' = False,
             message: 'Optional[str | bytes]' = None,
             headers: 'Optional[OrderedMultiDict[str, str]]' = None,
             body: 'bytes' = b'',
             charset: 'Optional[str]' = None,
             raw_line: 'Optional[bytes]' = None,
             raw_header: 'Sequence[bytes]' = (),
             **kwargs: 'Any') -> 'Schema_HTTP':
        """Make (construct) packet data.

        The start line and the field lines are built from the parsed values
        with single SPs, ``name: value`` and UTF-8 field values. ``raw_line``
        is written in place of the start line, and each ``raw_header`` entry in
        place of the header field at the same position, whenever reading it
        back gives the same values -- so a message rebuilds byte for byte,
        whitespace, ``obs-fold`` and field-value charset included, while a
        value that has been changed is written from the change. Field lines
        are matched to ``headers`` by content and in order, so adding or
        removing a field leaves the others as received.

        Args:
            http_version: HTTP version.
            method: HTTP method.
            uri: HTTP request URI.
            status: HTTP status code.
            status_default: Default HTTP status code.
            status_namespace: Namespace of HTTP status code.
            status_reversed: Whether to reverse the namespace.
            message: HTTP status message.
            headers: HTTP headers.
            body: HTTP body.
            charset: Encoding for a :obj:`str` request URI or status message,
                **UTF-8** if not given.
            raw_line: HTTP start line as received, CRLF excluded.
            raw_header: HTTP field lines as received, CRLF excluded, one per
                header field and in the order of ``headers``.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If the values are neither a request's nor a
                response's, or if ``raw_line`` or a ``raw_header`` entry that
                reads back as the given values carries a CR or LF that the
                values do not (other than the CRLF of an ``obs-fold``).

        """
        header_line = self._make_start_line(http_version, method=method, uri=uri, status=status,
                                            status_default=status_default,
                                            status_namespace=status_namespace,
                                            status_reversed=status_reversed,
                                            message=message, charset=charset)
        if raw_line is not None:
            try:
                received = self._read_start_line(raw_line)
            except ProtocolError:
                pass
            else:
                if self._make_start_line(received.version,  # type: ignore[attr-defined]
                                         method=getattr(received, 'method', None),
                                         uri=getattr(received, 'uri', None),
                                         status=getattr(received, 'status', None),
                                         message=getattr(received, 'message', None),
                                         charset=received.charset) == header_line:  # type: ignore[attr-defined]
                    text = getattr(received, 'uri', getattr(received, 'message', ''))  # type: str
                    self._check_raw(raw_line, text, fold=False)
                    header_line = raw_line + b'\r\n'

        # NOTE: Field lines are matched to the header fields by content, in
        # order, rather than by position, so that adding or removing a field
        # leaves the field lines around it as they were received.
        received_fields = []  # type: list[Optional[tuple[str, str]]]
        for raw_field in raw_header:
            try:
                received_fields.append(self._read_field_line(raw_field))
            except ProtocolError:
                received_fields.append(None)

        header_fields = []  # type: list[bytes]
        start = 0
        for key, value in headers.items(multi=True) if headers is not None else ():
            for index in range(start, len(received_fields)):
                if received_fields[index] == (key, value):
                    self._check_raw(raw_header[index], key, value, fold=True)
                    header_fields.append(raw_header[index] + b'\r\n')
                    start = index + 1
                    break
            else:
                header_fields.append(b'%s: %s\r\n' % (key.encode(), value.encode()))

        return Schema_HTTP(
            data=header_line + b''.join(header_fields) + b'\r\n' + body,
        )

    @staticmethod
    def _check_raw(raw: 'bytes', *values: 'str', fold: 'bool') -> 'None':
        """Refuse a raw line that would write a line break its values lack.

        Reading a line back strips the whitespace around its tokens, and that
        includes a lone CR or LF, so a raw line can read back as values that
        carry no line break while writing one to the wire.

        Args:
            raw: Raw start line or field line, CRLF excluded.
            *values: The values ``raw`` reads back as.
            fold: Whether the CRLF of an ``obs-fold``, followed by SP or HTAB,
                is allowed in ``raw``.

        Raises:
            ProtocolError: If ``raw`` carries a CR or LF that ``values`` do not.

        """
        if fold:
            raw = re.sub(rb'\r\n(?=[ \t])', b'', raw)
        for char in ('\r', '\n'):
            if raw.count(char.encode()) != sum(value.count(char) for value in values):
                raise ProtocolError('HTTP: raw line carries a CR or LF its values do not')

    def _make_start_line(self, http_version: 'str | bytes', *,
                         method: 'Optional[Enum_Method | str | bytes]' = None,
                         uri: 'Optional[str | bytes]' = None,
                         status: 'Optional[Enum_StatusCode | str | bytes | int]' = None,
                         status_default: 'Optional[int]' = None,
                         status_namespace: 'Optional[dict[str, int] | dict[int, str] | _Type[StdlibEnum] | _Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                         status_reversed: 'bool' = False,
                         message: 'Optional[str | bytes]' = None,
                         charset: 'Optional[str]' = None) -> 'bytes':
        """Make an HTTP/1.* start line from its values.

        Args:
            http_version: HTTP version.
            method: HTTP method.
            uri: HTTP request URI.
            status: HTTP status code.
            status_default: Default HTTP status code.
            status_namespace: Namespace of HTTP status code.
            status_reversed: Whether to reverse the namespace.
            message: HTTP status message.
            charset: Encoding for a :obj:`str` request URI or status message,
                **UTF-8** if not given.

        Returns:
            The start line, CRLF included.

        Raises:
            ProtocolError: If the values are neither a request's nor a
                response's.

        """
        version = http_version.encode() if isinstance(http_version, str) else http_version
        if method is not None and status is None:
            if uri is None:
                raise ProtocolError('HTTP request must have URI.')

            if isinstance(method, Enum_Method):
                meth = method.value.encode()
            elif isinstance(method, bytes):
                meth = method
            elif isinstance(method, str):
                meth = method.encode()
            else:
                meth = method.value.encode()
            uri_val = uri.encode(charset or 'utf-8') if isinstance(uri, str) else uri

            header_line = b'%s %s HTTP/%s\r\n' % (meth, uri_val, version)
        elif method is None and status is not None:
            status_code = self._make_index(status, status_default, namespace=status_namespace,
                                           reversed=status_reversed, pack=False)
            status_code_val = int(status_code)

            if message is None:
                msg = getattr(status, 'message', None) or getattr(status_code, 'message', b'') or b''
            else:
                msg = message.encode(charset or 'utf-8') if isinstance(message, str) else message
            if isinstance(msg, str):
                msg = msg.encode()

            # status-code is 3DIGIT (RFC 9112, section 4), so keep a leading zero
            header_line = b'HTTP/%s %03d %s\r\n' % (version, status_code_val, msg)
        else:
            raise ProtocolError('HTTP packet must be either request or response.')
        return header_line

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTP"], Literal["HTTPv1"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return (cls.__name__, 'HTTPv1')  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_HTTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        # NOTE: ``read`` records an empty body as :obj:`None`, which is the
        # public ``info.body`` value; ``make`` takes ``bytes`` and concatenates
        # it, so the read-side ``None`` is translated back here (#1050).
        return {
            'http_version': data.receipt.version,  # type: ignore[attr-defined]
            'method': getattr(data.receipt, 'method', None),
            'uri': getattr(data.receipt, 'uri', None),
            'status': getattr(data.receipt, 'status', None),
            'message': getattr(data.receipt, 'message', None),
            'headers': data.header,
            'body': b'' if data.body is None else data.body,
            'charset': getattr(data.receipt, 'charset', None),
            'raw_line': getattr(data.receipt, 'raw_line', None),
            'raw_header': getattr(data, 'raw_header', ()),
        }

    def _decode_text(self, text: 'bytes') -> 'tuple[str, Optional[str]]':
        """Decode start-line text, recording how to encode it back.

        The text is decoded by :meth:`self.decode
        <pcapkit.protocols.protocol.Protocol.decode>`. Where the result does
        not encode back to ``text`` as UTF-8 -- which :meth:`make` uses by
        default -- the detected charset is returned with it, or ``'latin-1'``
        (decoding again) if that does not reproduce ``text`` either, so that the
        original octets survive a rebuild.

        Args:
            text: Raw request URI or status message.

        Returns:
            The decoded text and the charset to encode it with, the latter
            :obj:`None` for UTF-8.

        """
        value = self.decode(text)
        for charset in (None, detect(text)):
            try:
                if value.encode(charset or 'utf-8') == text:
                    return value, charset
            except (LookupError, UnicodeError):
                pass
        return text.decode('latin-1'), 'latin-1'

    def _read_http_header(self, header: 'bytes') -> 'tuple[Data_Header, OrderedMultiDict[str, str]]':
        """Read HTTP/1.* header.

        Structure of HTTP/1.* header [:rfc:`7230`]:

        .. code-block:: text

           start-line      :==:    request-line / status-line
           request-line    :==:    method SP request-target SP HTTP-version CRLF
           status-line     :==:    HTTP-version SP status-code SP reason-phrase CRLF
           header-field    :==:    field-name ":" OWS field-value OWS

        Args:
            header: HTTP header data.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        # NOTE: A header with no CRLF is a start line with zero field lines,
        # which :rfc:`9112#section-2.1` allows (``*( field-line CRLF )``). The
        # one such header refused by name is the HTTP/2 connection preface's:
        # ``PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`` splits in ``read`` to exactly
        # ``PRI * HTTP/2.0``, which ``_RE_METHOD`` and ``_RE_VERSION`` would
        # otherwise accept as an HTTP/1 request (see ``_HTTP2_PREFACE_HEADER`` in
        # ``http.py``).
        if header == _HTTP2_PREFACE_HEADER:
            raise ProtocolError('HTTP: invalid format')
        startline, _, headerfield = header.partition(b'\r\n')
        header_line = self._read_start_line(startline)

        header_fields = OrderedMultiDict()  # type: OrderedMultiDict[str, str]
        for raw_field in self._split_field_lines(headerfield):
            header_fields.add(*self._read_field_line(raw_field))

        return header_line, header_fields

    @staticmethod
    def _split_field_lines(headerfield: 'bytes') -> 'tuple[bytes, ...]':
        """Split the field lines of an HTTP/1.* header.

        Args:
            headerfield: The header after its start line and that line's CRLF.

        Returns:
            One field line per header field, as received and CRLF excluded.

        Raises:
            ProtocolError: If the first field line is an ``obs-fold``
                continuation.

        """
        # NOTE: A field line beginning with SP or HTAB is an ``obs-fold``
        # continuation of the line before it (:rfc:`9112#section-5.2`), so it is
        # kept with that line rather than treated as a field line of its own,
        # and unfolded by ``_read_field_line``. Deprecated, but present in real
        # captures. Treating a continuation as a field line of its own goes wrong
        # twice: one carrying no colon fails the colon check, so a valid message
        # is refused; one that happens to contain a colon parses silently into a
        # spurious extra field (``X-Long: a`` plus ``b: c``, for a folded
        # ``X-Long: a b``).
        raw_fields = []  # type: list[bytes]
        for line in headerfield.split(b'\r\n') if headerfield else ():
            if line.startswith((b' ', b'\t')):
                # A continuation with nothing to continue -- the first field line
                # folded -- is malformed rather than unfoldable.
                if not raw_fields:
                    raise ProtocolError('HTTP: invalid format')
                raw_fields[-1] += b'\r\n' + line
                continue
            raw_fields.append(line)
        return tuple(raw_fields)

    def _read_field_line(self, line: 'bytes') -> 'tuple[str, str]':
        """Read one HTTP/1.* field line.

        Args:
            line: Field line as received, CRLF excluded, with any ``obs-fold``
                continuations still in it.

        Returns:
            The field name and the field value, the latter unfolded and without
            the optional whitespace around it.

        Raises:
            ProtocolError: If the line is not a field line.

        """
        # NOTE: The accumulator is right-stripped as well as the continuation,
        # because the production is ``obs-fold = OWS CRLF RWS`` and it is the
        # *whole* obs-fold that is replaced by a single space -- the RFC's own
        # remedy (:rfc:`9112#section-5.2`). The OWS before the CRLF belongs to
        # the fold, not to the value, so ``X: a \t\r\n\tb`` unfolds to ``'a b'``.
        field, *continuations = line.split(b'\r\n')
        for continuation in continuations:
            if not continuation.startswith((b' ', b'\t')):
                raise ProtocolError('HTTP: invalid format')
            field = field.rstrip() + b' ' + continuation.strip()

        # NOTE: Checked rather than left to ``item[1]``, and refused rather than
        # skipped: a field line with no colon is not a header field, and dropping
        # it would hand back a message whose fields are quietly not the ones on
        # the wire. ``ProtocolError`` for the reason ``read`` gives, and to the
        # same message.
        item = re.split(rb'\s*:\s*', field, maxsplit=1)
        if len(item) != 2:
            raise ProtocolError('HTTP: invalid format')
        return self.decode(item[0].strip()), self.decode(item[1].strip())

    def _read_start_line(self, startline: 'bytes') -> 'Data_Header':
        """Read an HTTP/1.* start line.

        Args:
            startline: Start line as received, CRLF excluded.

        Returns:
            Parsed start line.

        Raises:
            ProtocolError: If the line is neither a request line nor a status
                line.

        """
        # NOTE: Short for a start line of fewer than three whitespace-separated
        # tokens. Raised as ``ProtocolError`` for the reason ``read`` gives,
        # with the same message this method uses below for a start line it
        # cannot recognise.
        try:
            para1, para2, para3 = re.split(rb'\s+', startline, maxsplit=2)
        except ValueError as error:
            raise ProtocolError('HTTP: invalid format') from error

        if TYPE_CHECKING:
            header_line: 'Data_Header'

        match1 = re.match(_RE_METHOD, para1)
        match2 = re.match(_RE_VERSION, para3)
        match3 = re.match(_RE_VERSION, para1)
        match4 = re.match(_RE_STATUS, para2)
        if match1 and match2:
            uri, charset = self._decode_text(para2)
            header_line = Data_RequestHeader(
                type=Type.REQUEST,
                method=Enum_Method.get(self.decode(match1.group('method'))),
                uri=uri,
                version=self.decode(match2.group('version')),
                charset=charset,
                raw_line=startline,
            )
        elif match3 and match4:
            message, charset = self._decode_text(para3)
            header_line = Data_ResponseHeader(
                type=Type.RESPONSE,
                version=self.decode(match3.group('version')),
                status=Enum_StatusCode.get(int(para2)),
                message=message,
                charset=charset,
                raw_line=startline,
            )
        else:
            raise ProtocolError('HTTP: invalid format')
        return header_line

    def _read_http_body(self, body: 'bytes', *,
                        headers: 'OrderedMultiDict[str, str]') -> 'Any':
        """Read HTTP/1.* body.

        Args:
            body: HTTP body data.
            headers: HTTP header fields.

        Returns:
            Raw HTTP body.

        """
        return body

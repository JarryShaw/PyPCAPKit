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
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.application.http import HTTP as HTTPBase
from pcapkit.protocols.data.application.httpv1 import HTTP as Data_HTTP
from pcapkit.protocols.data.application.httpv1 import RequestHeader as Data_RequestHeader
from pcapkit.protocols.data.application.httpv1 import ResponseHeader as Data_ResponseHeader
from pcapkit.protocols.schema.application.httpv1 import HTTP as Schema_HTTP
from pcapkit.utilities.compat import StrEnum
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional
    from typing import Type as _Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.data.application.httpv1 import Header as Data_Header

__all__ = ['HTTP']

# Regular expression to match HTTP methods.
_RE_METHOD = re.compile(rb"(?P<method>[A-Z][A-Z-]*)")  # RFC 9110, section 16.1.1, 9.1, 5.6.2
# Regular expression to match HTTP version string.
_RE_VERSION = re.compile(rb"HTTP/(?P<version>\d\.\d)")
# Regular expression to match HTTP status code.
_RE_STATUS = re.compile(rb'\d{3}')


class Type(StrEnum):
    """HTTP packet type."""

    #: Request packet.
    REQUEST = 'request'
    #: Response packet.
    RESPONSE = 'response'


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
        header, body = packet.split(b'\r\n\r\n', maxsplit=1)

        header_line, header_unpacked = self._read_http_header(header)
        body_unpacked = self._read_http_body(body, headers=header_unpacked) or None

        http = Data_HTTP(
            receipt=header_line,
            header=header_unpacked,
            body=body_unpacked,
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
             **kwargs: 'Any') -> 'Schema_HTTP':
        """Make (construct) packet data.

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
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        version = http_version.encode() if isinstance(http_version, str) else http_version
        if method is not None and status is None:
            if uri is None:
                raise ProtocolError('HTTP request must have URI.')

            if isinstance(method, bytes):
                meth = method
            elif isinstance(method, str):
                meth = method.encode()
            else:
                meth = method.value.encode()
            uri_val = uri.encode() if isinstance(uri, str) else uri

            header_line = b'%s %s HTTP/%s\r\n' % (meth, uri_val, version)
        elif method is None and status is not None:
            status_code = self._make_index(status, status_default, namespace=status_namespace,
                                           reversed=status_reversed, pack=False)
            status_code_val = int(status_code)

            if message is None:
                msg = getattr(status_code, 'message', b'') or b''
            else:
                msg = message.encode() if isinstance(message, str) else message

            header_line = b'HTTP/%s %s %s\r\n' % (version, str(status_code_val).encode(), msg)

        header_fields = []  # type: list[bytes]
        if headers is not None:
            header_fields = []
            for key, value in headers.items(multi=True):
                header_fields.append(b'%s: %s\r\n' % (key.encode(), value.encode()))

        return Schema_HTTP(
            data=header_line + b''.join(header_fields) + b'\r\n' + body,
        )

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
        return {
            'http_version': data.receipt.version,  # type: ignore[attr-defined]
            'method': getattr(data.receipt, 'method', None),
            'uri': getattr(data.receipt, 'uri', None),
            'status': getattr(data.receipt, 'status', None),
            'message': getattr(data.receipt, 'message', None),
            'headers': data.header,
            'body': data.body,
        }

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
        startline, headerfield = header.split(b'\r\n', 1)
        para1, para2, para3 = re.split(rb'\s+', startline, 2)
        fields = headerfield.split(b'\r\n')
        lists = (re.split(rb'\s*:\s*', field, 1) for field in fields)

        if TYPE_CHECKING:
            header_line: 'Data_Header'

        match1 = re.match(_RE_METHOD, para1)
        match2 = re.match(_RE_VERSION, para3)
        match3 = re.match(_RE_VERSION, para1)
        match4 = re.match(_RE_STATUS, para2)
        if match1 and match2:
            header_line = Data_RequestHeader(
                type=Type.REQUEST,
                method=Enum_Method.get(self.decode(para1)),
                uri=self.decode(para2),
                version=self.decode(match2.group('version')),
            )
        elif match3 and match4:
            header_line = Data_ResponseHeader(
                type=Type.RESPONSE,
                version=self.decode(match3.group('version')),
                status=Enum_StatusCode.get(int(para2)),
                message=self.decode(para3),
            )
        else:
            raise ProtocolError('HTTP: invalid format')

        header_fields = OrderedMultiDict()  # type: OrderedMultiDict[str, str]
        for item in lists:
            key = self.decode(item[0].strip())
            value = self.decode(item[1].strip())
            header_fields.add(key, value)

        return header_line, header_fields

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

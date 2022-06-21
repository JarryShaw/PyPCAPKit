# -*- coding: utf-8 -*-
r"""HTTP/1.* - Hypertext Transfer Protocol
============================================

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

from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.application.http import HTTP as HTTPBase
from pcapkit.protocols.data.application.httpv1 import HTTP as DataType_HTTP
from pcapkit.protocols.data.application.httpv1 import RequestHeader as DataType_RequestHeader
from pcapkit.protocols.data.application.httpv1 import ResponseHeader as DataType_ResponseHeader
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.data.application.httpv1 import Header as DataType_Header

__all__ = ['HTTP']

#: Supported HTTP method.
HTTP_METHODS = [
    'GET', 'HEAD', 'POST', 'PUT',
    'DELETE', 'TRACE', 'OPTIONS',
    'CONNECT', 'PATCH',
]

#: Regular expression to match HTTP methods.
_RE_METHOD = re.compile(r'|'.join(HTTP_METHODS).encode())
#: Regular expression to match HTTP version string.
_RE_VERSION = re.compile(rb"HTTP/(?P<version>\d\.\d)")
#: Regular expression to match HTTP status code.
_RE_STATUS = re.compile(rb'\d{3}')


class HTTP(HTTPBase[DataType_HTTP]):
    """This class implements Hypertext Transfer Protocol (HTTP/1.*)."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Literal['request', 'response']: Type of HTTP receipt.
    _receipt: 'Literal["request", "response"]'

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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_HTTP':  # pylint: disable=unused-argument
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

        packet = self._file.read(length)
        header, body = packet.split(b'\r\n\r\n', maxsplit=1)

        header_line, header_unpacked = self._read_http_header(header)
        body_unpacked = self._read_http_body(body) or None

        http = DataType_HTTP(
            receipt=header_line,
            header=header_unpacked,
            body=body_unpacked,
        )
        self._receipt = header_line.type
        self._version = header_line.version  # type: ignore[attr-defined]
        self._length = len(packet)

        return http

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return (cls.__name__,)  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_http_header(self, header: 'bytes') -> 'tuple[DataType_Header, OrderedMultiDict[str, str]]':
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
            header_line: 'DataType_Header'

        match1 = re.match(_RE_METHOD, para1)
        match2 = re.match(_RE_VERSION, para3)
        match3 = re.match(_RE_VERSION, para1)
        match4 = re.match(_RE_STATUS, para2)
        if match1 and match2:
            header_line = DataType_RequestHeader(
                type='request',
                method=self.decode(para1),
                uri=self.decode(para2),
                version=self.decode(match2.group('version')),
            )
        elif match3 and match4:
            header_line = DataType_ResponseHeader(
                type='response',
                version=self.decode(match3.group('version')),
                status=int(para2),
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

    def _read_http_body(self, body: 'bytes') -> 'bytes':
        """Read HTTP/1.* body.

        Args:
            body: HTTP body data.

        Returns:
            Raw HTTP body.

        """
        return body

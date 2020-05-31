# -*- coding: utf-8 -*-
"""hypertext transfer protocol (HTTP/1.*)

:mod:`pcapkit.protocols.application.httpv1` contains
:class:`~pcapkit.protocols.application.httpv1.HTTPv1`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/1.*) [*]_, whose structure is described
as below::

    METHOD URL HTTP/VERSION\\r\\n :==: REQUEST LINE
    <key> : <value>\\r\\n         :==: REQUEST HEADER
    ............  (Ellipsis)      :==: REQUEST HEADER
    \\r\\n                        :==: REQUEST SEPARATOR
    <body>                        :==: REQUEST BODY (optional)

    HTTP/VERSION CODE DESP \\r\\n :==: RESPONSE LINE
    <key> : <value>\\r\\n         :==: RESPONSE HEADER
    ............  (Ellipsis)      :==: RESPONSE HEADER
    \\r\\n                        :==: RESPONSE SEPARATOR
    <body>                        :==: RESPONSE BODY (optional)

.. [*] https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol

"""
import re

from pcapkit.protocols.application.http import HTTP
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['HTTPv1']

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


class HTTPv1(HTTP):
    """This class implements Hypertext Transfer Protocol (HTTP/1.*)."""

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Literal['request', 'response']: Type of HTTP receipt.
    _receipt = None

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self):
        """Acronym of current protocol.

        :rtype: Literal['HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1']
        """
        return f'HTTP/{self._info.header[self._receipt].version}'  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Hypertext Transfer Protocol (HTTP/1.*).

        Structure of HTTP/1.* packet [:rfc:`7230`]::

            HTTP-message    :==:    start-line
                                    *( header-field CRLF )
                                    CRLF
                                    [ message-body ]


        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_HTTP: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        packet = self._file.read(length)
        try:
            header, body = packet.split(b'\r\n\r\n', maxsplit=1)
        except ValueError:
            raise ProtocolError('HTTP: invalid format', quiet=True)

        header_unpacked, http_receipt = self._read_http_header(header)
        body_unpacked = self._read_http_body(body) or None

        http = dict(
            receipt=http_receipt,
            header=header_unpacked,
            body=body_unpacked,
            raw=dict(
                header=header,
                body=body,
                packet=self._read_packet(length),
            ),
        )
        self._receipt = http_receipt

        return http

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Literal['HTTPv1']: Index ID of the protocol.

        """
        return cls.__name__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_http_header(self, header):
        """Read HTTP/1.* header.

        Structure of HTTP/1.* header [:rfc:`7230`]::

            start-line      :==:    request-line / status-line
            request-line    :==:    method SP request-target SP HTTP-version CRLF
            status-line     :==:    HTTP-version SP status-code SP reason-phrase CRLF
            header-field    :==:    field-name ":" OWS field-value OWS

        Args:
            header (bytes): HTTP header data.

        Returns:
            Union[DataType_HTTP_Request_Header, DataType_HTTP_Response_Header]: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        try:
            startline, headerfield = header.split(b'\r\n', 1)
            para1, para2, para3 = re.split(rb'\s+', startline, 2)
            fields = headerfield.split(b'\r\n')
            lists = (re.split(rb'\s*:\s*', field, 1) for field in fields)
        except ValueError:
            raise ProtocolError('HTTP: invalid format', quiet=True)

        match1 = re.match(_RE_METHOD, para1)
        match2 = re.match(_RE_VERSION, para3)
        match3 = re.match(_RE_VERSION, para1)
        match4 = re.match(_RE_STATUS, para2)
        if match1 and match2:
            receipt = 'request'
            header = dict(
                request=dict(
                    method=self.decode(para1),
                    target=self.decode(para2),
                    version=self.decode(match2.group('version')),
                ),
            )
        elif match3 and match4:
            receipt = 'response'
            header = dict(
                response=dict(
                    version=self.decode(match3.group('version')),
                    status=int(para2),
                    phrase=self.decode(para3),
                ),
            )
        else:
            raise ProtocolError('HTTP: invalid format', quiet=True)

        try:
            for item in lists:
                key = self.decode(item[0].strip()).replace(receipt, f'{receipt}_field')
                value = self.decode(item[1].strip())
                if key in header:
                    if isinstance(header[key], tuple):
                        header[key] += (value,)
                    else:
                        header[key] = (header[key], value)
                else:
                    header[key] = value
        except IndexError:
            raise ProtocolError('HTTP: invalid format', quiet=True)

        return header, receipt

    def _read_http_body(self, body):  # pylint: disable=no-self-use
        """Read HTTP/1.* body.

        Args:
            body (bytes): HTTP body data.

        Returns:
            str: Raw HTTP body.

        """
        return body

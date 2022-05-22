# -*- coding: utf-8 -*-
"""data model for HTTP/1.* protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.data.application.http import HTTP as DataType_HTTP

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'HTTP',

    'Header',
    'RequestHeader', 'ResponseHeader',
]


class HTTP(DataType_HTTP):
    """Data model for HTTP/1.* protocol."""

    #: HTTP receipt.
    receipt: 'Header'
    #: HTTP header.
    header: 'OrderedMultiDict[str, str]'
    #: HTTP body.
    body: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, receipt: 'Header', header: 'OrderedMultiDict[str, str]', body: 'Optional[bytes]') -> None: ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Header(Info):
    """Data model for HTTP/1.* header line."""

    #: Receipt type.
    type: 'Literal["request", "response"]'


class RequestHeader(Header):
    """Data model for HTTP/1.* request header line."""

    #: HTTP request header line.
    type: 'Literal["request"]'
    #: HTTP method.
    method: 'str'
    #: HTTP request URI.
    uri: 'str'
    #: HTTP request version.
    version: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal["request"]', method: 'str', uri: 'str', version: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class ResponseHeader(Header):
    """Data model for HTTP/1.* response header line."""

    #: HTTP response header line.
    type: 'Literal["response"]'
    #: HTTP response version.
    version: 'str'
    #: HTTP response status.
    status: 'int'
    #: HTTP response status message.
    message: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal["response"]', version: 'str', status: 'int', message: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

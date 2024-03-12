# -*- coding: utf-8 -*-
"""data model for HTTP/1.* protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing import Any

    from pcapkit.const.http.method import Method as Enum_Method
    from pcapkit.const.http.status_code import StatusCode as Enum_StatusCode
    from pcapkit.corekit.multidict import OrderedMultiDict
    from pcapkit.protocols.application.httpv1 import Type as HTTP_Type

__all__ = [
    'HTTP',

    'Header',
    'RequestHeader', 'ResponseHeader',
]


@info_final
class HTTP(Protocol):
    """Data model for HTTP/1.* protocol."""

    #: HTTP receipt.
    receipt: 'Header'
    #: HTTP header.
    header: 'OrderedMultiDict[str, str]'
    #: HTTP body.
    body: 'Any'

    if TYPE_CHECKING:
        def __init__(self, receipt: 'Header', header: 'OrderedMultiDict[str, str]', body: 'Any') -> None: ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Header(Data):
    """Data model for HTTP/1.* header line."""

    #: Receipt type.
    type: 'HTTP_Type'


@info_final
class RequestHeader(Header):
    """Data model for HTTP/1.* request header line."""

    #: HTTP request header line.
    type: 'HTTP_Type'
    #: HTTP method.
    method: 'Enum_Method'
    #: HTTP request URI.
    uri: 'str'
    #: HTTP request version.
    version: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'HTTP_Type', method: 'Enum_Method', uri: 'str', version: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


@info_final
class ResponseHeader(Header):
    """Data model for HTTP/1.* response header line."""

    #: HTTP response header line.
    type: 'HTTP_Type'
    #: HTTP response version.
    version: 'str'
    #: HTTP response status.
    status: 'Enum_StatusCode'
    #: HTTP response status message.
    message: 'str'

    if TYPE_CHECKING:
        def __init__(self, type: 'HTTP_Type', version: 'str', status: 'Enum_StatusCode', message: 'str') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

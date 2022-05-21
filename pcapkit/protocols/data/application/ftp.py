# -*- coding: utf-8 -*-
"""data models for FTP protocol"""


from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing import Optional

    from typing_extensions import Literal

    from pcapkit.const.ftp.command import CommandType
    from pcapkit.const.ftp.return_code import ReturnCode

__all__ = [
    'FTP',
    'Request', 'Response',
]


class FTP(Info):
    """Data model for FTP protocol."""

    #: Type.
    type: 'Literal["response", "request"]'


class Request(FTP):
    """Data model for FTP request."""

    #: Type.
    type: 'Literal["request"]'
    #: Command.
    command: 'CommandType'
    #: Arguments.
    arg: 'Optional[str]'
    #: Raw data.
    raw: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal["request"]', command: 'CommandType', arg: 'Optional[str]', raw: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class Response(FTP):
    """Data model for FTP response."""

    #: Type.
    type: 'Literal["response"]'
    #: Return code.
    code: 'ReturnCode'
    #: Arguments.
    arg: 'Optional[str]'
    #: More data flag.
    mf: 'bool'
    #: Raw data.
    raw: 'Optional[bytes]'

    if TYPE_CHECKING:
        def __init__(self, type: 'Literal["response"]', code: 'ReturnCode', arg: 'Optional[str]', mf: 'bool', raw: 'Optional[bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin

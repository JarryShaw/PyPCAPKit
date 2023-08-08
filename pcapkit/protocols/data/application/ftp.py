# -*- coding: utf-8 -*-
"""data models for FTP protocol"""


from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from typing_extensions import Literal

    from pcapkit.const.ftp.command import Command
    from pcapkit.const.ftp.return_code import ReturnCode
    from pcapkit.protocols.application.ftp import Type as FTP_Type

__all__ = [
    'FTP',
    'Request', 'Response',
]


class FTP(Data):
    """Data model for FTP protocol."""

    #: Type.
    type: 'FTP_Type'


@info_final
class Request(FTP):
    """Data model for FTP request."""

    #: Type.
    type: 'Literal[FTP_Type.REQUEST]'
    #: Command.
    cmmd: 'Command'
    #: Arguments.
    args: 'str'


@info_final
class Response(FTP):
    """Data model for FTP response."""

    #: Type.
    type: 'Literal[FTP_Type.RESPONSE]'
    #: Return code.
    code: 'ReturnCode'
    #: Arguments.
    args: 'str'
    #: More data flag.
    more: 'bool'

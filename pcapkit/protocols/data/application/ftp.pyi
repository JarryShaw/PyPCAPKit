from pcapkit.const.ftp.command import Command
from pcapkit.const.ftp.return_code import ReturnCode
from pcapkit.protocols.application.ftp import Type as FTP_Type
from pcapkit.protocols.data.data import Data
from typing_extensions import Literal

class FTP(Data):
    type: FTP_Type

class Request(FTP):
    type: Literal[FTP_Type.REQUEST]
    cmmd: Command
    args: str
    def __init__(self, type: Literal[FTP_Type.REQUEST], cmmd: Command, args: str) -> None: ...

class Response(FTP):
    type: Literal[FTP_Type.RESPONSE]
    code: ReturnCode
    args: str
    more: bool
    def __init__(self, type: Literal[FTP_Type.RESPONSE], code: ReturnCode, args: str, more: bool) -> None: ...

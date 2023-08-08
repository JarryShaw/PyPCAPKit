from pcapkit.const.http.method import Method as Enum_Method
from pcapkit.const.http.status_code import StatusCode as Enum_StatusCode
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.application.httpv1 import Type as HTTP_Type
from pcapkit.protocols.data.data import Data
from typing import Any

class HTTP(Data):
    receipt: Header
    header: OrderedMultiDict[str, str]
    body: Any
    def __init__(self, receipt: Header, header: OrderedMultiDict[str, str], body: Any) -> None: ...

class Header(Data):
    type: HTTP_Type

class RequestHeader(Header):
    type: HTTP_Type
    method: Enum_Method
    uri: str
    version: str
    def __init__(self, type: HTTP_Type, method: Enum_Method, uri: str, version: str) -> None: ...

class ResponseHeader(Header):
    type: HTTP_Type
    version: str
    status: Enum_StatusCode
    message: str
    def __init__(self, type: HTTP_Type, version: str, status: Enum_StatusCode, message: str) -> None: ...

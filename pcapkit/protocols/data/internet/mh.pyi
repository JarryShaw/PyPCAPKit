from datetime import datetime as dt_type, timedelta
from ipaddress import IPv6Address, IPv6Network
from pcapkit.const.mh.auth_subtype import AuthSubtype as Enum_AuthSubtype
from pcapkit.const.mh.binding_error import BindingError as Enum_BindingError
from pcapkit.const.mh.cga_extension import CGAExtension as Enum_CGAExtension
from pcapkit.const.mh.cga_type import CGAType as Enum_CGAType
from pcapkit.const.mh.lla_code import LLACode as Enum_LLACode
from pcapkit.const.mh.mn_id_subtype import MNIDSubtype as Enum_MNIDSubtype
from pcapkit.const.mh.option import Option as Enum_Option
from pcapkit.const.mh.packet import Packet
from pcapkit.const.mh.status_code import StatusCode as Enum_StatusCode
from pcapkit.const.reg.transtype import TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.internet.mh import NTPTimestamp

class MH(Data):
    next: TransType
    length: int
    type: Packet
    chksum: bytes

class UnknownMessage(MH):
    data: bytes
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, data: bytes) -> None: ...

class BindingRefreshRequestMessage(MH):
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class HomeTestInitMessage(MH):
    cookie: bytes
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, cookie: bytes, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class CareofTestInitMessage(MH):
    cookie: bytes
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, cookie: bytes, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class HomeTestMessage(MH):
    nonce_index: int
    cookie: bytes
    token: bytes
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, nonce_index: int, cookie: bytes, token: bytes, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class CareofTestMessage(MH):
    nonce_index: int
    cookie: bytes
    token: bytes
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, nonce_index: int, cookie: bytes, token: bytes, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class BindingUpdateMessage(MH):
    seq: int
    ack: bool
    home: bool
    lla_compat: bool
    key_mngt: bool
    lifetime: timedelta
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, seq: int, ack: bool, home: bool, lla_compat: bool, key_mngt: bool, lifetime: timedelta, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class BindingAcknowledgementMessage(MH):
    status: Enum_StatusCode
    key_mngt: bool
    seq: int
    lifetime: timedelta
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, status: Enum_StatusCode, key_mngt: bool, seq: int, lifetime: timedelta, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class BindingErrorMessage(MH):
    status: Enum_BindingError
    home: IPv6Address
    options: OrderedMultiDict[Enum_Option, Option]
    def __init__(self, next: TransType, length: int, type: Packet, chksum: bytes, status: Enum_BindingError, home: IPv6Address, options: OrderedMultiDict[Enum_Option, Option]) -> None: ...

class Option(Data):
    type: Enum_Option
    length: int

class UnassignedOption(Option):
    data: bytes
    def __init__(self, type: Enum_Option, length: int, data: bytes) -> None: ...

class PadOption(Option):
    def __init__(self, type: Enum_Option, length: int) -> None: ...

class BindingRefreshAdviceOption(Option):
    interval: int
    def __init__(self, type: Enum_Option, length: int, interval: int) -> None: ...

class AlternateCareofAddressOption(Option):
    address: IPv6Address
    def __init__(self, type: Enum_Option, length: int, address: IPv6Address) -> None: ...

class NonceIndicesOption(Option):
    home: int
    careof: int
    def __init__(self, type: Enum_Option, length: int, home: int, careof: int) -> None: ...

class AuthorizationDataOption(Option):
    data: bytes
    def __init__(self, type: Enum_Option, length: int, data: bytes) -> None: ...

class MobileNetworkPrefixOption(Option):
    prefix: IPv6Network
    def __init__(self, type: Enum_Option, length: int, prefix: IPv6Network) -> None: ...

class LinkLayerAddressOption(Option):
    code: Enum_LLACode
    lla: bytes
    def __init__(self, type: Enum_Option, length: int, code: Enum_LLACode, lla: bytes) -> None: ...

class MNIDOption(Option):
    subtype: Enum_MNIDSubtype
    identifier: bytes | str | IPv6Address
    def __init__(self, type: Enum_Option, length: int, subtype: Enum_MNIDSubtype, identifier: bytes | str | IPv6Address) -> None: ...

class AuthOption(Option):
    subtype: Enum_AuthSubtype
    spi: int
    data: bytes
    def __init__(self, type: Enum_Option, length: int, subtype: Enum_AuthSubtype, spi: int, data: bytes) -> None: ...

class MesgIDOption(Option):
    timestamp: dt_type
    ntp_timestamp: NTPTimestamp
    def __init__(self, type: Enum_Option, length: int, timestamp: dt_type, ntp_timestamp: NTPTimestamp) -> None: ...

class CGAParametersRequestOption(Option):
    def __init__(self, type: Enum_Option, length: int) -> None: ...

class CGAExtension(Data):
    type: Enum_CGAExtension
    length: int

class UnknownExtension(CGAExtension):
    data: bytes
    def __init__(self, type: Enum_CGAExtension, length: int, data: bytes) -> None: ...

class MultiPrefixExtension(CGAExtension):
    flag: bool
    prefixes: tuple[int, ...]
    def __init__(self, type: Enum_CGAExtension, length: int, flag: bool, prefixes: tuple[int, ...]) -> None: ...

class CGAParameter(Data):
    modifier: Enum_CGAType
    prefix: int
    collision_count: int
    public_key: bytes
    extensions: OrderedMultiDict[Enum_CGAExtension, CGAExtension]
    def __init__(self, modifier: Enum_CGAType, prefix: int, collision_count: int, public_key: bytes, extensions: OrderedMultiDict[Enum_CGAExtension, CGAExtension]) -> None: ...

class CGAParametersOption(Option):
    parameters: tuple[CGAParameter, ...]
    def __init__(self, type: Enum_Option, length: int, parameters: tuple[CGAParameter, ...]) -> None: ...

class SignatureOption(Option):
    signature: bytes
    def __init__(self, type: Enum_Option, length: int, signature: bytes) -> None: ...

class PermanentHomeKeygenTokenOption(Option):
    token: bytes
    def __init__(self, type: Enum_Option, length: int, token: bytes) -> None: ...

class CareofTestInitOption(Option):
    def __init__(self, type: Enum_Option, length: int) -> None: ...

class CareofTestOption(Option):
    token: bytes
    def __init__(self, type: Enum_Option, length: int, token: bytes) -> None: ...

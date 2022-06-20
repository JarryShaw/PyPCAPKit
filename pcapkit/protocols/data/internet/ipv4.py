# -*- coding: utf-8 -*-
"""data model for IPv4 protocol"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv4.option_class import OptionClass
from pcapkit.const.ipv4.tos_del import ToSDelay
from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from datetime import datetime as dt_type
    from datetime import timedelta
    from ipaddress import IPv4Address
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.const.ipv4.classification_level import ClassificationLevel
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
    from pcapkit.const.ipv4.qs_function import QSFunction
    from pcapkit.const.ipv4.router_alert import RouterAlert
    from pcapkit.const.ipv4.tos_ecn import ToSECN
    from pcapkit.const.ipv4.tos_pre import ToSPrecedence
    from pcapkit.const.ipv4.tos_rel import ToSReliability
    from pcapkit.const.ipv4.tos_thr import ToSThroughput
    from pcapkit.const.ipv4.ts_flag import TSFlag
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.multidict import OrderedMultiDict

__all__ = [
    'IPv4',

    'ToSField', 'Flags',
    'OptionType',

    'UnassignedOption', 'EOOLOption', 'NOPOption',
    'SECOption', 'LSROption', 'TSOption',
    'ESECOption', 'RROption', 'SIDOption',
    'SSROption', 'MTUPOption', 'MTUROption',
    'TROption', 'RTRALTOption', 'QSOption',
]


class ToSField(Info):
    """Data model for IPv4 ToS fields.

    Important:
        Due to the preserved keyword conflict, please use :meth:`from_dict`
        to create an instance of this data model.

    """

    #: Precedence.
    pre: 'ToSPrecedence'
    #: Delay.
    #del: 'ToSDelay'
    #: Throughput.
    thr: 'ToSThroughput'
    #: Reliability.
    rel: 'ToSReliability'
    #: Explicit congestion notification (ECN).
    ecn: 'ToSECN'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'ToSField':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: We cannot define ``del`` due to preserved keyword conflict.
        # Thus, we directly inject the information into the annotations.
        self.__annotations__['del'] = ToSDelay  # pylint: disable=no-member

        return self  # type: ignore[return-value]


class Flags(Info):
    """Data model for IPv4 Flags."""

    #: Don't fragment.
    df: 'bool'
    #: More fragments.
    mf: 'bool'

    if TYPE_CHECKING:
        def __init__(self, df: 'bool', mf: 'bool') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class IPv4(Info):
    """Data model for IPv4 packet."""

    #: Version.
    version: 'Literal[4]'
    #: Internet header length.
    hdr_len: 'int'
    #: Type of services.
    tos: 'ToSField'
    #: Total length.
    len: 'int'
    #: Identification.
    id: 'int'
    #: Flags.
    flags: 'Flags'
    #: Fragment offset.
    offset: 'int'
    #: Time to live.
    ttl: 'timedelta'
    #: Protocol.
    protocol: 'TransType'
    #: Header checksum.
    checksum: 'bytes'
    #: Source address.
    src: 'IPv4Address'
    #: Destination address.
    dst: 'IPv4Address'

    if TYPE_CHECKING:
        options: 'OrderedMultiDict[OptionNumber, Option]'

        def __init__(self, version: 'Literal[4]', hdr_len: 'int', tos: 'ToSField', len: 'int', id: 'int', flags: 'Flags', offset: 'int', ttl: 'timedelta', protocol: 'TransType', checksum: 'bytes', src: 'IPv4Address', dst: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class OptionType(Info):
    """Data model for IPv4 option type data."""

    #: Change flag.
    change: 'bool'
    #: Option class.
    #class: 'int'
    #: Number.
    number: 'int'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'OptionType':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: We cannot define ``class`` due to preserved keyword conflict.
        # Thus, we directly inject the information into the annotations.
        self.__annotations__['class'] = OptionClass  # pylint: disable=no-member

        return self  # type: ignore[return-value]


class Option(Info):
    """Data model for IPv4 options."""

    #: Option code.
    code: 'OptionNumber'
    #: Option length.
    length: 'int'
    #: Option type.
    type: 'OptionType'


class UnassignedOption(Option):
    """Data model for IPv4 unassigned option."""

    #: Option data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class EOOLOption(Option):
    """Data model for IPv4 End of Option List (``EOOL``) option."""

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class NOPOption(Option):
    """Data model for IPv4 No Operation (``NOP``) option."""

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class SECOption(Option):
    """Data model for IPv4 Security (``SEC``) option."""

    #: Classification level.
    level: 'ClassificationLevel'
    #: Protection authority flags.
    flags: 'Optional[OrderedMultiDict[ProtectionAuthority, bool]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', level: 'ClassificationLevel', flags: 'Optional[OrderedMultiDict[ProtectionAuthority, bool]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class LSROption(Option):
    """Data model for IPv4 Loose Source Route (``LSR``) option."""

    #: Pointer.
    pointer: 'int'
    #: Route.
    route: 'Optional[tuple[IPv4Address, ...]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', pointer: 'int', route: 'Optional[tuple[IPv4Address, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class TSOption(Option):
    """Data model for IPv4 Time Stamp (``TS``) option."""

    #: Pointer.
    pointer: 'int'
    #: Overflow.
    overflow: 'int'
    #: Flag.
    flag: 'TSFlag'
    #: Timestamp data.
    timestamp: 'Optional[bytes | tuple[dt_type, ...] | OrderedMultiDict[IPv4Address, dt_type]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', pointer: 'int', overflow: 'int', flag: 'TSFlag', timestamp: 'Optional[bytes | tuple[dt_type, ...] | OrderedMultiDict[IPv4Address, dt_type]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class ESECOption(Option):
    """Data model for IPv4 Extended Security (``ESEC``) option."""

    #: Classification level.
    level: 'ClassificationLevel'
    #: Protection authority flags.
    flags: 'Optional[OrderedMultiDict[ProtectionAuthority, bool]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', level: 'ClassificationLevel', flags: 'Optional[OrderedMultiDict[ProtectionAuthority, bool]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class RROption(Option):
    """Data model for IPv4 Record Route (``RR``) option."""

    #: Pointer.
    pointer: 'int'
    #: Route.
    route: 'Optional[tuple[IPv4Address, ...]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', pointer: 'int', route: 'Optional[tuple[IPv4Address, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class SIDOption(Option):
    """Data model for IPv4 Stream ID (``SID``) option."""

    #: Stream ID.
    sid: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', sid: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class SSROption(Option):
    """Data model for IPv4 Strict Source Route (``SSR``) option."""

    #: Pointer.
    pointer: 'int'
    #: Route.
    route: 'Optional[tuple[IPv4Address, ...]]'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', pointer: 'int', route: 'Optional[tuple[IPv4Address, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class MTUPOption(Option):
    """Data model for IPv4 MTU Probe (``MTUP``) option."""

    #: MTU.
    mtu: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', mtu: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class MTUROption(Option):
    """Data model for IPv4 MTU Reply (``MTUR``) option."""

    #: MTU.
    mtu: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', mtu: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class TROption(Option):
    """Data model for IPv4 Traceroute (``TR``) option.

    Important:
        Due to the preserved keyword conflict, please use :meth:`from_dict`
        to create an instance of this data model.

    """

    #: ID number.
    id: 'int'
    #: Outbound hop count.
    outbound: 'int'
    #: Return hop count.
    #return: 'int'
    originator: 'IPv4Address'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'TROption':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: We cannot define ``return`` due to preserved keyword conflict.
        # Thus, we directly inject the information into the annotations.
        self.__annotations__['return'] = int  # pylint: disable=no-member

        return self  # type: ignore[return-value]


class RTRALTOption(Option):
    """Data model for IPv4 Router Alert (``RTRALT``) option."""

    #: Router alert.
    alert: 'RouterAlert'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', alert: 'RouterAlert') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long,redefined-builtin


class QSOption(Option):
    """Data model for IPv4 Quick Start (``QS``) option."""

    #: QS function.
    func: 'QSFunction'
    #: Rate request/report.
    rate: 'int'
    #: TTL.
    ttl: 'Optional[timedelta]'
    #: Nounce.
    nounce: 'int'

    if TYPE_CHECKING:
        def __init__(self, code: 'OptionNumber', length: 'int', type: 'OptionType', func: 'QSFunction', rate: 'int', ttl: 'Optional[timedelta]', nounce: 'int') -> 'None': ...  # pylint: disable=super-init-not-called,unused-argument,redefined-builtin,multiple-statements,line-too-long

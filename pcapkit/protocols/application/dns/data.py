# -*- coding: utf-8 -*-
"""data models for DNS protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional, Union

    from pcapkit.const.dns.opcode import Opcode as Enum_Opcode
    from pcapkit.const.dns.option import Option as Enum_Option
    from pcapkit.const.dns.rcode import RCode as Enum_RCode
    from pcapkit.const.dns.rr_class import RRClass as Enum_RRClass
    from pcapkit.const.dns.rr_type import RRType as Enum_RRType

__all__ = [
    'DNS', 'Flags', 'Name', 'Question', 'ResourceRecord', 'OPT', 'Option',
    'RData', 'A', 'AAAA', 'NS', 'CNAME', 'PTR', 'SOA', 'MX', 'TXT', 'SRV', 'CAA',
    'OptionData', 'ClientSubnet', 'Cookie', 'TCPKeepalive', 'ExtendedError',
]


@info_final
class Name(Data):
    """Data model for a domain name (:rfc:`1035#section-3.1`).

    :attr:`literal` and :attr:`pointer` record how the name was written, so
    that it is rebuilt with the compression it was read with
    (:rfc:`1035#section-4.1.4`).

    """

    #: Name in presentation form, absolute, e.g. ``www.example.com.``; the
    #: root is ``.``.
    name: 'str'
    #: Every label of the name, the root's empty label left out.
    labels: 'tuple[bytes, ...]'
    #: How many of :attr:`labels` are written in full where the name is.
    literal: 'int'
    #: Offset into the message of the compression pointer ending the name, or
    #: :obj:`None` where the root label ends it.
    pointer: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, name: 'str', labels: 'tuple[bytes, ...]', literal: 'int',
                     pointer: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class Flags(Data):
    """Data model for the DNS header flags (:rfc:`1035#section-4.1.1`)."""

    #: Whether the message is a response.
    qr: 'bool'
    #: Kind of query.
    opcode: 'Enum_Opcode'
    #: Authoritative answer.
    aa: 'bool'
    #: Truncation.
    tc: 'bool'
    #: Recursion desired.
    rd: 'bool'
    #: Recursion available.
    ra: 'bool'
    #: Reserved bit.
    z: 'int'
    #: Authentic data (:rfc:`4035#section-3.2.3`).
    ad: 'bool'
    #: Checking disabled (:rfc:`4035#section-3.2.2`).
    cd: 'bool'
    #: Response code, the low four bits of an extended one
    #: (:rfc:`6891#section-6.1.3`).
    rcode: 'Enum_RCode'

    if TYPE_CHECKING:
        def __init__(self, qr: 'bool', opcode: 'Enum_Opcode', aa: 'bool', tc: 'bool', rd: 'bool',
                     ra: 'bool', z: 'int', ad: 'bool', cd: 'bool', rcode: 'Enum_RCode') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Question(Data):
    """Data model for a question section entry (:rfc:`1035#section-4.1.2`).

    Its ``class`` key, a keyword in Python, holds the :class:`~pcapkit.const.dns.rr_class.RRClass`.

    """

    #: Domain name asked about.
    name: 'Name'
    #: Type of the query.
    type: 'Enum_RRType'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'Question':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: ``class`` is a keyword, so it is annotated here, as IPv6's data model does.
        cls.__annotations__['class'] = 'Enum_RRClass'

        return self


class RData(Data):
    """Data model for the decoded RDATA of a resource record.

    Each subclass is the structure one :class:`~pcapkit.const.dns.rr_type.RRType`
    carries, its fields named as its specification names them.

    """


@info_final
class ResourceRecord(Data):
    """Data model for a resource record (:rfc:`1035#section-4.1.3`).

    Its ``class`` key, a keyword in Python, holds the :class:`~pcapkit.const.dns.rr_class.RRClass`.
    :attr:`rdata` holds the decoded RDATA where
    :attr:`DNS.__rdata__ <pcapkit.protocols.application.dns.protocol.DNS.__rdata__>`
    registers a decoder for :attr:`type`, and the raw octets otherwise,
    including RDATA its decoder cannot read exactly.

    """

    #: Owner name.
    name: 'Name'
    #: Type.
    type: 'Enum_RRType'
    #: Time to live, in seconds.
    ttl: 'int'
    #: Length of the RDATA.
    rdlength: 'int'
    #: RDATA, decoded or as raw octets.
    rdata: 'Union[RData, bytes]'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'ResourceRecord':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: ``class`` is a keyword, so it is annotated here, as IPv6's data model does.
        cls.__annotations__['class'] = 'Enum_RRClass'

        return self


class OptionData(Data):
    """Data model for the decoded OPTION-DATA of an EDNS(0) option.

    Each subclass is the structure one :class:`~pcapkit.const.dns.option.Option`
    carries, its fields named as its specification names them.

    """


@info_final
class Option(Data):
    """Data model for an EDNS(0) option (:rfc:`6891#section-6.1.2`).

    :attr:`data` holds the decoded OPTION-DATA where
    :attr:`DNS.__option__ <pcapkit.protocols.application.dns.protocol.DNS.__option__>`
    registers a decoder for :attr:`code`, and the raw octets otherwise.

    """

    #: OPTION-CODE.
    code: 'Enum_Option'
    #: OPTION-LENGTH.
    length: 'int'
    #: OPTION-DATA, decoded or as raw octets.
    data: 'Union[OptionData, bytes]'

    if TYPE_CHECKING:
        def __init__(self, code: 'Enum_Option', length: 'int', data: 'Union[OptionData, bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class OPT(Data):
    """Data model for the OPT pseudo-record of EDNS(0) (:rfc:`6891#section-6.1.2`).

    The CLASS and TTL fields of a resource record are redefined for it, and
    each of their parts has a field here.

    """

    #: Owner name, the root.
    name: 'Name'
    #: Type, :attr:`~pcapkit.const.dns.rr_type.RRType.OPT`.
    type: 'Enum_RRType'
    #: Requestor's UDP payload size, the CLASS field.
    udp_payload_size: 'int'
    #: Upper eight bits of the extended RCODE.
    extended_rcode: 'int'
    #: EDNS version.
    version: 'int'
    #: DNSSEC OK bit (:rfc:`3225#section-3`).
    do: 'bool'
    #: The remaining fifteen bits of the TTL field.
    z: 'int'
    #: Length of the RDATA.
    rdlength: 'int'
    #: Options, or the raw RDATA where they do not decode.
    options: 'Union[tuple[Option, ...], bytes]'

    if TYPE_CHECKING:
        def __init__(self, name: 'Name', type: 'Enum_RRType', udp_payload_size: 'int', extended_rcode: 'int',
                     version: 'int', do: 'bool', z: 'int', rdlength: 'int',
                     options: 'Union[tuple[Option, ...], bytes]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long


@info_final
class A(RData):
    """Data model for the ``A`` RDATA (:rfc:`1035#section-3.4.1`)."""

    #: IPv4 address.
    address: 'IPv4Address'

    if TYPE_CHECKING:
        def __init__(self, address: 'IPv4Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class AAAA(RData):
    """Data model for the ``AAAA`` RDATA (:rfc:`3596#section-2.2`)."""

    #: IPv6 address.
    address: 'IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, address: 'IPv6Address') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class NS(RData):
    """Data model for the ``NS`` RDATA (:rfc:`1035#section-3.3.11`)."""

    #: Authoritative name server.
    nsdname: 'Name'

    if TYPE_CHECKING:
        def __init__(self, nsdname: 'Name') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class CNAME(RData):
    """Data model for the ``CNAME`` RDATA (:rfc:`1035#section-3.3.1`)."""

    #: Canonical name.
    cname: 'Name'

    if TYPE_CHECKING:
        def __init__(self, cname: 'Name') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class PTR(RData):
    """Data model for the ``PTR`` RDATA (:rfc:`1035#section-3.3.12`)."""

    #: Name pointed to.
    ptrdname: 'Name'

    if TYPE_CHECKING:
        def __init__(self, ptrdname: 'Name') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SOA(RData):
    """Data model for the ``SOA`` RDATA (:rfc:`1035#section-3.3.13`)."""

    #: Primary name server of the zone.
    mname: 'Name'
    #: Mailbox of the person responsible for the zone.
    rname: 'Name'
    #: Version number of the zone.
    serial: 'int'
    #: Refresh interval, in seconds.
    refresh: 'int'
    #: Retry interval, in seconds.
    retry: 'int'
    #: Expiry limit, in seconds.
    expire: 'int'
    #: Minimum TTL, in seconds; the negative-caching TTL (:rfc:`2308#section-4`).
    minimum: 'int'

    if TYPE_CHECKING:
        def __init__(self, mname: 'Name', rname: 'Name', serial: 'int', refresh: 'int', retry: 'int',
                     expire: 'int', minimum: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class MX(RData):
    """Data model for the ``MX`` RDATA (:rfc:`1035#section-3.3.9`)."""

    #: Preference, lower preferred.
    preference: 'int'
    #: Mail exchange host.
    exchange: 'Name'

    if TYPE_CHECKING:
        def __init__(self, preference: 'int', exchange: 'Name') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class TXT(RData):
    """Data model for the ``TXT`` RDATA (:rfc:`1035#section-3.3.14`)."""

    #: The character-strings, each without its length octet.
    strings: 'tuple[bytes, ...]'

    if TYPE_CHECKING:
        def __init__(self, strings: 'tuple[bytes, ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class SRV(RData):
    """Data model for the ``SRV`` RDATA (:rfc:`2782`)."""

    #: Priority, lower preferred.
    priority: 'int'
    #: Weight among targets of equal priority.
    weight: 'int'
    #: Port of the service.
    port: 'int'
    #: Target host.
    target: 'Name'

    if TYPE_CHECKING:
        def __init__(self, priority: 'int', weight: 'int', port: 'int', target: 'Name') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class CAA(RData):
    """Data model for the ``CAA`` RDATA (:rfc:`8659#section-4.1`)."""

    #: Flags octet.
    flags: 'int'
    #: Issuer Critical flag, the flags octet's high bit.
    critical: 'bool'
    #: Property tag.
    tag: 'bytes'
    #: Property value.
    value: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, flags: 'int', critical: 'bool', tag: 'bytes', value: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class ClientSubnet(OptionData):
    """Data model for the ``edns-client-subnet`` option (:rfc:`7871#section-6`)."""

    #: Address family (IANA Address Family Numbers).
    family: 'int'
    #: Source prefix length.
    source_prefix: 'int'
    #: Scope prefix length.
    scope_prefix: 'int'
    #: Address, as many octets as :attr:`source_prefix` covers.
    address: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, family: 'int', source_prefix: 'int', scope_prefix: 'int', address: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long


@info_final
class Cookie(OptionData):
    """Data model for the ``COOKIE`` option (:rfc:`7873#section-4`)."""

    #: Client cookie.
    client: 'bytes'
    #: Server cookie, empty when absent.
    server: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, client: 'bytes', server: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class TCPKeepalive(OptionData):
    """Data model for the ``edns-tcp-keepalive`` option (:rfc:`7828#section-3.1`)."""

    #: Idle timeout, in units of 100 milliseconds, or :obj:`None` when absent.
    timeout: 'Optional[int]'

    if TYPE_CHECKING:
        def __init__(self, timeout: 'Optional[int]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class ExtendedError(OptionData):
    """Data model for the ``Extended DNS Error`` option (:rfc:`8914#section-2`)."""

    #: INFO-CODE.
    info_code: 'int'
    #: EXTRA-TEXT, as octets; UTF-8 by the specification.
    extra_text: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, info_code: 'int', extra_text: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class DNS(Protocol):
    """Data model for a DNS message (:rfc:`1035#section-4.1`)."""

    #: Identifier.
    id: 'int'
    #: Header flags.
    flags: 'Flags'
    #: Number of question entries, as the header gives it.
    qdcount: 'int'
    #: Number of answer records, as the header gives it.
    ancount: 'int'
    #: Number of authority records, as the header gives it.
    nscount: 'int'
    #: Number of additional records, as the header gives it.
    arcount: 'int'
    #: Question section.
    question: 'tuple[Question, ...]'
    #: Answer section.
    answer: 'tuple[Union[ResourceRecord, OPT], ...]'
    #: Authority section.
    authority: 'tuple[Union[ResourceRecord, OPT], ...]'
    #: Additional section, holding the OPT pseudo-record of EDNS(0) if any.
    additional: 'tuple[Union[ResourceRecord, OPT], ...]'

    if TYPE_CHECKING:
        #: Message length, the two-octet field preceding the message over TCP
        #: (:rfc:`1035#section-4.2.2`); present only for such a message.
        length: 'int'
        #: Octets of the message past its last record, present only when there
        #: are any.
        trailer: 'bytes'

        def __init__(self, id: 'int', flags: 'Flags', qdcount: 'int', ancount: 'int', nscount: 'int',
                     arcount: 'int', question: 'tuple[Question, ...]',
                     answer: 'tuple[Union[ResourceRecord, OPT], ...]',
                     authority: 'tuple[Union[ResourceRecord, OPT], ...]',
                     additional: 'tuple[Union[ResourceRecord, OPT], ...]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long

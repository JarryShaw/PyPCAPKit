# -*- coding: utf-8 -*-
"""DNS - Domain Name System
==============================

.. module:: pcapkit.protocols.application.dns.protocol

:mod:`pcapkit.protocols.application.dns.protocol` holds
:class:`~pcapkit.protocols.application.dns.protocol.DNS`, the extractor for
Domain Name System (DNS) messages [:rfc:`1035`], whose header is:

.. table::

   ====== ===== ================== ===========================================
   Octets Bits  Name               Description
   ====== ===== ================== ===========================================
   0          0 ``dns.length``     Message Length (over TCP only)
   ------ ----- ------------------ -------------------------------------------
   0          0 ``dns.id``         Identifier
   ------ ----- ------------------ -------------------------------------------
   2         16 ``dns.flags``      QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE
   ------ ----- ------------------ -------------------------------------------
   4         32 ``dns.qdcount``    Question Count
   ------ ----- ------------------ -------------------------------------------
   6         48 ``dns.ancount``    Answer Count
   ------ ----- ------------------ -------------------------------------------
   8         64 ``dns.nscount``    Authority Count
   ------ ----- ------------------ -------------------------------------------
   10        80 ``dns.arcount``    Additional Count
   ====== ===== ================== ===========================================

The four sections follow: :attr:`~pcapkit.protocols.application.dns.data.DNS.question`,
:attr:`~pcapkit.protocols.application.dns.data.DNS.answer`,
:attr:`~pcapkit.protocols.application.dns.data.DNS.authority` and
:attr:`~pcapkit.protocols.application.dns.data.DNS.additional`.

Over TCP, the two-octet length precedes the message, so every offset above
moves two octets on (:rfc:`1035#section-4.2.2`, :rfc:`7766#section-8`).

.. versionadded:: 1.7.0

"""
import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.dns.opcode import Opcode as Enum_Opcode
from pcapkit.const.dns.option import Option as Enum_Option
from pcapkit.const.dns.rcode import RCode as Enum_RCode
from pcapkit.const.dns.rr_class import RRClass as Enum_RRClass
from pcapkit.const.dns.rr_type import RRType as Enum_RRType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.schema.ipaddress import parse_ip_address
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.application.dns.const import HEADER_LENGTH
from pcapkit.protocols.application.dns.data import AAAA as Data_AAAA
from pcapkit.protocols.application.dns.data import CAA as Data_CAA
from pcapkit.protocols.application.dns.data import CNAME as Data_CNAME
from pcapkit.protocols.application.dns.data import DNS as Data_DNS
from pcapkit.protocols.application.dns.data import MX as Data_MX
from pcapkit.protocols.application.dns.data import NS as Data_NS
from pcapkit.protocols.application.dns.data import OPT as Data_OPT
from pcapkit.protocols.application.dns.data import PTR as Data_PTR
from pcapkit.protocols.application.dns.data import SOA as Data_SOA
from pcapkit.protocols.application.dns.data import SRV as Data_SRV
from pcapkit.protocols.application.dns.data import TXT as Data_TXT
from pcapkit.protocols.application.dns.data import A as Data_A
from pcapkit.protocols.application.dns.data import ClientSubnet as Data_ClientSubnet
from pcapkit.protocols.application.dns.data import Cookie as Data_Cookie
from pcapkit.protocols.application.dns.data import ExtendedError as Data_ExtendedError
from pcapkit.protocols.application.dns.data import Flags as Data_Flags
from pcapkit.protocols.application.dns.data import Name as Data_Name
from pcapkit.protocols.application.dns.data import Option as Data_Option
from pcapkit.protocols.application.dns.data import Question as Data_Question
from pcapkit.protocols.application.dns.data import ResourceRecord as Data_ResourceRecord
from pcapkit.protocols.application.dns.data import TCPKeepalive as Data_TCPKeepalive
from pcapkit.protocols.application.dns.schema import DNS as Schema_DNS
from pcapkit.protocols.application.dns.schema import (compress_name, make_name, name_to_text,
                                                      read_name, record_name, text_to_labels)
from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Callable, DefaultDict, Iterable, Mapping, Optional, Union

    from mypy_extensions import NamedArg
    from typing_extensions import Literal

    from pcapkit.const.reg.apptype.udp import UDP as AppType_UDP
    from pcapkit.protocols.application.dns.data import OptionData as Data_OptionData
    from pcapkit.protocols.application.dns.data import RData as Data_RData
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

    #: Parser of an RDATA, given its type and octets, and the message and offset
    #: they sit at for the names inside.
    RDataParser = Callable[[Enum_RRType, bytes, NamedArg(bytes, 'message'), NamedArg(int, 'offset')],
                           Union[Data_RData, bytes]]
    #: Constructor of an RDATA, given its type and fields, and the offset it is
    #: written at and the names written so far for compression.
    RDataConstructor = Callable[[Enum_RRType, 'Mapping[str, Any]', NamedArg(int, 'offset'),
                                 NamedArg(Optional[dict[tuple[bytes, ...], int]], 'table')], bytes]
    #: Parser of an EDNS(0) OPTION-DATA.
    OptionParser = Callable[[Enum_Option, bytes], Union[Data_OptionData, bytes]]
    #: Constructor of an EDNS(0) OPTION-DATA.
    OptionConstructor = Callable[[Enum_Option, 'Mapping[str, Any]'], bytes]

    #: A name as :meth:`DNS.make` takes it.
    NameLike = Union[str, 'Iterable[bytes]', 'Mapping[str, Any]']

__all__ = ['DNS']

#: UDP's AppType registry, named lazily so that importing this module does not
#: import it.
_UDP: 'ModuleDescriptor[AppType_UDP]' = ModuleDescriptor('pcapkit.const.reg.apptype.udp', 'UDP')


def _opens_whole_message(octets: 'bytes') -> 'bool':
    """Whether ``octets`` open with a whole message behind a TCP length field.

    Args:
        octets: Octets after a message over TCP.

    Returns:
        Whether the two-octet length is at least a header's and the octets it
        counts are all there.

    """
    if len(octets) < 2:
        return False
    length = int.from_bytes(octets[:2], 'big')
    return length >= HEADER_LENGTH and len(octets) >= 2 + length


def _sections_end(message: 'bytes') -> 'Optional[int]':
    """Where the sections the header of ``message`` counts end, if they fit in it.

    Args:
        message: Octets read as a message, from its header on.

    Returns:
        The offset just past the last entry, where every entry the four counts
        name has a well-formed name and ends inside ``message``; :obj:`None`
        otherwise. RDATA is not decoded.

    """
    if len(message) < HEADER_LENGTH:
        return None
    counts = [int.from_bytes(message[index:index + 2], 'big') for index in range(4, HEADER_LENGTH, 2)]
    pos = HEADER_LENGTH
    try:
        # NOTE: A name that does not read is an answer here, so its error is quiet.
        with CaughtByCaller(ProtocolError):
            for _ in range(counts[0]):
                pos = read_name(message, pos)[3] + 4
                if pos > len(message):
                    return None
            for _ in range(sum(counts[1:])):
                pos = read_name(message, pos)[3] + 10
                if pos > len(message):
                    return None
                pos += int.from_bytes(message[pos - 2:pos], 'big')
                if pos > len(message):
                    return None
    except ProtocolError:
        return None
    return pos


def _frames_message(octets: 'bytes') -> 'bool':
    """Whether ``octets`` are a message behind the TCP length field.

    Args:
        octets: Octets of a DNS layer, with ``framed`` not given.

    Returns:
        Whether a whole message behind a length field opens ``octets`` and
        decodes, and ``octets`` do not decode as a message, or decode no
        better. Where both readings decode and the framed message ends exactly
        at its length, the framed one is taken if the plain one stops short of
        the end of ``octets``; if it reads to the end, the framed one is taken
        where it counts a question and the plain one none, or where a further
        framed message follows that ends exactly at its length too. So a plain
        message whose ID equals the octets after it, with its question, stays
        plain.

    Note:
        A length read as an ID makes the flags read as the question count,
        which flags of zero leave at zero, so the plain reading of a framed
        message with such flags can decode: it stops short of the end, or
        reads an octet run it lands on, such as a following message's length,
        as an RDLENGTH counting the rest.

    """
    if not _opens_whole_message(octets):
        return False
    length = int.from_bytes(octets[:2], 'big')
    framed = _sections_end(octets[2:2 + length])
    if framed is None:
        return False
    plain = _sections_end(octets)
    if plain is None:
        return True
    if framed != length:
        return False
    if plain < len(octets):
        return True
    if int.from_bytes(octets[4:6], 'big') == 0 < int.from_bytes(octets[6:8], 'big'):
        return True
    rest = octets[2 + length:]
    nested = int.from_bytes(rest[:2], 'big')
    return _opens_whole_message(rest) and _sections_end(rest[2:2 + nested]) == nested


class DNS(Application[Data_DNS, Schema_DNS], schema=Schema_DNS, data=Data_DNS):
    """This class implements Domain Name System.

    A message is parsed whole: the header, the four sections, the RDATA of the
    types :attr:`__rdata__` registers and the options of the OPT pseudo-record
    of EDNS(0) (:rfc:`6891`) that :attr:`__option__` registers. Each domain name
    records the compression it was read with
    (:class:`~pcapkit.protocols.application.dns.data.Name`), so a message
    rebuilds as captured.

    Over TCP the two-octet length precedes the message, which ``framed=True``
    reads and writes. A parse not given ``framed`` reads the length where a
    whole message decodes behind it and the octets read worse as a plain
    message, as :func:`_frames_message` weighs them, much as TLS tries SSLv2 on
    what its own parser refuses (:ref:`protocol-family-ssl`): the port the
    transport dispatches on is the same for TCP and UDP. A further whole message after a framed one is
    dissected as another :class:`DNS` layer, the previous one's payload, as TLS
    records are; a message the segment ends inside is not reassembled and
    stays :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

    The RDATA each type carries:

    .. list-table::
       :header-rows: 1

       * - RR Type
         - Data Model
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.A`
         - :class:`~pcapkit.protocols.application.dns.data.A`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.NS`
         - :class:`~pcapkit.protocols.application.dns.data.NS`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.CNAME`
         - :class:`~pcapkit.protocols.application.dns.data.CNAME`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.SOA`
         - :class:`~pcapkit.protocols.application.dns.data.SOA`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.PTR`
         - :class:`~pcapkit.protocols.application.dns.data.PTR`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.MX`
         - :class:`~pcapkit.protocols.application.dns.data.MX`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.TXT`
         - :class:`~pcapkit.protocols.application.dns.data.TXT`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.AAAA`
         - :class:`~pcapkit.protocols.application.dns.data.AAAA`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.SRV`
         - :class:`~pcapkit.protocols.application.dns.data.SRV`
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.OPT`
         - :class:`~pcapkit.protocols.application.dns.data.OPT`, the whole record
       * - :attr:`~pcapkit.const.dns.rr_type.RRType.CAA`
         - :class:`~pcapkit.protocols.application.dns.data.CAA`

    Any other type, and RDATA its decoder cannot read exactly, is kept as raw
    octets. The EDNS(0) options decoded are ``edns-client-subnet``
    (:class:`~pcapkit.protocols.application.dns.data.ClientSubnet`), ``COOKIE``
    (:class:`~pcapkit.protocols.application.dns.data.Cookie`),
    ``edns-tcp-keepalive``
    (:class:`~pcapkit.protocols.application.dns.data.TCPKeepalive`) and
    ``Extended DNS Error``
    (:class:`~pcapkit.protocols.application.dns.data.ExtendedError`); any other
    is kept as raw octets.

    """
    #: Octets of the message with its TCP length field, as :meth:`read` measures
    #: them; :attr:`length` reads it.
    _length: 'int'

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: RR type to method mapping, see :meth:`_read_dns_record` and
    #: :meth:`_make_dns_record`. A :obj:`str` value names the methods
    #: ``_read_rdata_${name}`` and ``_make_rdata_${name}``, falling back to
    #: :meth:`_read_rdata_unknown` and :meth:`_make_rdata_unknown` when the
    #: class has no such method; any other value is a ``(parser, constructor)``
    #: pair of callables. The OPT pseudo-record is read whole by
    #: :meth:`_read_dns_opt`, outside this map.
    __rdata__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_RRType.A: 'a',          # [RFC 1035]
            Enum_RRType.NS: 'ns',        # [RFC 1035]
            Enum_RRType.CNAME: 'cname',  # [RFC 1035]
            Enum_RRType.SOA: 'soa',      # [RFC 1035]
            Enum_RRType.PTR: 'ptr',      # [RFC 1035]
            Enum_RRType.MX: 'mx',        # [RFC 1035]
            Enum_RRType.TXT: 'txt',      # [RFC 1035]
            Enum_RRType.AAAA: 'aaaa',    # [RFC 3596]
            Enum_RRType.SRV: 'srv',      # [RFC 2782]
            Enum_RRType.CAA: 'caa',      # [RFC 8659]
        },
    )  # type: DefaultDict[Enum_RRType | int, str | tuple[RDataParser, RDataConstructor]]

    #: EDNS(0) option code to method mapping, see :meth:`_read_dns_options`
    #: and :meth:`_make_dns_options`. A :obj:`str` value names the methods
    #: ``_read_opt_${name}`` and ``_make_opt_${name}``, falling back to
    #: :meth:`_read_opt_unknown` and :meth:`_make_opt_unknown`; any other
    #: value is a ``(parser, constructor)`` pair of callables.
    __option__ = collections.defaultdict(
        lambda: 'unknown',
        {
            Enum_Option.edns_client_subnet: 'client_subnet',     # [RFC 7871]
            Enum_Option.COOKIE: 'cookie',                        # [RFC 7873]
            Enum_Option.edns_tcp_keepalive: 'tcp_keepalive',     # [RFC 7828]
            Enum_Option.Extended_DNS_Error: 'extended_error',    # [RFC 8914]
        },
    )  # type: DefaultDict[Enum_Option | int, str | tuple[OptionParser, OptionConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Domain Name System"]':
        """Name of current protocol."""
        return 'Domain Name System'

    @property
    def length(self) -> 'int':
        """Header length of current protocol, i.e. the message with its TCP length field."""
        return self._length

    @property
    def rcode(self) -> 'Enum_RCode | int':
        """Response code, extended by the OPT pseudo-record's upper bits if any
        (:rfc:`6891#section-6.1.3`)."""
        code = int(self._info.flags['rcode'])
        for record in self._info.additional:
            if isinstance(record, Data_OPT):
                code |= int(record.extended_rcode) << 4
                break
        return Enum_RCode.get(code)

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DNS':
        """Read Domain Name System.

        Structure of DNS header [:rfc:`1035`]:

        .. code-block:: text

                                           1  1  1  1  1  1
             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      ID                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    QDCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ANCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    NSCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                    ARCOUNT                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the TCP length field counts fewer octets than
                the header, or a section entry runs past the message or holds
                a malformed domain name.

        """
        schema = self.__header__
        framed = schema.length is not None
        if framed and cast('int', schema.length) < HEADER_LENGTH:
            raise ProtocolError(f'{self.alias}: invalid format: message length {schema.length} '
                                f'is shorter than the header')

        start = 2 if framed else 0
        message = self._data[start:start + HEADER_LENGTH + len(schema.body)]
        self._length = start + len(message)

        flags = schema.flags
        pos = HEADER_LENGTH
        question = []  # type: list[Data_Question]
        for _ in range(schema.qdcount):
            entry, pos = self._read_dns_question(message, pos)
            question.append(entry)
        sections = []  # type: list[tuple[Data_ResourceRecord | Data_OPT, ...]]
        for count in (schema.ancount, schema.nscount, schema.arcount):
            records = []  # type: list[Data_ResourceRecord | Data_OPT]
            for _ in range(count):
                record, pos = self._read_dns_record(message, pos)
                records.append(record)
            sections.append(tuple(records))

        dns = Data_DNS(
            id=schema.id,
            flags=Data_Flags(
                qr=bool(flags['qr']),
                opcode=Enum_Opcode.get(flags['opcode']),
                aa=bool(flags['aa']),
                tc=bool(flags['tc']),
                rd=bool(flags['rd']),
                ra=bool(flags['ra']),
                z=flags['z'],
                ad=bool(flags['ad']),
                cd=bool(flags['cd']),
                rcode=Enum_RCode.get(flags['rcode']),
            ),
            qdcount=schema.qdcount,
            ancount=schema.ancount,
            nscount=schema.nscount,
            arcount=schema.arcount,
            question=tuple(question),
            answer=sections[0],
            authority=sections[1],
            additional=sections[2],
        )
        if framed:
            dns.__update__([
                ('length', schema.length),
            ])
        # NOTE: Octets the message holds past its last record are kept, so the
        # message rebuilds as captured.
        if pos < len(message):
            dns.__update__([
                ('trailer', message[pos:]),
            ])

        rest = (len(self._data) if length is None else length) - self._length
        return self._decode_next_layer(dns, -1, rest)

    def make(self,  # pylint: disable=redefined-builtin
             id: 'int' = 0,
             qr: 'bool' = False,
             opcode: 'Enum_Opcode | int' = Enum_Opcode.Query,
             aa: 'bool' = False,
             tc: 'bool' = False,
             rd: 'bool' = False,
             ra: 'bool' = False,
             z: 'int' = 0,
             ad: 'bool' = False,
             cd: 'bool' = False,
             rcode: 'Enum_RCode | int' = Enum_RCode.NoError,
             question: 'Iterable[Mapping[str, Any]]' = (),
             answer: 'Iterable[Mapping[str, Any]]' = (),
             authority: 'Iterable[Mapping[str, Any]]' = (),
             additional: 'Iterable[Mapping[str, Any]]' = (),
             framed: 'bool' = False,
             message_length: 'Optional[int]' = None,
             compress: 'bool' = False,
             trailer: 'bytes' = b'',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_DNS':
        """Make (construct) packet data.

        The section counts are those of the entries given. A question entry
        is a mapping of ``name``, ``type`` and ``class``, as
        :class:`~pcapkit.protocols.application.dns.data.Question` is. A record
        is a mapping of ``name``, ``type``, ``class``, ``ttl``, ``rdlength``
        and ``rdata``, as
        :class:`~pcapkit.protocols.application.dns.data.ResourceRecord` is,
        or, for the OPT pseudo-record, of the fields of
        :class:`~pcapkit.protocols.application.dns.data.OPT`. ``rdata`` is raw
        octets, or a mapping of the fields of the type's data model, as
        :attr:`__rdata__` registers it. A name is a
        :class:`~pcapkit.protocols.application.dns.data.Name`, which writes
        the compression it records, its labels, or its presentation form.

        Args:
            id: Identifier.
            qr: Whether the message is a response.
            opcode: Kind of query.
            aa: Authoritative answer.
            tc: Truncation.
            rd: Recursion desired.
            ra: Recursion available.
            z: Reserved bit.
            ad: Authentic data.
            cd: Checking disabled.
            rcode: Response code, the header's four bits.
            question: Question section.
            answer: Answer section.
            authority: Authority section.
            additional: Additional section.
            framed: Whether to write the TCP length field.
            message_length: TCP length field, written whenever given; the
                message's own length otherwise.
            compress: Whether to compress the names given as labels or text
                against those written before them (:rfc:`1035#section-4.1.4`),
                where the type allows it.
            trailer: Octets of the message past its last record.
            payload: Payload data, after the message.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If a field does not fit its width, an enumeration
                field is a name or a :obj:`bool` for a field wider than a bit,
                a name is malformed, or ``rdata`` is a mapping for a type with
                no constructor.

        """
        table = {} if compress else None  # type: Optional[dict[tuple[bytes, ...], int]]
        sections = (tuple(question), tuple(answer), tuple(authority), tuple(additional))
        body = bytearray()
        for entry in sections[0]:
            body += self._make_dns_question(entry, offset=HEADER_LENGTH + len(body), table=table)
        for section in sections[1:]:
            for record in section:
                body += self._make_dns_record(record, offset=HEADER_LENGTH + len(body), table=table)
        if not isinstance(trailer, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid trailer: {trailer!r}')
        body += trailer

        counts = [self._make_uint(len(section), bits=16, name='section count') for section in sections]

        if message_length is not None:
            length = self._make_uint(message_length, bits=16, name='message length')  # type: Optional[int]
        elif framed:
            length = self._make_uint(HEADER_LENGTH + len(body), bits=16, name='message length')
        else:
            length = None

        return Schema_DNS(
            length=length,
            id=self._make_uint(id, bits=16, name='identifier'),
            flags={
                'qr': self._make_uint(qr, bits=1, name='QR flag'),
                'opcode': int(self._make_index(opcode, Enum_Opcode, bits=4, name='opcode')),
                'aa': self._make_uint(aa, bits=1, name='AA flag'),
                'tc': self._make_uint(tc, bits=1, name='TC flag'),
                'rd': self._make_uint(rd, bits=1, name='RD flag'),
                'ra': self._make_uint(ra, bits=1, name='RA flag'),
                'z': self._make_uint(z, bits=1, name='Z bit'),
                'ad': self._make_uint(ad, bits=1, name='AD flag'),
                'cd': self._make_uint(cd, bits=1, name='CD flag'),
                'rcode': int(self._make_index(rcode, Enum_RCode, bits=4, name='rcode')),
            },
            qdcount=counts[0],
            ancount=counts[1],
            nscount=counts[2],
            arcount=counts[3],
            body=bytes(body),
            payload=payload,
        )

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an EDNS(0) option parser.

        Args:
            code: EDNS(0) option code.
            meth: Name of the ``_read_opt_${name}`` and ``_make_opt_${name}``
                methods, or a ``(parser, constructor)`` pair of callables; see
                :attr:`__option__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op.

        """
        incumbent = cls.__option__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'DNS: [Option {code}] option already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    @classmethod
    def register_rdata(cls, code: 'Enum_RRType', meth: 'str | tuple[RDataParser, RDataConstructor]') -> 'None':
        """Register an RDATA parser.

        Args:
            code: RR type.
            meth: Name of the ``_read_rdata_${name}`` and ``_make_rdata_${name}``
                methods, or a ``(parser, constructor)`` pair of callables; see
                :attr:`__rdata__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op.

        """
        incumbent = cls.__rdata__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'DNS: [RR {code}] RDATA already registered, overwriting', RegistryWarning)
        cls.__rdata__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'int':
        """Return an estimated length for the object."""
        return HEADER_LENGTH

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: port 53, the port of
            :attr:`UDP.domain <pcapkit.const.reg.apptype.udp.UDP.domain>` as an
            :class:`int`, at which :attr:`UDP.__proto__
            <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>` and
            :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.protocol.TCP.__proto__>`
            dispatch here (:ref:`registry-protocol-index`).

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        """
        return int(_UDP.klass.domain)  # type: ignore[call-overload]

    def __post_init__(self, file: 'Optional[Any]' = None, length: 'Optional[int]' = None,
                      **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            framed (Optional[bool]): Parsing, whether the TCP length field
                precedes the message. When not given, it does where
                :func:`_frames_message` finds a whole message behind a length
                field that reads better than the octets as a plain one, which
                is how a TCP segment carries one.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            :meth:`self.make <pcapkit.protocols.application.dns.protocol.DNS.make>`
            for the construction arguments.

        """
        if file is not None:
            framed = kwargs.pop('framed', None)
            data = file if isinstance(file, bytes) else file.read(length)
            if framed is None:
                framed = _frames_message(data if length is None else data[:length])
            kwargs['__packet__'] = {**kwargs.get('__packet__', {}), '__framed__': bool(framed)}
            file = data
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_DNS') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        flags = data['flags']
        return {
            'id': data['id'],
            'qr': flags['qr'],
            'opcode': flags['opcode'],
            'aa': flags['aa'],
            'tc': flags['tc'],
            'rd': flags['rd'],
            'ra': flags['ra'],
            'z': flags['z'],
            'ad': flags['ad'],
            'cd': flags['cd'],
            'rcode': flags['rcode'],
            'question': tuple(data['question']),
            'answer': tuple(data['answer']),
            'authority': tuple(data['authority']),
            'additional': tuple(data['additional']),
            'framed': 'length' in data,
            'message_length': data.get('length'),
            'trailer': data.get('trailer', b''),
            'payload': cls._make_payload(data),
        }

    def _read_dns_question(self, message: 'bytes', pos: 'int') -> 'tuple[Data_Question, int]':
        """Read a question section entry.

        Structure of a question entry [:rfc:`1035#section-4.1.2`]:

        .. code-block:: text

                                           1  1  1  1  1  1
             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           /                     QNAME                     /
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                     QTYPE                     |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                     QCLASS                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        Args:
            message: The message, from its header on.
            pos: Offset of the entry in ``message``.

        Returns:
            The entry, and the offset just past it.

        """
        name, pos = self._read_dns_name(message, pos)
        return Data_Question.from_dict({
            'name': name,
            'type': Enum_RRType.get(self._read_uint(message, pos, size=2, what='question type')),
            'class': Enum_RRClass.get(self._read_uint(message, pos + 2, size=2, what='question class')),
        }), pos + 4

    def _make_dns_question(self, entry: 'Mapping[str, Any]', *, offset: 'int',
                           table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make a question section entry.

        Args:
            entry: The entry's ``name``, ``type`` and ``class``.
            offset: Offset of the entry in the message.
            table: Names written so far, when compressing.

        Returns:
            The entry's octets.

        """
        if not isinstance(entry, collections.abc.Mapping):
            raise ProtocolError(f'{self.alias}: invalid question entry: {entry!r}')
        name = self._make_dns_name(entry.get('name', '.'), offset=offset, table=table)
        qtype = self._make_index(entry.get('type', Enum_RRType.A), Enum_RRType, bits=16, name='question type')
        qclass = self._make_index(entry.get('class', Enum_RRClass.IN), Enum_RRClass, bits=16,
                                  name='question class')
        return name + self._make_pack(int(qtype), size=2) + self._make_pack(int(qclass), size=2)

    def _read_dns_record(self, message: 'bytes', pos: 'int') -> 'tuple[Data_ResourceRecord | Data_OPT, int]':
        """Read a resource record.

        Structure of a resource record [:rfc:`1035#section-4.1.3`]:

        .. code-block:: text

                                           1  1  1  1  1  1
             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           /                      NAME                     /
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      TYPE                     |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                     CLASS                     |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                      TTL                      |
           |                                               |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
           |                   RDLENGTH                    |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
           /                     RDATA                     /
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        The RDATA is read by the parser :attr:`__rdata__` registers for its
        type. Its length delimits it, so RDATA its parser rejects with a
        :exc:`~pcapkit.utilities.exceptions.ProtocolError` is kept as raw
        octets, quietly, as a TLS extension body is.

        Args:
            message: The message, from its header on.
            pos: Offset of the record in ``message``.

        Returns:
            The record, and the offset just past it.

        """
        name, pos = self._read_dns_name(message, pos)
        rr_type = Enum_RRType.get(self._read_uint(message, pos, size=2, what='record type'))
        rr_class = self._read_uint(message, pos + 2, size=2, what='record class')
        ttl = self._read_uint(message, pos + 4, size=4, what='record TTL')
        rdlength = self._read_uint(message, pos + 8, size=2, what='record data length')
        start = pos + 10
        rdata = self._read_octets(message, start, size=rdlength, what='record data')

        if rr_type == Enum_RRType.OPT:
            return self._read_dns_opt(name, rr_class, ttl, rdata), start + rdlength

        meth = self._lookup_registry(self.__rdata__, rr_type)
        if isinstance(meth, str):
            parser = cast('RDataParser', getattr(self, f'_read_rdata_{meth}', self._read_rdata_unknown))
        else:
            parser = meth[0]
        try:
            # NOTE: RDATA its parser rejects is kept raw below, so the error is quiet.
            with CaughtByCaller(ProtocolError):
                value = parser(rr_type, rdata, message=message, offset=start)  # type: Data_RData | bytes
        except ProtocolError:
            value = rdata
        return Data_ResourceRecord.from_dict({
            'name': name,
            'type': rr_type,
            'class': Enum_RRClass.get(rr_class),
            'ttl': ttl,
            'rdlength': rdlength,
            'rdata': value,
        }), start + rdlength

    def _make_dns_record(self, record: 'Mapping[str, Any]', *, offset: 'int',
                         table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make a resource record, or the OPT pseudo-record.

        Args:
            record: The record's fields, as :meth:`make` describes them.
            offset: Offset of the record in the message.
            table: Names written so far, when compressing.

        Returns:
            The record's octets.

        """
        if not isinstance(record, collections.abc.Mapping):
            raise ProtocolError(f'{self.alias}: invalid resource record: {record!r}')
        name = self._make_dns_name(record.get('name', '.'), offset=offset, table=table)
        rr_type = self._make_index(record.get('type', Enum_RRType.A), Enum_RRType, bits=16, name='record type')
        start = offset + len(name) + 10

        if rr_type == Enum_RRType.OPT and 'class' not in record:
            rr_class, ttl, rdata = self._make_dns_opt(record)
        else:
            rr_class = int(self._make_index(record.get('class', Enum_RRClass.IN), Enum_RRClass, bits=16,
                                            name='record class'))
            ttl = self._make_uint(record.get('ttl', 0), bits=32, name='record TTL')
            value = record.get('rdata')
            if isinstance(value, (bytes, bytearray)):
                rdata = bytes(value)
            else:
                meth = self._lookup_registry(self.__rdata__, rr_type)
                if isinstance(meth, str):
                    maker = cast('RDataConstructor', getattr(self, f'_make_rdata_{meth}', self._make_rdata_unknown))
                else:
                    maker = meth[1]
                rdata = maker(rr_type, {} if value is None else value, offset=start, table=table)

        rdlength = record.get('rdlength')
        size = len(rdata) if rdlength is None else self._make_uint(rdlength, bits=16, name='record data length')
        return (name + self._make_pack(int(rr_type), size=2) + self._make_pack(rr_class, size=2)
                + self._make_pack(ttl, size=4) + self._make_pack(size, size=2) + rdata)

    def _read_rdata_unknown(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                            message: 'bytes', offset: 'int') -> 'bytes':  # pylint: disable=unused-argument
        """Read an RDATA with no decoder registered: its raw octets.

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            ``data`` itself.

        """
        return data

    def _read_rdata_a(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                      message: 'bytes', offset: 'int') -> 'Data_A':  # pylint: disable=unused-argument
        """Read an ``A`` RDATA (:rfc:`1035#section-3.4.1`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        Raises:
            ProtocolError: If ``data`` is not four octets.

        """
        if len(data) != 4:
            raise ProtocolError(f'{self.alias}: invalid A record data length: {len(data)}')
        return Data_A(address=cast('IPv4Address', parse_ip_address(data, f'{self.alias}: A record address',
                                                                    version=4)))

    def _read_rdata_ns(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                       message: 'bytes', offset: 'int') -> 'Data_NS':
        """Read an ``NS`` RDATA (:rfc:`1035#section-3.3.11`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        """
        return Data_NS(nsdname=self._read_rdata_name(data, message, offset))

    def _read_rdata_cname(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                          message: 'bytes', offset: 'int') -> 'Data_CNAME':
        """Read a ``CNAME`` RDATA (:rfc:`1035#section-3.3.1`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        """
        return Data_CNAME(cname=self._read_rdata_name(data, message, offset))

    def _read_rdata_soa(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                        message: 'bytes', offset: 'int') -> 'Data_SOA':
        """Read an ``SOA`` RDATA (:rfc:`1035#section-3.3.13`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        Raises:
            ProtocolError: If the names do not leave exactly the five 32-bit
                fields.

        """
        limit = offset + len(data)
        mname, pos = self._read_dns_name(message, offset, limit=limit)
        rname, pos = self._read_dns_name(message, pos, limit=limit)
        if limit - pos != 20:
            raise ProtocolError(f'{self.alias}: invalid SOA record data length: {len(data)}')
        serial, refresh, retry, expire, minimum = (
            self._read_uint(message, pos + 4 * index, size=4, what='SOA field') for index in range(5))
        return Data_SOA(mname=mname, rname=rname, serial=serial, refresh=refresh, retry=retry,
                        expire=expire, minimum=minimum)

    def _read_rdata_ptr(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                        message: 'bytes', offset: 'int') -> 'Data_PTR':
        """Read a ``PTR`` RDATA (:rfc:`1035#section-3.3.12`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        """
        return Data_PTR(ptrdname=self._read_rdata_name(data, message, offset))

    def _read_rdata_mx(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                       message: 'bytes', offset: 'int') -> 'Data_MX':
        """Read an ``MX`` RDATA (:rfc:`1035#section-3.3.9`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        """
        preference = self._read_uint(data, 0, size=2, what='MX preference')
        return Data_MX(preference=preference, exchange=self._read_rdata_name(data, message, offset, skip=2))

    def _read_rdata_txt(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                        message: 'bytes', offset: 'int') -> 'Data_TXT':  # pylint: disable=unused-argument
        """Read a ``TXT`` RDATA (:rfc:`1035#section-3.3.14`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        Raises:
            ProtocolError: If ``data`` is empty, or a character-string runs past it.

        """
        if not data:
            raise ProtocolError(f'{self.alias}: invalid TXT record: no character-string')
        strings = []  # type: list[bytes]
        pos = 0
        while pos < len(data):
            string, pos = self._read_vector(data, pos, size=1, what='TXT character-string')
            strings.append(string)
        return Data_TXT(strings=tuple(strings))

    def _read_rdata_aaaa(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                         message: 'bytes', offset: 'int') -> 'Data_AAAA':  # pylint: disable=unused-argument
        """Read an ``AAAA`` RDATA (:rfc:`3596#section-2.2`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        Raises:
            ProtocolError: If ``data`` is not sixteen octets.

        """
        if len(data) != 16:
            raise ProtocolError(f'{self.alias}: invalid AAAA record data length: {len(data)}')
        return Data_AAAA(address=cast('IPv6Address', parse_ip_address(data, f'{self.alias}: AAAA record address',
                                                                       version=6)))

    def _read_rdata_srv(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                        message: 'bytes', offset: 'int') -> 'Data_SRV':
        """Read an ``SRV`` RDATA (:rfc:`2782`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        """
        priority, weight, port = (self._read_uint(data, 2 * index, size=2, what='SRV field') for index in range(3))
        return Data_SRV(priority=priority, weight=weight, port=port,
                        target=self._read_rdata_name(data, message, offset, skip=6))

    def _read_rdata_caa(self, rr_type: 'Enum_RRType', data: 'bytes', *,  # pylint: disable=unused-argument
                        message: 'bytes', offset: 'int') -> 'Data_CAA':  # pylint: disable=unused-argument
        """Read a ``CAA`` RDATA (:rfc:`8659#section-4.1`).

        Args:
            rr_type: RR type.
            data: RDATA octets.
            message: The message, for the names inside.
            offset: Offset of ``data`` in ``message``.

        Returns:
            Parsed RDATA.

        Raises:
            ProtocolError: If the tag is empty or runs past ``data``.

        """
        flags = self._read_uint(data, 0, size=1, what='CAA flags')
        tag, pos = self._read_vector(data, 1, size=1, what='CAA tag')
        if not tag:
            raise ProtocolError(f'{self.alias}: invalid CAA record: empty tag')
        return Data_CAA(flags=flags, critical=bool(flags & 0x80), tag=tag, value=data[pos:])

    def _read_opt_unknown(self, code: 'Enum_Option', data: 'bytes') -> 'bytes':  # pylint: disable=unused-argument
        """Read an EDNS(0) option with no decoder registered: its raw octets.

        Args:
            code: Option code.
            data: OPTION-DATA octets.

        Returns:
            ``data`` itself.

        """
        return data

    def _read_opt_client_subnet(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ClientSubnet':  # pylint: disable=unused-argument
        """Read an ``edns-client-subnet`` option (:rfc:`7871#section-6`).

        Args:
            code: Option code.
            data: OPTION-DATA octets.

        Returns:
            Parsed OPTION-DATA.

        """
        return Data_ClientSubnet(
            family=self._read_uint(data, 0, size=2, what='client subnet family'),
            source_prefix=self._read_uint(data, 2, size=1, what='client subnet source prefix length'),
            scope_prefix=self._read_uint(data, 3, size=1, what='client subnet scope prefix length'),
            address=data[4:],
        )

    def _read_opt_cookie(self, code: 'Enum_Option', data: 'bytes') -> 'Data_Cookie':  # pylint: disable=unused-argument
        """Read a ``COOKIE`` option (:rfc:`7873#section-4`).

        Args:
            code: Option code.
            data: OPTION-DATA octets.

        Returns:
            Parsed OPTION-DATA.

        Raises:
            ProtocolError: If ``data`` is neither the 8-octet client cookie
                nor that and a server cookie of 8 to 32 octets.

        """
        if not (len(data) == 8 or 16 <= len(data) <= 40):
            raise ProtocolError(f'{self.alias}: invalid COOKIE option length: {len(data)}')
        return Data_Cookie(client=data[:8], server=data[8:])

    def _read_opt_tcp_keepalive(self, code: 'Enum_Option', data: 'bytes') -> 'Data_TCPKeepalive':  # pylint: disable=unused-argument
        """Read an ``edns-tcp-keepalive`` option (:rfc:`7828#section-3.1`).

        Args:
            code: Option code.
            data: OPTION-DATA octets.

        Returns:
            Parsed OPTION-DATA.

        Raises:
            ProtocolError: If ``data`` is neither empty nor two octets.

        """
        if len(data) not in (0, 2):
            raise ProtocolError(f'{self.alias}: invalid edns-tcp-keepalive option length: {len(data)}')
        return Data_TCPKeepalive(timeout=int.from_bytes(data, 'big') if data else None)

    def _read_opt_extended_error(self, code: 'Enum_Option', data: 'bytes') -> 'Data_ExtendedError':  # pylint: disable=unused-argument
        """Read an ``Extended DNS Error`` option (:rfc:`8914#section-2`).

        Args:
            code: Option code.
            data: OPTION-DATA octets.

        Returns:
            Parsed OPTION-DATA.

        """
        return Data_ExtendedError(info_code=self._read_uint(data, 0, size=2, what='extended error INFO-CODE'),
                                  extra_text=data[2:])

    def _make_rdata_unknown(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,
                            offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an RDATA with no constructor registered.

        Args:
            rr_type: RR type.
            data: RDATA fields; none can be written.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            Empty RDATA, for no fields.

        Raises:
            ProtocolError: If ``data`` holds a field.

        """
        if data:
            raise ProtocolError(f'{self.alias}: no RDATA constructor for type {rr_type!r}; give its octets')
        return b''

    def _make_rdata_a(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                      offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``A`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``address``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        return parse_ip_address(data.get('address', '0.0.0.0'),  # nosec: B104
                                f'{self.alias}: A record address', version=4).packed

    def _make_rdata_ns(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                       offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make an ``NS`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``nsdname``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        return self._make_dns_name(data.get('nsdname', '.'), offset=offset, table=table)

    def _make_rdata_cname(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                          offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make a ``CNAME`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``cname``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        return self._make_dns_name(data.get('cname', '.'), offset=offset, table=table)

    def _make_rdata_soa(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                        offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make an ``SOA`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``mname``, ``rname``, ``serial``,
                ``refresh``, ``retry``, ``expire`` and ``minimum``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        mname = self._make_dns_name(data.get('mname', '.'), offset=offset, table=table)
        rname = self._make_dns_name(data.get('rname', '.'), offset=offset + len(mname), table=table)
        return mname + rname + b''.join(
            self._make_pack(self._make_uint(data.get(key, 0), bits=32, name=f'SOA {key}'), size=4)
            for key in ('serial', 'refresh', 'retry', 'expire', 'minimum'))

    def _make_rdata_ptr(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                        offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make a ``PTR`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``ptrdname``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        return self._make_dns_name(data.get('ptrdname', '.'), offset=offset, table=table)

    def _make_rdata_mx(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                       offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make an ``MX`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``preference`` and ``exchange``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        preference = self._make_uint(data.get('preference', 0), bits=16, name='MX preference')
        return self._make_pack(preference, size=2) + self._make_dns_name(
            data.get('exchange', '.'), offset=offset + 2, table=table)

    def _make_rdata_txt(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                        offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make a ``TXT`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``strings``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        Raises:
            ProtocolError: If a string is not :obj:`bytes` of at most 255 octets.

        """
        out = bytearray()
        for string in data.get('strings', (b'',)):
            if not isinstance(string, (bytes, bytearray)) or len(string) > 255:
                raise ProtocolError(f'{self.alias}: invalid TXT character-string: {string!r}')
            out += self._make_vector(bytes(string), size=1)
        return bytes(out)

    def _make_rdata_aaaa(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                         offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``AAAA`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``address``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        return parse_ip_address(data.get('address', '::'), f'{self.alias}: AAAA record address', version=6).packed

    def _make_rdata_srv(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                        offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``SRV`` RDATA; its target is never compressed (:rfc:`2782`).

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``priority``, ``weight``, ``port`` and
                ``target``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        """
        head = b''.join(self._make_pack(self._make_uint(data.get(key, 0), bits=16, name=f'SRV {key}'), size=2)
                        for key in ('priority', 'weight', 'port'))
        return head + self._make_dns_name(data.get('target', '.'), offset=offset + 6, table=None)

    def _make_rdata_caa(self, rr_type: 'Enum_RRType', data: 'Mapping[str, Any]', *,  # pylint: disable=unused-argument
                        offset: 'int', table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':  # pylint: disable=unused-argument
        """Make a ``CAA`` RDATA.

        Args:
            rr_type: RR type.
            data: RDATA fields, i.e. ``flags``, ``tag`` and ``value``; the
                Issuer Critical flag is the high bit of ``flags``.
            offset: Offset of the RDATA in the message.
            table: Names written so far, when compressing.

        Returns:
            RDATA octets.

        Raises:
            ProtocolError: If ``tag`` is not :obj:`bytes` of 1 to 255 octets,
                or ``value`` is not :obj:`bytes`.

        """
        flags = self._make_uint(data.get('flags', 0), bits=8, name='CAA flags')
        tag, value = data.get('tag', b'issue'), data.get('value', b'')
        if not isinstance(tag, (bytes, bytearray)) or not 1 <= len(tag) <= 255:
            raise ProtocolError(f'{self.alias}: invalid CAA tag: {tag!r}')
        if not isinstance(value, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid CAA value: {value!r}')
        return self._make_pack(flags, size=1) + self._make_vector(bytes(tag), size=1) + bytes(value)

    def _make_opt_unknown(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':
        """Make an EDNS(0) option with no constructor registered.

        Args:
            code: Option code.
            data: OPTION-DATA fields; none can be written.

        Returns:
            Empty OPTION-DATA, for no fields.

        Raises:
            ProtocolError: If ``data`` holds a field.

        """
        if data:
            raise ProtocolError(f'{self.alias}: no OPTION-DATA constructor for option {code!r}; give its octets')
        return b''

    def _make_opt_client_subnet(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``edns-client-subnet`` option.

        Args:
            code: Option code.
            data: OPTION-DATA fields, i.e. ``family``, ``source_prefix``,
                ``scope_prefix`` and ``address``.

        Returns:
            OPTION-DATA octets.

        Raises:
            ProtocolError: If ``address`` is not :obj:`bytes`.

        """
        address = data.get('address', b'')
        if not isinstance(address, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid client subnet address: {address!r}')
        return (self._make_pack(self._make_uint(data.get('family', 1), bits=16, name='client subnet family'), size=2)
                + self._make_pack(self._make_uint(data.get('source_prefix', 0), bits=8,
                                                  name='client subnet source prefix length'), size=1)
                + self._make_pack(self._make_uint(data.get('scope_prefix', 0), bits=8,
                                                  name='client subnet scope prefix length'), size=1)
                + bytes(address))

    def _make_opt_cookie(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Make a ``COOKIE`` option.

        Args:
            code: Option code.
            data: OPTION-DATA fields, i.e. ``client`` and ``server``.

        Returns:
            OPTION-DATA octets.

        Raises:
            ProtocolError: If ``client`` is not 8 octets, or ``server`` is
                neither empty nor of 8 to 32 octets.

        """
        client = self._make_octets(data.get('client', bytes(8)), size=8, name='client cookie')
        server = data.get('server', b'')
        if not isinstance(server, (bytes, bytearray)) or not (len(server) == 0 or 8 <= len(server) <= 32):
            raise ProtocolError(f'{self.alias}: invalid server cookie: {server!r}')
        return client + bytes(server)

    def _make_opt_tcp_keepalive(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``edns-tcp-keepalive`` option.

        Args:
            code: Option code.
            data: OPTION-DATA fields, i.e. ``timeout``, which :obj:`None` leaves out.

        Returns:
            OPTION-DATA octets.

        """
        timeout = data.get('timeout')
        if timeout is None:
            return b''
        return self._make_pack(self._make_uint(timeout, bits=16, name='keepalive timeout'), size=2)

    def _make_opt_extended_error(self, code: 'Enum_Option', data: 'Mapping[str, Any]') -> 'bytes':  # pylint: disable=unused-argument
        """Make an ``Extended DNS Error`` option.

        Args:
            code: Option code.
            data: OPTION-DATA fields, i.e. ``info_code`` and ``extra_text``.

        Returns:
            OPTION-DATA octets.

        Raises:
            ProtocolError: If ``extra_text`` is not :obj:`bytes`.

        """
        text = data.get('extra_text', b'')
        if not isinstance(text, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid extended error EXTRA-TEXT: {text!r}')
        return self._make_pack(self._make_uint(data.get('info_code', 0), bits=16,
                                               name='extended error INFO-CODE'), size=2) + bytes(text)

    def _read_dns_name(self, message: 'bytes', pos: 'int', *,
                       limit: 'Optional[int]' = None) -> 'tuple[Data_Name, int]':
        """Read a domain name, following its compression pointers.

        Args:
            message: The message, from its header on.
            pos: Offset of the name in ``message``.
            limit: Offset the name has to end by, if any.

        Returns:
            The name, and the offset just past it.

        Raises:
            ProtocolError: As :func:`~pcapkit.protocols.application.dns.schema.read_name`
                raises it, or if the name ends past ``limit``.

        """
        labels, literal, pointer, end = read_name(message, pos, alias=self.alias)
        if limit is not None and end > limit:
            raise ProtocolError(f'{self.alias}: invalid format: domain name runs past the record data')
        return Data_Name(name=name_to_text(labels), labels=labels, literal=literal, pointer=pointer), end

    def _read_rdata_name(self, data: 'bytes', message: 'bytes', offset: 'int', *,
                         skip: 'int' = 0) -> 'Data_Name':
        """Read the domain name that ends an RDATA.

        Args:
            data: RDATA octets.
            message: The message, from its header on.
            offset: Offset of ``data`` in ``message``.
            skip: Octets of ``data`` before the name.

        Returns:
            The name.

        Raises:
            ProtocolError: If the name does not end where ``data`` does.

        """
        if len(data) <= skip:
            raise ProtocolError(f'{self.alias}: invalid format: record data ends before its domain name')
        name, end = self._read_dns_name(message, offset + skip, limit=offset + len(data))
        if end != offset + len(data):
            raise ProtocolError(f'{self.alias}: invalid format: record data carries excess octets')
        return name

    def _make_dns_name(self, name: 'NameLike', *, offset: 'int',
                       table: 'Optional[dict[tuple[bytes, ...], int]]') -> 'bytes':
        """Make a domain name.

        Args:
            name: A :class:`~pcapkit.protocols.application.dns.data.Name`, or
                its :obj:`dict` form, written with the compression it records;
                or its labels, or its presentation form, compressed against
                ``table`` if given.
            offset: Offset of the name in the message.
            table: Names written so far, when compressing; the suffixes this
                name writes in full are added to it.

        Returns:
            The name's octets.

        Raises:
            ProtocolError: If ``name`` is none of those, or is malformed.

        """
        if isinstance(name, collections.abc.Mapping):
            labels = tuple(name.get('labels', ()))
            literal, pointer = name.get('literal'), name.get('pointer')
            if table is not None:
                record_name(labels, len(labels) if literal is None else literal, table, offset)
        else:
            if isinstance(name, str):
                labels = text_to_labels(name, alias=self.alias)
            elif isinstance(name, (list, tuple)):
                labels = tuple(name)
            else:
                raise ProtocolError(f'{self.alias}: invalid domain name: {name!r}')
            if table is None:
                literal, pointer = None, None
            else:
                literal, pointer = compress_name(labels, table, offset)
        return make_name(labels, literal=literal, pointer=pointer, alias=self.alias)

    def _read_dns_opt(self, name: 'Data_Name', udp_payload_size: 'int', ttl: 'int',
                      rdata: 'bytes') -> 'Data_OPT':
        """Read the OPT pseudo-record of EDNS(0).

        Structure of the OPT record's TTL field [:rfc:`6891#section-6.1.3`]:

        .. code-block:: text

                       +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         0: |         EXTENDED-RCODE        |            VERSION            |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         2: | DO|                           Z                               |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

        Args:
            name: Owner name.
            udp_payload_size: The CLASS field.
            ttl: The TTL field.
            rdata: RDATA octets, i.e. the options.

        Returns:
            The record; its options are the raw RDATA where their framing
            does not decode.

        """
        try:
            with CaughtByCaller(ProtocolError):
                options = self._read_dns_options(rdata)  # type: tuple[Data_Option, ...] | bytes
        except ProtocolError:
            options = rdata
        return Data_OPT(
            name=name,
            type=cast('Enum_RRType', Enum_RRType.OPT),
            udp_payload_size=udp_payload_size,
            extended_rcode=ttl >> 24,
            version=(ttl >> 16) & 0xFF,
            do=bool(ttl & 0x8000),
            z=ttl & 0x7FFF,
            rdlength=len(rdata),
            options=options,
        )

    def _make_dns_opt(self, record: 'Mapping[str, Any]') -> 'tuple[int, int, bytes]':
        """Make the CLASS, TTL and RDATA fields of the OPT pseudo-record.

        Args:
            record: The fields of :class:`~pcapkit.protocols.application.dns.data.OPT`.

        Returns:
            The CLASS and TTL values, and the RDATA octets.

        """
        udp_payload_size = self._make_uint(record.get('udp_payload_size', 4096), bits=16, name='UDP payload size')
        ttl = ((self._make_uint(record.get('extended_rcode', 0), bits=8, name='extended RCODE') << 24)
               | (self._make_uint(record.get('version', 0), bits=8, name='EDNS version') << 16)
               | (self._make_uint(record.get('do', False), bits=1, name='DO bit') << 15)
               | self._make_uint(record.get('z', 0), bits=15, name='OPT Z bits'))
        options = record.get('options', ())
        if isinstance(options, (bytes, bytearray)):
            return udp_payload_size, ttl, bytes(options)
        return udp_payload_size, ttl, self._make_dns_options(options)

    def _read_dns_options(self, data: 'bytes') -> 'tuple[Data_Option, ...]':
        """Read the options of the OPT pseudo-record.

        Structure of an option [:rfc:`6891#section-6.1.2`]:

        .. code-block:: text

                       +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         0: |                          OPTION-CODE                          |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         2: |                         OPTION-LENGTH                         |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
         4: |                                                               |
            /                          OPTION-DATA                          /
            /                                                               /
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

        Each OPTION-DATA is read by the parser :attr:`__option__` registers for
        its code, and kept as raw octets where that parser rejects it.

        Args:
            data: The OPT record's RDATA.

        Returns:
            The options, in order.

        Raises:
            ProtocolError: If an option's header or data runs past ``data``.

        """
        options = []  # type: list[Data_Option]
        pos = 0
        while pos < len(data):
            code = Enum_Option.get(self._read_uint(data, pos, size=2, what='option code'))
            value, pos = self._read_vector(data, pos + 2, size=2, what='option data')
            meth = self._lookup_registry(self.__option__, code)
            if isinstance(meth, str):
                parser = cast('OptionParser', getattr(self, f'_read_opt_{meth}', self._read_opt_unknown))
            else:
                parser = meth[0]
            try:
                with CaughtByCaller(ProtocolError):
                    body = parser(code, value)  # type: Data_OptionData | bytes
            except ProtocolError:
                body = value
            options.append(Data_Option(code=code, length=len(value), data=body))
        return tuple(options)

    def _make_dns_options(self, options: 'Iterable[Mapping[str, Any]]') -> 'bytes':
        """Make the options of the OPT pseudo-record.

        Args:
            options: Each option's ``code``, ``length`` and ``data``, as
                :class:`~pcapkit.protocols.application.dns.data.Option` holds
                them; ``data`` is raw octets or a mapping of the fields of the
                code's data model, and ``length`` is computed when not given.

        Returns:
            The options' octets.

        """
        out = bytearray()
        for option in options:
            if not isinstance(option, collections.abc.Mapping):
                raise ProtocolError(f'{self.alias}: invalid EDNS(0) option: {option!r}')
            code = self._make_index(option.get('code', Enum_Option.Padding), Enum_Option, bits=16,
                                    name='option code')
            value = option.get('data')
            if isinstance(value, (bytes, bytearray)):
                body = bytes(value)
            else:
                meth = self._lookup_registry(self.__option__, code)
                if isinstance(meth, str):
                    maker = cast('OptionConstructor', getattr(self, f'_make_opt_{meth}', self._make_opt_unknown))
                else:
                    maker = meth[1]
                body = maker(code, {} if value is None else value)
            length = option.get('length')
            size = len(body) if length is None else self._make_uint(length, bits=16, name='option length')
            out += self._make_pack(int(code), size=2) + self._make_pack(size, size=2) + body
        return bytes(out)

    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[override]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor: a further whole message, or the rest undissected.

        Over TCP, a segment may carry several messages, each behind its
        length field. So the ``-1`` remainder after a framed message is
        dissected as this class when :func:`_opens_whole_message` finds a
        whole message opening it, and is otherwise kept as
        :meth:`Application._import_next_layer
        <pcapkit.protocols.application.application.Application._import_next_layer>`
        keeps it.

        Arguments:
            proto: next layer protocol index; only the ``-1`` sentinel
                (the rest) is accepted
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of this class for a further message, or as
            :meth:`Application._import_next_layer
            <pcapkit.protocols.application.application.Application._import_next_layer>`
            returns otherwise.

        """
        if (proto == -1 and not self._sigterm and self.__header__.length is not None
                and _opens_whole_message(self._get_payload()[:length])):
            return self._import_next_message(proto, length, packet=packet)  # type: ignore[misc,call-arg]
        return super()._import_next_layer(proto, length, packet=packet)

    @beholder  # type: ignore[arg-type]
    def _import_next_message(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                             packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import the further message :meth:`_import_next_layer` found.

        Arguments:
            proto: next layer protocol index, the ``-1`` sentinel
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of this class, or of :class:`~pcapkit.protocols.misc.raw.protocol.Raw`
            when :func:`~pcapkit.corekit.decorators.beholder` replaces a message
            that fails to parse.

        """
        file_ = self._get_payload()
        return self._parse_next_layer(type(self), file_, len(file_) if length is None else length,
                                      alias=proto, packet=packet, layer=self._exlayer,
                                      protocol=self._exproto, context=self._exctx, framed=True)

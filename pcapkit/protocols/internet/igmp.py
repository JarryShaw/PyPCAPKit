# -*- coding: utf-8 -*-
"""IGMP - Internet Group Management Protocol
================================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` contains
:class:`~pcapkit.protocols.internet.igmp.IGMP` only,
which implements the extractor for Internet Group
Management Protocol (IGMP) [*]_ versions 1, 2 and 3.

IGMPv1 (:rfc:`1112`) and IGMPv2 (:rfc:`2236`) share one 8-octet message
shape:

======= ========= ============================= ===================================
Octets      Bits        Name                          Description
======= ========= ============================= ===================================
  0           0   ``igmp.type``                 Type
  1           8   ``igmp.body.max_resp_code``    Max Response Code
  2          16   ``igmp.body.checksum``         Checksum
  4          32   ``igmp.body.group``            Group Address
======= ========= ============================= ===================================

An IGMPv3 (:rfc:`3376`) Membership Query (type ``0x11``, shared with v1/v2)
reuses that 8-octet layout and, when at least 12 octets long overall, appends
a source-list extension:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  8          64   ``igmp.body.ext.flags``             Resv / S Flag / QRV
  9          72   ``igmp.body.ext.qqic``              Querier's Query Interval Code
  10         80   ``igmp.body.ext.num_sources``       Number of Sources (N)
  12         96   ``igmp.body.ext.sources``           Source Address [1..N]
======= ========= ================================== ===================================

An IGMPv3 Membership Report (type ``0x22``) has an unrelated, materially
different shape of its own:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmp.type``                       Type
  1           8   ``igmp.body.reserved_1``             Reserved
  2          16   ``igmp.body.checksum``               Checksum
  4          32   ``igmp.body.reserved_2``             Reserved
  6          48   ``igmp.body.num_group_records``      Number of Group Records (M)
  8          64   ``igmp.body.records``                Group Record [1..M]
======= ========= ================================== ===================================

.. [*] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol

.. versionadded:: 1.6.0

   IGMPv1 (:rfc:`1112`), IGMPv2 (:rfc:`2236`) and IGMPv3 (:rfc:`3376`), as an
   :class:`Internet <pcapkit.protocols.internet.internet.Internet>`
   subclass per :discussion:`251` (:issue:`2439`, :issue:`2448`).

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.igmp import IGMP as Data_IGMP
from pcapkit.protocols.data.internet.igmp import GroupAddressMessage as Data_GroupAddressMessage
from pcapkit.protocols.data.internet.igmp import GroupRecord as Data_GroupRecord
from pcapkit.protocols.data.internet.igmp import \
    Version3MembershipReport as Data_Version3MembershipReport
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.igmp import IGMP as Schema_IGMP
from pcapkit.protocols.schema.internet.igmp import GroupBody as Schema_GroupBody
from pcapkit.protocols.schema.internet.igmp import GroupRecord as Schema_GroupRecord
from pcapkit.protocols.schema.internet.igmp import QueryExtension as Schema_QueryExtension
from pcapkit.protocols.schema.internet.igmp import ReportBody as Schema_ReportBody
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, Iterable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IGMP']

#: Octets in the fixed header every IGMP message starts with: the type, and
#: the 7 octets after it (:rfc:`2236#section-2`, :rfc:`3376#section-4`).
#: Reported as the length even when fewer octets were captured, so that
#: :meth:`Protocol._parse_next_layer
#: <pcapkit.protocols.protocol.Protocol._parse_next_layer>` sees a cut header
#: as short and falls back to :class:`~pcapkit.protocols.misc.raw.Raw`.
_FIXED_HEADER_LENGTH = 8

#: The four message types IGMPv1 (:rfc:`1112#appendix-I`) and IGMPv2
#: (:rfc:`2236#section-2.1`) define, plus the IGMPv3 Membership Query, which
#: reuses the Membership Query type (:rfc:`3376#section-4`). Every one of
#: these is a :class:`~pcapkit.protocols.schema.internet.igmp.GroupBody`.
_GROUP_BODY_TYPES = (
    Enum_Type.IGMP_Membership_Query,
    Enum_Type.IGMPv1_Membership_Report,
    Enum_Type.IGMPv2_Membership_Report,
    Enum_Type.IGMPv2_Leave_Group,
)


def _decode_resp_code(code: 'int') -> 'int':
    """Decode a Max Resp Code/QQIC octet into its real value.

    Per :rfc:`3376#section-4.1.1` (:attr:`~pcapkit.protocols.data.internet.igmp.GroupAddressMessage.max_resp_time`)
    and :rfc:`3376#section-4.1.7` (:attr:`~pcapkit.protocols.data.internet.igmp.GroupAddressMessage.qqi`)
    alike:

    * if ``code < 128``, the value is ``code`` itself;
    * otherwise ``code`` is a floating-point value ``1 exp(3) mant(4)``, and
      the value is ``(mant | 0x10) << (exp + 3)``.

    Args:
        code: the raw octet.

    Returns:
        The decoded value.

    """
    if code < 128:
        return code
    exp = (code >> 4) & 0x07
    mant = code & 0x0F
    return (mant | 0x10) << (exp + 3)


def _encode_resp_code(value: 'int') -> 'int':
    """Encode a value into a Max Resp Code/QQIC octet.

    The reverse of :func:`_decode_resp_code`. A value below 128 round-trips
    exactly. At or above it, this picks the smallest exponent whose mantissa
    fits 4 bits, which round-trips exactly for any value that formula can
    represent and otherwise floors to the nearest one it can (the same
    lossy-above-127 trade-off :rfc:`3376#section-4.1.1` itself makes) --
    mirroring how :meth:`HIP._make_puzzle_lifetime
    <pcapkit.protocols.internet.hip.HIP._make_puzzle_lifetime>` encodes its
    own exponential field.

    Args:
        value: the value to encode, in the same units as :func:`_decode_resp_code`
            returns.

    Returns:
        The raw octet.

    """
    if value < 0:
        raise ProtocolError(f'IGMP: invalid Max Resp Time/QQI value: {value!r}')
    if value < 128:
        return value

    exp = 0
    mant_full = value >> 3
    while mant_full > 31 and exp < 7:
        exp += 1
        mant_full = value >> (exp + 3)
    mant_full = min(mant_full, 31)

    mant = mant_full & 0x0F
    return 0x80 | (exp << 4) | mant


class IGMP(Internet[Data_IGMP, Schema_IGMP],
           schema=Schema_IGMP, data=Data_IGMP):
    """This class implements Internet Group Management Protocol.

    IGMPv1 and IGMPv2 share one 8-octet message shape. IGMPv3 reuses it for
    its Membership Query, adding a source-list extension when at least 12
    octets are present (:rfc:`3376#section-7.1`), and defines its own
    group-record shape for its Membership Report.
    :attr:`~pcapkit.const.igmp.type.Type` carries every type the three
    versions define; :func:`~pcapkit.protocols.schema.internet.igmp.igmp_body_selector`
    picks the shape (:issue:`2439`, :issue:`2448`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Group Management Protocol"]':
        """Name of corresponding protocol."""
        return 'Internet Group Management Protocol'

    @property
    def alias(self) -> 'Literal["IGMP"]':
        """Acronym of corresponding protocol."""
        return 'IGMP'

    @property
    def length(self) -> 'int':
        """Header length of current protocol.

        Every message starts with an 8-octet header. An IGMPv3 message's
        length varies with its body (a Query may carry the source-list
        extension, and a Report's group-record list has no fixed size), so
        it is taken during :meth:`read` from the octets consumed, but never
        less than 8: a shorter capture reports 8, so the enclosing layer
        sees the cut header as short.

        """
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IGMP':
        """Read Internet Group Management Protocol.

        Structure of an IGMPv1/v2 message, and of an IGMPv3 Membership
        Query's fixed portion [:rfc:`1112#appendix-I`, :rfc:`2236#section-2`,
        :rfc:`3376#section-4.1`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Type     | Max Resp Code |           Checksum           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Group Address                        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If :attr:`schema.type <pcapkit.protocols.schema.internet.igmp.IGMP.type>`
                is not one of the message types IGMP defines -- see
                :func:`~pcapkit.protocols.schema.internet.igmp.igmp_body_selector`,
                which is where this is actually raised, from the schema
                unpack rather than from here.

        """
        if length is None:
            length = len(self)
        schema = self.__header__
        body = schema.body

        if isinstance(body, Schema_GroupBody):
            igmp, trailing = self._read_group_address_message(schema.type, body)  # type: Data_IGMP, bytes
        elif isinstance(body, Schema_ReportBody):
            igmp, trailing = self._read_version3_membership_report(schema.type, body)
        else:  # pragma: no cover
            raise ProtocolError(f'IGMP: unsupported message type: {schema.type!r}')

        return self._decode_next_layer(igmp, None, len(trailing))

    def _read_group_address_message(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin
                                     body: 'Schema_GroupBody') -> 'tuple[Data_GroupAddressMessage, bytes]':
        """Build the data model for a :class:`~pcapkit.protocols.schema.internet.igmp.GroupBody`-shaped message.

        Args:
            type: Message type.
            body: Parsed message body.

        Returns:
            The data model, and the trailing octets kept as payload.

        """
        ext = body.ext
        resv = None  # type: Optional[int]
        s_flag = None  # type: Optional[bool]
        qrv = None  # type: Optional[int]
        qqic = None  # type: Optional[int]
        qqi = None  # type: Optional[int]
        sources = None  # type: Optional[tuple[IPv4Address, ...]]
        # NOTE: The floating-point Max Resp Code applies only to an IGMPv3 Query
        # with the extension (:rfc:`3376#section-4.1.1`); an 8-octet code is literal.
        max_resp_time = body.max_resp_code
        if ext is not None:
            resv = ext.flags['resv']
            s_flag = bool(ext.flags['s_flag'])
            qrv = ext.flags['qrv']
            qqic = ext.qqic
            qqi = _decode_resp_code(qqic)
            sources = tuple(ext.sources)
            max_resp_time = _decode_resp_code(body.max_resp_code)

        trailing = body.get_payload()
        igmp = Data_GroupAddressMessage(
            type=type,
            length=max(_FIXED_HEADER_LENGTH, 1 + len(body) - len(trailing)),
            max_resp_code=body.max_resp_code,
            max_resp_time=max_resp_time,
            checksum=body.checksum,
            group=body.group,
            resv=resv,
            s_flag=s_flag,
            qrv=qrv,
            qqic=qqic,
            qqi=qqi,
            sources=sources,
        )
        return igmp, trailing

    def _read_version3_membership_report(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin
                                         body: 'Schema_ReportBody') -> 'tuple[Data_Version3MembershipReport, bytes]':
        """Build the data model for an IGMPv3 Membership Report.

        Args:
            type: Message type.
            body: Parsed message body.

        Returns:
            The data model, and the trailing octets kept as payload.

        """
        records = tuple(
            Data_GroupRecord(
                record_type=record.record_type,
                aux_data_len=record.aux_data_len,
                num_sources=record.num_sources,
                multicast_address=record.multicast_address,
                sources=tuple(record.sources),
                aux_data=record.aux_data,
            ) for record in body.records
        )

        igmp = Data_Version3MembershipReport(
            type=type,
            length=max(_FIXED_HEADER_LENGTH, 1 + len(body) - len(body.payload)),
            reserved_1=body.reserved_1,
            checksum=body.checksum,
            reserved_2=body.reserved_2,
            num_group_records=body.num_group_records,
            records=records,
        )
        return igmp, body.payload

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.IGMP_Membership_Query,  # pylint: disable=redefined-builtin
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             max_resp_code: 'Optional[int]' = None,
             max_resp_time: 'int' = 0,
             checksum: 'bytes' = b'\x00\x00',
             group: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             resv: 'Optional[int]' = None,
             s_flag: 'Optional[bool]' = None,
             qrv: 'Optional[int]' = None,
             qqic: 'Optional[int]' = None,
             qqi: 'Optional[int]' = None,
             sources: 'Optional[Iterable[IPv4Address | str | bytes | int]]' = None,
             reserved_1: 'int' = 0,
             reserved_2: 'bytes' = b'\x00\x00',
             records: 'Optional[Iterable[dict[str, Any]]]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IGMP':
        """Make (construct) packet data.

        Args:
            type: Message type.
            type_default: Default value of message type.
            type_namespace: Namespace of message type.
            type_reversed: If the namespace is reversed.
            max_resp_code: Max response code, as transmitted on the wire. When
                not given, derived from ``max_resp_time``: floating-point
                encoded via :func:`_encode_resp_code` only for an IGMPv3 Query
                with the extension; literal otherwise (8-octet messages).
            max_resp_time: Max response time, in units of 1/10 second: an
                :obj:`int` from 0 to 255 (not a :obj:`bool`), else
                :exc:`ProtocolError`. Written literally, except on an IGMPv3
                Query, where it is floating-point encoded; ignored when
                ``max_resp_code`` is given.
            checksum: Checksum; the one's complement of the one's complement
                sum of the message, with this field taken as zero and no
                pseudo-header -- the message itself for IGMPv1
                (:rfc:`1112#appendix-I`), or the whole IP payload for
                IGMPv2/v3 (:rfc:`2236#section-2.3`, :rfc:`3376#section-4.1.2`).
            group: Group address; ``0.0.0.0`` for a General Query.
            resv: The 4 reserved high-order bits of the flags octet
                (:rfc:`3376#section-4.1.4`); ``0`` on a standards-conformant
                sender. See ``sources`` for when the IGMPv3 source-list
                extension is actually written.
            s_flag: Suppress Router-Side Processing flag
                (:rfc:`3376#section-4.1.5`). Only meaningful when ``type``
                is an IGMPv3 Query; see ``sources``.
            qrv: Querier's Robustness Variable (:rfc:`3376#section-4.1.6`);
                see ``s_flag``.
            qqic: Querier's Query Interval Code, as transmitted on the wire;
                derived from ``qqi`` via :func:`_encode_resp_code` when not
                given; see ``s_flag`` and ``sources``.
            qqi: Querier's Query Interval, in seconds; ignored when ``qqic``
                is given; see ``s_flag`` and ``sources``.
            sources: Source addresses being queried
                (:rfc:`3376#section-4.1.9`). The source-list extension is
                written only if ``type`` is an IGMPv3 Query and one of
                ``resv``, ``s_flag``, ``qrv``, ``qqic``, ``qqi`` or ``sources``
                is given. All six default to :data:`None`, so leaving them
                unset builds a plain 8-octet message. Pass ``sources=[]`` to
                force a zero-sourced Query.
            reserved_1: The reserved octet following ``type``
                (:rfc:`3376#section-4.2.1`); only read for an IGMPv3
                Membership Report.
            reserved_2: The reserved 16 bits before the group-record count
                (:rfc:`3376#section-4.2.1`); see ``reserved_1``.
            records: Group records (:rfc:`3376#section-4.2.4`), each either
                a :class:`~pcapkit.protocols.data.internet.igmp.GroupRecord`
                or a :obj:`dict` of the keyword arguments
                :meth:`_make_group_record` takes; only meaningful, and only
                read, when ``type`` is an IGMPv3 Membership Report.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``max_resp_time`` is not an :obj:`int` from 0
                to 255, or ``type`` is not one IGMP defines.

        """
        type_value = self._make_index(type, type_default, namespace=type_namespace,
                                      reversed=type_reversed, pack=False)
        # NOTE: A bool is an int, so it is refused explicitly; a float is refused
        # as not an int.
        if isinstance(max_resp_time, bool) or not isinstance(max_resp_time, int) \
                or not 0 <= max_resp_time <= 255:
            raise ProtocolError(f'{self.alias}: invalid max_resp_time: {max_resp_time!r}')

        if type_value == Enum_Type.IGMPv3_Membership_Report:
            record_list = [] if records is None else [
                self._make_group_record(**record) if isinstance(record, dict) else
                self._make_group_record(
                    record_type=record.record_type, aux_data_len=record.aux_data_len,
                    num_sources=record.num_sources, multicast_address=record.multicast_address,
                    sources=record.sources, aux_data=record.aux_data,
                ) for record in records
            ]
            return Schema_IGMP(
                type=type_value,
                body=Schema_ReportBody(
                    reserved_1=reserved_1,
                    checksum=checksum,
                    reserved_2=reserved_2,
                    num_group_records=len(record_list),
                    records=record_list,
                    payload=payload,
                ),
            )

        if type_value in _GROUP_BODY_TYPES:
            ext = None  # type: Optional[Schema_QueryExtension]
            if type_value == Enum_Type.IGMP_Membership_Query and (
                    resv is not None or s_flag is not None or qrv is not None
                    or qqic is not None or qqi is not None or sources is not None):
                if qqic is None:
                    qqic = _encode_resp_code(0 if qqi is None else qqi)
                source_list = [] if sources is None else list(sources)
                ext = Schema_QueryExtension(
                    flags={'resv': 0 if resv is None else resv, 's_flag': int(bool(s_flag)),
                           'qrv': 0 if qrv is None else qrv},
                    qqic=qqic,
                    num_sources=len(source_list),
                    sources=source_list,
                    payload=b'',
                )

            if max_resp_code is None:
                # The floating-point code is for an IGMPv3 Query only; a
                # plain 8-octet message carries the literal value.
                max_resp_code = max_resp_time if ext is None else _encode_resp_code(max_resp_time)

            return Schema_IGMP(
                type=type_value,
                body=Schema_GroupBody(
                    max_resp_code=max_resp_code,
                    checksum=checksum,
                    group=group,
                    ext=ext,
                    payload=payload,
                ),
            )

        raise ProtocolError(f'IGMP: unsupported message type: {type_value!r}')

    @staticmethod
    def _make_group_record(record: 'Optional[Data_GroupRecord]' = None, *,
                           record_type: 'Enum_RecordType | int' = Enum_RecordType.MODE_IS_INCLUDE,
                           aux_data_len: 'Optional[int]' = None,
                           num_sources: 'Optional[int]' = None,
                           multicast_address: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
                           sources: 'Optional[Iterable[IPv4Address | str | bytes | int]]' = None,
                           aux_data: 'bytes' = b'',
                           **kwargs: 'Any') -> 'Schema_GroupRecord':  # pylint: disable=unused-argument
        """Make an IGMPv3 group record (:rfc:`3376#section-4.2.4`).

        Args:
            record: An already-built group record, taking precedence over
                the keyword arguments below (mirrors
                :meth:`HIP._make_param_locator_set
                <pcapkit.protocols.internet.hip.HIP._make_param_locator_set>`'s
                ``param``/keyword split).
            record_type: Record type.
            aux_data_len: Auxiliary data length, in 32-bit words; derived
                from ``aux_data`` when not given.
            num_sources: Number of source addresses; derived from
                ``sources`` when not given.
            multicast_address: Multicast address.
            sources: Source addresses.
            aux_data: Auxiliary data; :rfc:`3376#section-4.2.10` requires an
                IGMPv3 sender to leave this empty.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Group record schema.

        """
        if record is not None:
            return Schema_GroupRecord(
                record_type=record.record_type,
                aux_data_len=record.aux_data_len,
                num_sources=record.num_sources,
                multicast_address=record.multicast_address,
                sources=list(record.sources),
                aux_data=record.aux_data,
            )

        source_list = [] if sources is None else list(sources)
        return Schema_GroupRecord(
            record_type=record_type,
            aux_data_len=len(aux_data) // 4 if aux_data_len is None else aux_data_len,
            num_sources=len(source_list) if num_sources is None else num_sources,
            multicast_address=multicast_address,
            sources=source_list,
            aux_data=aux_data,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object.

        Every IGMP message is at least 8 octets; this is a hint for the
        extractor's buffering, not :attr:`length` itself, which varies by
        message (see :attr:`length`).

        """
        return 8

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IGMP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IGMP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        Note:
            Dispatches on ``data.type`` rather than on
            :func:`isinstance(data, Data_Version3MembershipReport) <isinstance>`,
            so that a hand-built :obj:`dict` carrying the right ``type`` but
            not actually one of the two concrete data classes -- as a test
            double legitimately might -- still rebuilds correctly, the same
            way :meth:`make` itself dispatches on the ``type`` it is given
            rather than requiring a particular input class.

        """
        if data.type == Enum_Type.IGMPv3_Membership_Report:
            report = cast('Data_Version3MembershipReport', data)
            return {
                'type': report.type,
                'reserved_1': report.reserved_1,
                'checksum': report.checksum,
                'reserved_2': report.reserved_2,
                'records': report.records,
                'payload': cls._make_payload(data),
            }

        message = cast('Data_GroupAddressMessage', data)
        return {
            'type': message.type,
            'max_resp_code': message.max_resp_code,
            'checksum': message.checksum,
            'group': message.group,
            'resv': message.resv,
            's_flag': message.s_flag,
            'qrv': message.qrv,
            'qqic': message.qqic,
            'sources': message.sources,
            'payload': cls._make_payload(data),
        }

# -*- coding: utf-8 -*-
"""IGMPv3 - Internet Group Management Protocol version 3
==============================================================

.. module:: pcapkit.protocols.internet.igmpv3

:mod:`pcapkit.protocols.internet.igmpv3` contains
:class:`~pcapkit.protocols.internet.igmpv3.IGMPv3`, which implements an
extractor for Internet Group Management Protocol version 3 (IGMPv3)
[:rfc:`3376`]. Unlike IGMPv1/v2, IGMPv3 defines two message shapes of its
own, both handled by this one class:

An IGMPv3 Membership Query (type ``0x11``, shared with v1/v2) reuses the
8-octet layout IGMPv1/v2 share and, when at least 12 octets long overall,
appends a source-list extension:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmpv3.type``                    Type
  1           8   ``igmpv3.max_resp_code``           Max Response Code
  2          16   ``igmpv3.checksum``                Checksum
  4          32   ``igmpv3.group``                   Group Address
  8          64   ``igmpv3.resv``                    Reserved (Resv)
  8          68   ``igmpv3.s_flag``                  Suppress Router-Side Processing (S)
  8          69   ``igmpv3.qrv``                     Querier's Robustness Variable (QRV)
  9          72   ``igmpv3.qqic``                    Querier's Query Interval Code
  10         80                                      Number of Sources (N)
  12         96   ``igmpv3.sources``                 Source Address [1..N]
======= ========= ================================== ===================================

An IGMPv3 Membership Report (type ``0x22``) has an unrelated, materially
different shape of its own:

======= ========= ================================== ===================================
Octets      Bits        Name                               Description
======= ========= ================================== ===================================
  0           0   ``igmpv3.type``                    Type
  1           8   ``igmpv3.reserved_1``              Reserved
  2          16   ``igmpv3.checksum``                Checksum
  4          32   ``igmpv3.reserved_2``              Reserved
  6          48   ``igmpv3.num_group_records``       Number of Group Records (M)
  8          64   ``igmpv3.records``                 Group Record [1..M]
======= ========= ================================== ===================================

:meth:`~pcapkit.protocols.internet.igmp.IGMP._classify` is what keeps an
IGMPv1/v2 message out of this class; :attr:`~pcapkit.protocols.internet.igmp.IGMP.version`
and :meth:`id` are this class's own.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.const.igmp.type import Type as Enum_Type
from pcapkit.protocols.data.internet.igmpv3 import GroupRecord as Data_GroupRecord
from pcapkit.protocols.data.internet.igmpv3 import IGMPv3 as Data_IGMPv3
from pcapkit.protocols.data.internet.igmpv3 import Query as Data_Query
from pcapkit.protocols.data.internet.igmpv3 import Report as Data_Report
from pcapkit.protocols.internet.igmp import IGMP as IGMPBase
from pcapkit.protocols.schema.internet.igmpv3 import GroupRecord as Schema_GroupRecord
from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3 as Schema_IGMPv3
from pcapkit.protocols.schema.internet.igmpv3 import Query as Schema_Query
from pcapkit.protocols.schema.internet.igmpv3 import QueryExtension as Schema_QueryExtension
from pcapkit.protocols.schema.internet.igmpv3 import Report as Schema_Report
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, Iterable, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IGMPv3']


def _decode_resp_code(code: 'int') -> 'int':
    """Decode a Max Resp Code/QQIC octet into its real value.

    Per :rfc:`3376#section-4.1.1` (:attr:`~pcapkit.protocols.data.internet.igmpv3.Query.max_resp_time`)
    and :rfc:`3376#section-4.1.7` (:attr:`~pcapkit.protocols.data.internet.igmpv3.Query.qqi`)
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
        raise ProtocolError(f'IGMPv3: invalid Max Resp Time/QQI value: {value!r}')
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


class IGMPv3(IGMPBase[Data_IGMPv3, Schema_IGMPv3],
             schema=Schema_IGMPv3, data=Data_IGMPv3):
    """This class implements Internet Group Management Protocol version 3.

    Unlike :class:`~pcapkit.protocols.internet.igmpv1.IGMPv1` and
    :class:`~pcapkit.protocols.internet.igmpv2.IGMPv2`, which share the base's
    own 8-octet schema and data model, IGMPv3's wire format differs
    materially by message -- a Query's source-list extension, a Report's
    group-record list -- so this class carries its own (:issue:`2439`,
    :issue:`2448`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def version(self) -> 'Literal[3]':
        """IGMP version this class reads: ``3``."""
        return 3

    @property
    def length(self) -> 'int':
        """Header length of current protocol.

        Every message starts with an 8-octet header. A Query may carry the
        source-list extension, and a Report's group-record list has no fixed
        size, so this is taken during :meth:`read` from the octets consumed
        (see :attr:`~pcapkit.protocols.data.internet.igmpv3.IGMPv3.length`)
        rather than returned as a constant, unlike the base's own
        :attr:`~pcapkit.protocols.internet.igmp.IGMP.length`.

        """
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["IGMPv3"]]':  # type: ignore[override]
        """Index ID of the protocol.

        :rfc:`3376` names the protocol ``IGMPv3``, carrying its own version.

        Returns:
            Index ID of the protocol.

        """
        return ('IGMPv3',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IGMPv3':
        """Read Internet Group Management Protocol version 3.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If :meth:`_classify` does not place the message in
                :attr:`version` 3 -- an IGMPv1/v2-shaped Query, or a type
                neither version of IGMP defines.

        """
        if length is None:
            length = len(self)
        schema = cast('Schema_IGMPv3', self.__header__)
        body = schema.body

        if isinstance(body, Schema_Query):
            if self._classify(schema.type, body.max_resp_code, length) != self.version:
                raise ProtocolError(f'{self.alias}: {schema.type!r} is not an {self.alias} '
                                    f'message ({length} octets)')

            # NOTE: The classify check above only accepts a Query of 12 or more
            # octets, which is exactly when ``query_extension_present`` parses
            # ``ext`` -- so it is never ``None`` here.
            ext = cast('Schema_QueryExtension', body.ext)
            resv = ext.flags['resv']
            s_flag = bool(ext.flags['s_flag'])
            qrv = ext.flags['qrv']
            qqic = ext.qqic
            qqi = _decode_resp_code(qqic)
            max_resp_time = _decode_resp_code(body.max_resp_code)
            sources = tuple(ext.sources)
            trailing = ext.get_payload()

            igmp = Data_Query(
                type=schema.type,
                length=1 + len(body) - len(trailing),
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
            )  # type: Data_IGMPv3
        elif isinstance(body, Schema_Report):
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
            trailing = body.payload
            igmp = Data_Report(
                type=schema.type,
                length=1 + len(body) - len(trailing),
                reserved_1=body.reserved_1,
                checksum=body.checksum,
                reserved_2=body.reserved_2,
                num_group_records=body.num_group_records,
                records=records,
            )
        else:  # pragma: no cover
            raise ProtocolError(f'{self.alias}: unsupported message type: {schema.type!r}')

        return self._decode_next_layer(igmp, None, len(trailing))

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.IGMP_Membership_Query,  # pylint: disable=redefined-builtin
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             max_resp_code: 'Optional[int]' = None,
             max_resp_time: 'int' = 0,
             checksum: 'bytes' = b'\x00\x00',
             group: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             resv: 'int' = 0,
             s_flag: 'bool' = False,
             qrv: 'int' = 0,
             qqic: 'Optional[int]' = None,
             qqi: 'Optional[int]' = None,
             sources: 'Optional[Iterable[IPv4Address | str | bytes | int]]' = None,
             reserved_1: 'int' = 0,
             reserved_2: 'bytes' = b'\x00\x00',
             records: 'Optional[Iterable[dict[str, Any] | Data_GroupRecord]]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IGMPv3':
        """Make (construct) packet data.

        Building a Query (the default) always writes the source-list
        extension: this class is specifically IGMPv3, unlike the base's own
        :meth:`~pcapkit.protocols.internet.igmp.IGMP.make`, which writes the
        extension only when asked, since there a plain 8-octet message is
        the more natural default.

        Args:
            type: Message type.
            type_default: Default value of message type.
            type_namespace: Namespace of message type.
            type_reversed: If the namespace is reversed.
            max_resp_code: Max response code, as transmitted on the wire. When
                not given, derived from ``max_resp_time`` via
                :func:`_encode_resp_code`; only meaningful for a Query.
            max_resp_time: Max response time, in units of 1/10 second: an
                :obj:`int` from 0 to 255 (not a :obj:`bool`), else
                :exc:`ProtocolError`. Ignored when ``max_resp_code`` is given.
            checksum: Checksum; the one's complement of the one's complement
                sum of the message, with this field taken as zero and no
                pseudo-header -- the whole IP payload (:rfc:`3376#section-4.1.2`,
                :rfc:`3376#section-4.2.2`).
            group: Group address; ``0.0.0.0`` for a General Query; only
                meaningful for a Query.
            resv: The 4 reserved high-order bits of the flags octet
                (:rfc:`3376#section-4.1.4`); ``0`` on a standards-conformant
                sender; only meaningful for a Query.
            s_flag: Suppress Router-Side Processing flag
                (:rfc:`3376#section-4.1.5`); only meaningful for a Query.
            qrv: Querier's Robustness Variable (:rfc:`3376#section-4.1.6`);
                only meaningful for a Query.
            qqic: Querier's Query Interval Code, as transmitted on the wire;
                derived from ``qqi`` via :func:`_encode_resp_code` when not
                given; only meaningful for a Query.
            qqi: Querier's Query Interval, in seconds; ignored when ``qqic``
                is given; only meaningful for a Query.
            sources: Source addresses being queried
                (:rfc:`3376#section-4.1.9`); only meaningful for a Query.
            reserved_1: The reserved octet following ``type``
                (:rfc:`3376#section-4.2.1`); only meaningful for a Report.
            reserved_2: The reserved 16 bits before the group-record count
                (:rfc:`3376#section-4.2.1`); only meaningful for a Report.
            records: Group records (:rfc:`3376#section-4.2.4`), each either
                a :class:`~pcapkit.protocols.data.internet.igmpv3.GroupRecord`
                or a :obj:`dict` of the keyword arguments
                :meth:`_make_group_record` takes; only meaningful for a
                Report.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``max_resp_time`` is not an :obj:`int` from 0
                to 255, or ``type`` is neither a Query nor a Report.

        """
        type_value = self._make_index(type, type_default, namespace=type_namespace,
                                      reversed=type_reversed, pack=False)
        if isinstance(max_resp_time, bool) or not isinstance(max_resp_time, int) \
                or not 0 <= max_resp_time <= 255:
            raise ProtocolError(f'{self.alias}: invalid max_resp_time: {max_resp_time!r}')

        if type_value == Enum_Type.IGMPv3_Membership_Report:
            record_list = [] if records is None else [
                self._make_group_record(record) if not isinstance(record, dict) else
                self._make_group_record(**record) for record in records
            ]
            return Schema_IGMPv3(
                type=type_value,
                body=Schema_Report(
                    reserved_1=reserved_1,
                    checksum=checksum,
                    reserved_2=reserved_2,
                    num_group_records=len(record_list),
                    records=record_list,
                    payload=payload,
                ),
            )  # type: ignore[return-value]

        if type_value == Enum_Type.IGMP_Membership_Query:
            if qqic is None:
                qqic = _encode_resp_code(0 if qqi is None else qqi)
            source_list = [] if sources is None else list(sources)
            ext = Schema_QueryExtension(
                flags={'resv': resv, 's_flag': int(bool(s_flag)), 'qrv': qrv},
                qqic=qqic,
                num_sources=len(source_list),
                sources=source_list,
                payload=b'',
            )

            if max_resp_code is None:
                max_resp_code = _encode_resp_code(max_resp_time)

            return Schema_IGMPv3(
                type=type_value,
                body=Schema_Query(
                    max_resp_code=max_resp_code,
                    checksum=checksum,
                    group=group,
                    ext=ext,
                    payload=payload,
                ),
            )  # type: ignore[return-value]

        raise ProtocolError(f'{self.alias}: unsupported message type: {type_value!r}')

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
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IGMPv3') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        Note:
            Dispatches on ``data.type`` rather than on
            :func:`isinstance(data, Data_Report) <isinstance>`, so that a
            hand-built :obj:`dict` carrying the right ``type`` but not
            actually one of the two concrete data classes -- as a test double
            legitimately might -- still rebuilds correctly, the same way
            :meth:`make` itself dispatches on the ``type`` it is given rather
            than requiring a particular input class.

        """
        if data.type == Enum_Type.IGMPv3_Membership_Report:
            report = cast('Data_Report', data)
            return {
                'type': report.type,
                'reserved_1': report.reserved_1,
                'checksum': report.checksum,
                'reserved_2': report.reserved_2,
                'records': report.records,
                'payload': cls._make_payload(data),
            }

        query = cast('Data_Query', data)
        return {
            'type': query.type,
            'max_resp_code': query.max_resp_code,
            'checksum': query.checksum,
            'group': query.group,
            'resv': query.resv,
            's_flag': query.s_flag,
            'qrv': query.qrv,
            'qqic': query.qqic,
            'sources': query.sources,
            'payload': cls._make_payload(data),
        }

# -*- coding: utf-8 -*-
"""ICMPv6 - Internet Control Message Protocol for IPv6
=========================================================

.. module:: pcapkit.protocols.internet.icmpv6.protocol

:mod:`pcapkit.protocols.internet.icmpv6.protocol` contains
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6` only,
which implements the extractor for Internet Control
Message Protocol for IPv6 (ICMPv6) [*]_, whose structure
is described as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``icmpv6.type``           Type
  1           8   ``icmpv6.code``           Code
  2          16   ``icmpv6.checksum``       Checksum
  4          32   ``icmpv6.data``           Message Body
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.const.igmp.record_type import RecordType as Enum_RecordType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.corekit.schema.shortread import hoist_short_read
from pcapkit.protocols.internet.icmp.protocol import ICMP
from pcapkit.protocols.internet.icmpv6.data import \
    DestinationUnreachable as Data_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.data import Echo as Data_Echo
from pcapkit.protocols.internet.icmpv6.data import ICMPv6 as Data_ICMPv6
from pcapkit.protocols.internet.icmpv6.data import MLDv1 as Data_MLDv1
from pcapkit.protocols.internet.icmpv6.data import MLDv2Query as Data_MLDv2Query
from pcapkit.protocols.internet.icmpv6.data import MLDv2Report as Data_MLDv2Report
from pcapkit.protocols.internet.icmpv6.data import \
    MulticastAddressRecord as Data_MulticastAddressRecord
from pcapkit.protocols.internet.icmpv6.data import PacketTooBig as Data_PacketTooBig
from pcapkit.protocols.internet.icmpv6.data import ParameterProblem as Data_ParameterProblem
from pcapkit.protocols.internet.icmpv6.data import TimeExceeded as Data_TimeExceeded
from pcapkit.protocols.internet.icmpv6.data import Unknown as Data_Unknown
from pcapkit.protocols.internet.icmpv6.schema import \
    DestinationUnreachable as Schema_DestinationUnreachable
from pcapkit.protocols.internet.icmpv6.schema import Echo as Schema_Echo
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6 as Schema_ICMPv6
from pcapkit.protocols.internet.icmpv6.schema import ICMPv6Type as Schema_ICMPv6Type
from pcapkit.protocols.internet.icmpv6.schema import MLDQuery as Schema_MLDQuery
from pcapkit.protocols.internet.icmpv6.schema import MLDv1 as Schema_MLDv1
from pcapkit.protocols.internet.icmpv6.schema import \
    MLDv2QueryExtension as Schema_MLDv2QueryExtension
from pcapkit.protocols.internet.icmpv6.schema import MLDv2Report as Schema_MLDv2Report
from pcapkit.protocols.internet.icmpv6.schema import \
    MulticastAddressRecord as Schema_MulticastAddressRecord
from pcapkit.protocols.internet.icmpv6.schema import PacketTooBig as Schema_PacketTooBig
from pcapkit.protocols.internet.icmpv6.schema import ParameterProblem as Schema_ParameterProblem
from pcapkit.protocols.internet.icmpv6.schema import TimeExceeded as Schema_TimeExceeded
from pcapkit.protocols.internet.icmpv6.schema import Unknown as Schema_Unknown
from pcapkit.protocols.misc.no_payload.protocol import NoPayload
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Callable, DefaultDict, Iterable, NoReturn, Optional

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo
    from pcapkit.protocols.schema import Schema

    TypeParser = Callable[[Schema_ICMPv6Type, NamedArg(Schema_ICMPv6, 'header'), NamedArg(int, 'length')],
                          Data_ICMPv6]
    TypeConstructor = Callable[[Enum_Type, DefaultArg(Optional[Data_ICMPv6]), KwArg(Any)], Schema_ICMPv6Type]

__all__ = ['ICMPv6']

#: The pseudo-header a payload's checksum is computed over in :meth:`ICMPv6.make`,
#: resolved there rather than imported, so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_PSEUDO_HEADER: 'ModuleDescriptor[Any]' = \
    ModuleDescriptor('pcapkit.protocols.misc.checksum.ip_pseudo.protocol', 'pseudo_header')


class ICMPv6(ICMP[Data_ICMPv6, Schema_ICMPv6],
             schema=Schema_ICMPv6, data=Data_ICMPv6):
    """This class implements Internet Control Message Protocol for IPv6.

    This class parses the following ICMPv6 message
    types, which are registered in the
    :attr:`self.__type__ <pcapkit.protocols.internet.icmpv6.protocol.ICMPv6.__type__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Type
         - Data Parser
         - Data Constructor
       * - Destination Unreachable
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_destination_unreachable`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_destination_unreachable`
       * - Packet Too Big
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_packet_too_big`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_packet_too_big`
       * - Time Exceeded
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_time_exceeded`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_time_exceeded`
       * - Parameter Problem
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_parameter_problem`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_parameter_problem`
       * - Echo Request / Echo Reply
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_echo`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_echo`
       * - Multicast Listener Query
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mld_query`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mld_query`
       * - Multicast Listener Report / Multicast Listener Done
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mldv1`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mldv1`
       * - Version 2 Multicast Listener Report
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._read_data_type_mldv2_report`
         - :meth:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6._make_data_type_mldv2_report`

    Any other type, including Neighbor Discovery (:rfc:`4861`), is kept as its
    raw message body, see :meth:`_read_data_type_none` and
    :meth:`_make_data_type_none`.

    .. versionchanged:: 1.6.0

       The checksum is computed when :meth:`make` is given none, over the
       ``pseudo`` it is given or by the enclosing IPv6 layer, and verified by
       that layer under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`
       (:issue:`2470`).

    .. versionchanged:: 1.7.0

       Decodes Multicast Listener Discovery, MLDv1 (:rfc:`2710`) and MLDv2
       (:rfc:`9777`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Type code to method mapping. A :obj:`str` value names the methods
    #: ``_read_data_type_${name}`` and ``_make_data_type_${name}``, falling
    #: back to ``_read_data_type_none`` / ``_make_data_type_none`` when they
    #: do not exist; any other value is a ``(parser, constructor)`` pair of
    #: callables.
    __type__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Type.Destination_Unreachable:             'destination_unreachable',
            Enum_Type.Packet_Too_Big:                      'packet_too_big',
            Enum_Type.Time_Exceeded:                       'time_exceeded',
            Enum_Type.Parameter_Problem:                   'parameter_problem',
            Enum_Type.Echo_Request:                        'echo',
            Enum_Type.Echo_Reply:                          'echo',
            Enum_Type.Multicast_Listener_Query:            'mld_query',
            Enum_Type.Multicast_Listener_Report:           'mldv1',
            Enum_Type.Multicast_Listener_Done:             'mldv1',
            Enum_Type.Version_2_Multicast_Listener_Report: 'mldv2_report',
        },
    )  # type: DefaultDict[Enum_Type | int, str | tuple[TypeParser, TypeConstructor]]

    #: Whether :meth:`make` left the checksum for the enclosing IP layer to
    #: compute, see :mod:`pcapkit.protocols.misc.checksum.ip_pseudo.protocol`.
    _checksum_pending = False

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Control Message Protocol for IPv6"]':
        """Name of current protocol."""
        return 'Internet Control Message Protocol for IPv6'

    @property
    def alias(self) -> 'Literal["ICMPv6"]':
        """Acronym of corresponding protocol."""
        return 'ICMPv6'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ICMPv6"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('ICMPv6',)

    def read(self, length: 'Optional[int]' = None, *,
             __packet__: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Data_ICMPv6':  # pylint: disable=unused-argument
        """Read Internet Control Message Protocol for IPv6 (ICMPv6).

        Structure of ICMPv6 header [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                         Message Body                         +
           |                                                               |

        Args:
            length: Length of packet data.
            __packet__: Optional packet data, unused.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        name = self._lookup_registry(self.__type__, schema.type)
        if isinstance(name, str):
            name = f'_read_data_type_{name}'
            meth = cast('TypeParser',
                       getattr(self, name, self._read_data_type_none))
        else:
            meth = name[0]
        icmpv6 = meth(schema.data, header=schema, length=length)

        body = schema.data
        if isinstance(body, Schema_MLDQuery):
            parts = (body, body.ext)  # type: tuple[Optional[Schema], ...]
        elif isinstance(body, Schema_MLDv2Report):
            parts = (body, *body.records)
        else:
            parts = (body,)
        # NOTE: Every schema in the body reads to the end of the data, so a cut
        # inside one is the message's, as a Report counting records past it.
        hoist_short_read(schema, 'data', parts)

        # NOTE: The quoted original packet stays raw in the message body,
        # so there is no next layer; the schema has no ``payload`` field.
        self._next = NoPayload()  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias)  # pylint: disable=attribute-defined-outside-init
        return icmpv6

    def make(self,
             type: 'Enum_Type | int' = Enum_Type.Echo_Request,  # pylint: disable=redefined-builtin
             code: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             # Echo identifier and sequence number, the shortest body.
             body: 'bytes | Data_ICMPv6 | Schema_ICMPv6Type | dict[str, Any]' = b'\x00\x00\x00\x00',
             pseudo: 'Optional[IP_Pseudo]' = None,
             **kwargs: 'Any') -> 'Schema_ICMPv6':
        """Make (construct) packet data.

        Args:
            type: ICMPv6 type.
            code: ICMPv6 code; meaning is entirely ``type``-dependent.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on,
                computed over ``pseudo`` (:rfc:`4443#section-2.3`), or left to
                an IPv6 layer this message is the payload of; zero otherwise.
            body: Message body. :obj:`bytes` is parsed against ``type``'s own
                schema; a :obj:`dict` or a
                :class:`~pcapkit.protocols.internet.icmpv6.data.ICMPv6` data
                model is handed to that type's own constructor method (see
                :attr:`__type__`); any other
                :class:`~pcapkit.protocols.internet.icmpv6.schema.ICMPv6Type`
                is used as is.
            pseudo: Pseudo-header of the enclosing IPv6 layer; its length is
                replaced by this message's own.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is a name, a :obj:`bool`, or a member
                or code that does not fit in one octet; if ``body`` is
                :obj:`bytes` that do not parse as the message body of
                ``type``, or is of none of the accepted types; or if
                ``checksum`` is not two octets.

        """
        type_val = self._make_index(type, Enum_Type, bits=8, name='type')

        if isinstance(body, bytes):
            try:
                data_val = Schema_ICMPv6Type.registry[type_val].unpack(  # pylint: disable=unsubscriptable-object
                    body, len(body), {})  # type: Schema_ICMPv6Type
            except Exception as exc:
                raise ProtocolError(f'{self.alias}: [TypeNo {type_val}] message body '
                                    f'{body.hex()} does not parse as this type') from exc
        elif isinstance(body, (dict, Data_ICMPv6)):
            name = self._lookup_registry(self.__type__, type_val)
            if isinstance(name, str):
                name = f'_make_data_type_{name}'
                meth = cast('TypeConstructor',
                           getattr(self, name, self._make_data_type_none))
            else:
                meth = name[1]

            if isinstance(body, dict):
                data_val = meth(type_val, **body)
            else:
                data_val = meth(type_val, body)
        elif isinstance(body, Schema_ICMPv6Type):
            data_val = body
        else:
            raise ProtocolError(f'{self.alias}: invalid message body type: {body.__class__}')

        schema = Schema_ICMPv6(
            type=type_val,
            code=code,
            checksum=b'\x00\x00' if checksum is None else self._make_octets(checksum, size=2, name='checksum'),
            data=data_val,
        )

        self._checksum_pending = False
        if checksum is None and config.CHECKSUM_COMPUTE:
            if pseudo is None:
                self._checksum_pending = True
            else:
                from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
                pseudo_header = _PSEUDO_HEADER.klass
                octets = schema.pack()
                schema.checksum = compute_checksum(octets, prefix=pseudo_header(pseudo, len(octets)))
        return schema

    @classmethod
    def register_type(cls, code: 'Enum_Type', meth: 'str | tuple[TypeParser, TypeConstructor]') -> 'None':
        """Register a message body parser.

        Args:
            code: ICMPv6 type code.
            meth: Name ``X`` of the ``_read_data_type_X`` and
                ``_make_data_type_X`` methods, or a ``(parser, constructor)``
                pair of callables, see :attr:`__type__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten.

        """
        incumbent = cls.__type__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'type {code} already registered, overwriting', RegistryWarning)
        cls.__type__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv6_ICMP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_ICMPv6') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'type': data.type,
            'code': data.code,
            'checksum': data.checksum,
            'body': data,
        }

    def _read_data_type_none(self, schema: 'Schema_Unknown', *, header: 'Schema_ICMPv6',
                             length: 'int') -> 'Data_Unknown':
        """Read ICMPv6 message of unknown type.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_Unknown(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            data=schema.data,
        )

    def _read_data_type_destination_unreachable(self, schema: 'Schema_DestinationUnreachable', *,
                                                header: 'Schema_ICMPv6',
                                                length: 'int') -> 'Data_DestinationUnreachable':
        """Read ICMPv6 Destination Unreachable message.

        Structure of ICMPv6 Destination Unreachable message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             Unused                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_DestinationUnreachable(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            unused=schema.unused,
            data=schema.data,
        )

    def _read_data_type_packet_too_big(self, schema: 'Schema_PacketTooBig', *, header: 'Schema_ICMPv6',
                                       length: 'int') -> 'Data_PacketTooBig':
        """Read ICMPv6 Packet Too Big message.

        Structure of ICMPv6 Packet Too Big message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             MTU                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_PacketTooBig(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            mtu=schema.mtu,
            data=schema.data,
        )

    def _read_data_type_time_exceeded(self, schema: 'Schema_TimeExceeded', *, header: 'Schema_ICMPv6',
                                      length: 'int') -> 'Data_TimeExceeded':
        """Read ICMPv6 Time Exceeded message.

        Structure of ICMPv6 Time Exceeded message [:rfc:`4443`] is identical
        to that of :meth:`_read_data_type_destination_unreachable`, but for
        the type code.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_TimeExceeded(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            unused=schema.unused,
            data=schema.data,
        )

    def _read_data_type_parameter_problem(self, schema: 'Schema_ParameterProblem', *,
                                          header: 'Schema_ICMPv6',
                                          length: 'int') -> 'Data_ParameterProblem':
        """Read ICMPv6 Parameter Problem message.

        Structure of ICMPv6 Parameter Problem message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            Pointer                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                    As much of invoking packet                |
           |                   as will fit without the ICMPv6             |
           |                   packet exceeding the minimum IPv6 MTU      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_ParameterProblem(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            pointer=schema.pointer,
            data=schema.data,
        )

    def _read_data_type_echo(self, schema: 'Schema_Echo', *, header: 'Schema_ICMPv6',
                             length: 'int') -> 'Data_Echo':
        """Read ICMPv6 Echo Request/Reply message.

        Structure of ICMPv6 Echo Request/Reply message [:rfc:`4443`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Identifier          |        Sequence Number        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                             Data                              +
           |                                                               |

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_Echo(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            id=schema.id,
            seq=schema.seq,
            data=schema.data,
        )

    def _read_data_type_mld_query(self, schema: 'Schema_MLDQuery', *, header: 'Schema_ICMPv6',
                                  length: 'int') -> 'Data_MLDv1 | Data_MLDv2Query':
        """Read MLD Multicast Listener Query message.

        Structure of MLDv2 Multicast Listener Query message [:rfc:`9777`], whose
        first 24 octets are the whole of an MLDv1 Query [:rfc:`2710`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Type = 130   |      Code     |           Checksum            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Maximum Response Code      |           Reserved            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Multicast Address                       *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Flags |S| QRV |     QQIC      |     Number of Sources (N)     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Source Address [1..N]                   *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        A Query of 28 or more octets is MLDv2's, and one of fewer MLDv1's
        (:rfc:`9777#section-8.1`), see
        :func:`~pcapkit.protocols.internet.icmpv6.schema.mldv2_query_present`.

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data: MLDv1's or MLDv2's.

        """
        ext = schema.ext
        if ext is None:
            return Data_MLDv1(
                type=header.type,
                code=header.code,
                checksum=header.checksum,
                length=length,
                version=1,
                max_resp_delay=schema.max_resp_code,
                reserved=schema.reserved,
                multicast_address=schema.multicast_address,
                data=schema.data,
            )
        return Data_MLDv2Query(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=2,
            max_resp_code=schema.max_resp_code,
            max_resp_delay=self._read_float_code(schema.max_resp_code, bits=16),
            reserved=schema.reserved,
            multicast_address=schema.multicast_address,
            flags=ext.flags['flags'],
            s_flag=bool(ext.flags['s_flag']),
            qrv=ext.flags['qrv'],
            qqic=ext.qqic,
            qqi=self._read_float_code(ext.qqic, bits=8),
            num_sources=ext.num_sources,
            sources=tuple(ext.sources),
            data=ext.data,
        )

    def _read_data_type_mldv1(self, schema: 'Schema_MLDv1', *, header: 'Schema_ICMPv6',
                              length: 'int') -> 'Data_MLDv1':
        """Read MLDv1 Multicast Listener Report/Done message.

        Structure of MLDv1 message [:rfc:`2710`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Maximum Response Delay    |          Reserved             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                       Multicast Address                       +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        return Data_MLDv1(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=1,
            max_resp_delay=schema.max_resp_delay,
            reserved=schema.reserved,
            multicast_address=schema.multicast_address,
            data=schema.data,
        )

    def _read_data_type_mldv2_report(self, schema: 'Schema_MLDv2Report', *, header: 'Schema_ICMPv6',
                                     length: 'int') -> 'Data_MLDv2Report':
        """Read MLDv2 Version 2 Multicast Listener Report message.

        Structure of MLDv2 Report message [:rfc:`9777`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Type = 143   |    Reserved   |           Checksum            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Flags             |Nr of Mcast Address Records (M)|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                  Multicast Address Record [1..M]              .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Each record has the shape of an IGMPv3 group record
        (:rfc:`3376#section-4.2.4`), with IPv6 addresses:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Multicast Address                       *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           *                       Source Address [1..N]                   *
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                         Auxiliary Data                        .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMPv6 header schema
            length: total length of the current ICMPv6 message

        Returns:
            Parsed message data.

        """
        records = tuple(
            Data_MulticastAddressRecord(
                record_type=record.record_type,
                aux_data_len=record.aux_data_len,
                num_sources=record.num_sources,
                multicast_address=record.multicast_address,
                sources=tuple(record.sources),
                aux_data=record.aux_data,
            ) for record in schema.records
        )
        return Data_MLDv2Report(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            version=2,
            flags=schema.flags,
            num_records=schema.num_records,
            records=records,
            data=schema.data,
        )

    def _make_data_type_none(self, type: 'Enum_Type', message: 'Optional[Data_Unknown]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_Unknown':
        """Make ICMPv6 message of unknown type.

        Args:
            type: ICMPv6 type.
            message: message data.
            data: raw message body as :obj:`bytes`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            data = message.data
        return Schema_Unknown(data=data)

    def _make_data_type_destination_unreachable(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                                message: 'Optional[Data_DestinationUnreachable]' = None, *,
                                                unused: 'bytes' = b'\x00\x00\x00\x00',
                                                data: 'bytes' = b'',
                                                **kwargs: 'Any') -> 'Schema_DestinationUnreachable':
        """Make ICMPv6 Destination Unreachable message.

        Args:
            type: ICMPv6 type.
            message: message data.
            unused: the four unused octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``unused`` is not four octets.

        """
        if message is not None:
            unused = getattr(message, 'unused', b'\x00\x00\x00\x00')
            data = message.data
        return Schema_DestinationUnreachable(unused=self._make_octets(unused, size=4, name='unused octets'),
                                             data=data)

    def _make_data_type_packet_too_big(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                       message: 'Optional[Data_PacketTooBig]' = None, *,
                                       mtu: 'int' = 0, data: 'bytes' = b'',
                                       **kwargs: 'Any') -> 'Schema_PacketTooBig':
        """Make ICMPv6 Packet Too Big message.

        Args:
            type: ICMPv6 type.
            message: message data.
            mtu: MTU of the link that could not forward the invoking packet.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            mtu = message.mtu
            data = message.data
        return Schema_PacketTooBig(mtu=mtu, data=data)

    def _make_data_type_time_exceeded(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                      message: 'Optional[Data_TimeExceeded]' = None, *,
                                      unused: 'bytes' = b'\x00\x00\x00\x00',
                                      data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_TimeExceeded':
        """Make ICMPv6 Time Exceeded message.

        Args:
            type: ICMPv6 type.
            message: message data.
            unused: the four unused octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``unused`` is not four octets.

        """
        if message is not None:
            unused = getattr(message, 'unused', b'\x00\x00\x00\x00')
            data = message.data
        return Schema_TimeExceeded(unused=self._make_octets(unused, size=4, name='unused octets'),
                                   data=data)

    def _make_data_type_parameter_problem(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                          message: 'Optional[Data_ParameterProblem]' = None, *,
                                          pointer: 'int' = 0, data: 'bytes' = b'',
                                          **kwargs: 'Any') -> 'Schema_ParameterProblem':
        """Make ICMPv6 Parameter Problem message.

        Args:
            type: ICMPv6 type.
            message: message data.
            pointer: pointer to the octet offset within the invoking packet
                where the error was detected.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            pointer = message.pointer
            data = message.data
        return Schema_ParameterProblem(pointer=pointer, data=data)

    def _make_data_type_echo(self, type: 'Enum_Type', message: 'Optional[Data_Echo]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             id: 'int' = 0, seq: 'int' = 0, data: 'bytes' = b'',  # pylint: disable=redefined-builtin
                             **kwargs: 'Any') -> 'Schema_Echo':
        """Make ICMPv6 Echo Request/Reply message.

        Args:
            type: ICMPv6 type.
            message: message data.
            id: identifier.
            seq: sequence number.
            data: data, echoed back verbatim by a reply to the same
                identifier and sequence number.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            id = message.id
            seq = message.seq
            data = message.data
        return Schema_Echo(id=id, seq=seq, data=data)

    def _make_data_type_mld_query(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                  message: 'Optional[Data_MLDv1 | Data_MLDv2Query]' = None, *,
                                  version: 'Optional[int]' = None,
                                  max_resp_code: 'Optional[int]' = None,
                                  max_resp_delay: 'int' = 0,
                                  reserved: 'bytes' = b'\x00\x00',
                                  multicast_address: 'IPv6Address | str | bytes | int' = '::',
                                  flags: 'Optional[int]' = None,
                                  s_flag: 'Optional[bool]' = None,
                                  qrv: 'Optional[int]' = None,
                                  qqic: 'Optional[int]' = None,
                                  qqi: 'Optional[int]' = None,
                                  num_sources: 'Optional[int]' = None,
                                  sources: 'Optional[Iterable[IPv6Address | str | bytes | int]]' = None,
                                  data: 'bytes' = b'',
                                  **kwargs: 'Any') -> 'Schema_MLDQuery':
        """Make MLD Multicast Listener Query message.

        Args:
            type: ICMPv6 type.
            message: message data, whose ``version`` picks the version built.
            version: MLD version, ``1`` (:rfc:`2710`) or ``2`` (:rfc:`9777`),
                which type 130 is shared by; no field picks it.
            max_resp_code: MLDv2's Maximum Response Code, as on the wire;
                encoded from ``max_resp_delay`` when not given.
            max_resp_delay: Maximum Response Delay, in milliseconds; MLDv1's
                field, or what MLDv2's ``max_resp_code`` encodes.
            reserved: the two reserved octets.
            multicast_address: multicast address queried, ``::`` for a General
                Query.
            flags: MLDv2's four flag bits, zero when not given.
            s_flag: MLDv2's Suppress Router-Side Processing flag, clear when
                not given.
            qrv: MLDv2's Querier's Robustness Variable, zero when not given.
            qqic: MLDv2's Querier's Query Interval Code, as on the wire;
                encoded from ``qqi`` when not given.
            qqi: MLDv2's Querier's Query Interval, in seconds.
            num_sources: MLDv2's number of sources, the length of ``sources``
                when not given; a count above it is written as given, as on a
                Query the capture cut inside its sources.
            sources: MLDv2's source addresses.
            data: octets past the fields of the version built; fewer than
                four for MLDv1, since a Query of 28 or more octets is MLDv2's.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``version`` is neither ``1`` nor ``2``; if an
                MLDv1 Query is given a field only MLDv2 takes, or four or more
                octets of ``data``; if a field does not fit its width, or
                ``num_sources`` is below the length of ``sources``; or if
                ``reserved`` is not two octets.

        """
        if message is not None:
            version = message.get('version')
            reserved = message.reserved
            multicast_address = message.multicast_address
            data = message.data
            if version == 2:
                query = cast('Data_MLDv2Query', message)
                max_resp_code = query.max_resp_code
                flags = query.flags
                s_flag = query.s_flag
                qrv = query.qrv
                qqic = query.qqic
                num_sources = query.num_sources
                sources = query.sources
            else:
                max_resp_delay = message.max_resp_delay
        if isinstance(version, bool) or version not in (1, 2):
            raise ProtocolError(f'{self.alias}: [TypeNo {type}] invalid MLD version: {version!r}')
        reserved = self._make_octets(reserved, size=2, name='reserved')

        if version == 1:
            # NOTE: The keyword check of the member a version names (#2574), and a length
            # that reads back as MLDv1 (RFC 9777 section 8.1).
            extra = [name for name, value in (
                ('max_resp_code', max_resp_code), ('flags', flags), ('s_flag', s_flag), ('qrv', qrv),
                ('qqic', qqic), ('qqi', qqi), ('num_sources', num_sources), ('sources', sources),
            ) if value is not None]
            if extra:
                raise ProtocolError(f'{self.alias}: [TypeNo {type}] an MLDv1 Query takes no '
                                    f'{", ".join(extra)}')
            if len(data) >= 4:
                raise ProtocolError(f'{self.alias}: [TypeNo {type}] an MLDv1 Query with {len(data)} octets '
                                    'of data reads as MLDv2')
            return Schema_MLDQuery(
                max_resp_code=self._make_uint(max_resp_delay, bits=16, name='max_resp_delay'),
                reserved=reserved,
                multicast_address=multicast_address,
                ext=None,
                data=data,
            )

        if max_resp_code is None:
            max_resp_code = self._make_float_code(max_resp_delay, bits=16, name='max_resp_delay')
        if qqic is None:
            qqic = self._make_float_code(0 if qqi is None else qqi, bits=8, name='qqi')
        source_list = [] if sources is None else list(sources)
        if num_sources is None:
            num_sources = len(source_list)
        elif self._make_uint(num_sources, bits=16, name='num_sources') < len(source_list):
            raise ProtocolError(f'{self.alias}: invalid num_sources: {num_sources!r} '
                                f'for {len(source_list)} source(s)')
        return Schema_MLDQuery(
            max_resp_code=self._make_uint(max_resp_code, bits=16, name='max_resp_code'),
            reserved=reserved,
            multicast_address=multicast_address,
            ext=Schema_MLDv2QueryExtension(
                flags={
                    'flags': self._make_uint(0 if flags is None else flags, bits=4, name='flags'),
                    's_flag': self._make_uint(False if s_flag is None else s_flag, bits=1, name='s_flag'),
                    'qrv': self._make_uint(0 if qrv is None else qrv, bits=3, name='qrv'),
                },
                qqic=self._make_uint(qqic, bits=8, name='qqic'),
                num_sources=num_sources,
                sources=source_list,
                data=data,
            ),
            data=b'',
        )

    def _make_data_type_mldv1(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                              message: 'Optional[Data_MLDv1]' = None, *,
                              max_resp_delay: 'int' = 0,
                              reserved: 'bytes' = b'\x00\x00',
                              multicast_address: 'IPv6Address | str | bytes | int' = '::',
                              data: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_MLDv1':
        """Make MLDv1 Multicast Listener Report/Done message.

        Args:
            type: ICMPv6 type.
            message: message data.
            max_resp_delay: Maximum Response Delay, in milliseconds; zero on
                a conformant sender.
            reserved: the two reserved octets.
            multicast_address: multicast address reported or left.
            data: octets past the 24 :rfc:`2710#section-3` defines.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``max_resp_delay`` does not fit 16 bits, or
                ``reserved`` is not two octets.

        """
        if message is not None:
            max_resp_delay = message.max_resp_delay
            reserved = message.reserved
            multicast_address = message.multicast_address
            data = message.data
        return Schema_MLDv1(
            max_resp_delay=self._make_uint(max_resp_delay, bits=16, name='max_resp_delay'),
            reserved=self._make_octets(reserved, size=2, name='reserved'),
            multicast_address=multicast_address,
            data=data,
        )

    def _make_data_type_mldv2_report(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                     message: 'Optional[Data_MLDv2Report]' = None, *,
                                     flags: 'int' = 0,
                                     num_records: 'Optional[int]' = None,
                                     records: 'Optional[Iterable[dict[str, Any] | Data_MulticastAddressRecord]]' = None,  # pylint: disable=line-too-long
                                     data: 'bytes' = b'',
                                     **kwargs: 'Any') -> 'Schema_MLDv2Report':
        """Make MLDv2 Version 2 Multicast Listener Report message.

        Args:
            type: ICMPv6 type.
            message: message data.
            flags: the 16 flag bits.
            num_records: number of multicast address records, the length of
                ``records`` when not given; a count above it is written as
                given, as on a Report the capture cut short.
            records: multicast address records, each a
                :class:`~pcapkit.protocols.internet.icmpv6.data.MulticastAddressRecord`
                or a :obj:`dict` of the keyword arguments
                :meth:`_make_address_record` takes.
            data: additional data past the last record.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        Raises:
            ProtocolError: If ``flags`` does not fit 16 bits, ``num_records`` is
                not an :obj:`int` from the length of ``records`` to 65535, or a
                record is refused, see :meth:`_make_address_record`.

        """
        if message is not None:
            flags = message.flags
            num_records = message.num_records
            records = message.records
            data = message.data
        record_list = [] if records is None else [
            self._make_address_record(record) if not isinstance(record, dict) else
            self._make_address_record(**record) for record in records
        ]
        if num_records is None:
            num_records = len(record_list)
        elif self._make_uint(num_records, bits=16, name='num_records') < len(record_list):
            raise ProtocolError(f'{self.alias}: invalid num_records: {num_records!r} '
                                f'for {len(record_list)} record(s)')
        return Schema_MLDv2Report(
            flags=self._make_uint(flags, bits=16, name='flags'),
            num_records=num_records,
            records=record_list,
            data=data,
        )

    def _make_address_record(self, record: 'Optional[Data_MulticastAddressRecord]' = None, *,
                             record_type: 'Enum_RecordType | int' = Enum_RecordType.MODE_IS_INCLUDE,
                             aux_data_len: 'Optional[int]' = None,
                             num_sources: 'Optional[int]' = None,
                             multicast_address: 'IPv6Address | str | bytes | int' = '::',
                             sources: 'Optional[Iterable[IPv6Address | str | bytes | int]]' = None,
                             aux_data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_MulticastAddressRecord':  # pylint: disable=unused-argument
        """Make an MLDv2 multicast address record (:rfc:`9777#section-5.2`).

        Args:
            record: record data, taking precedence over the keyword arguments
                below.
            record_type: record type (:rfc:`9777#section-5.2.13`).
            aux_data_len: auxiliary data length, in 32-bit words; derived from
                ``aux_data`` when not given.
            num_sources: number of source addresses, the length of ``sources``
                when not given; a count above it is written as given, as on a
                record the capture cut inside its sources.
            multicast_address: multicast address the record pertains to.
            sources: source addresses.
            aux_data: auxiliary data; :rfc:`9777#section-5.2.11` has an MLDv2
                sender leave it empty.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed record schema.

        Raises:
            ProtocolError: If ``record_type`` is a name, a :obj:`bool`, or a
                member or code outside 0 to 255; if ``aux_data_len`` or
                ``num_sources`` does not fit its width, or ``num_sources`` is
                below the length of ``sources``; or if ``aux_data_len`` is not
                given and ``aux_data`` is no whole number of 32-bit words.

        """
        if record is not None:
            record_type = record.record_type
            aux_data_len = record.aux_data_len
            num_sources = record.num_sources
            multicast_address = record.multicast_address
            sources = record.sources
            aux_data = record.aux_data

        source_list = [] if sources is None else list(sources)
        if num_sources is None:
            num_sources = len(source_list)
        elif self._make_uint(num_sources, bits=16, name='num_sources') < len(source_list):
            raise ProtocolError(f'{self.alias}: invalid num_sources: {num_sources!r} '
                                f'for {len(source_list)} source(s)')
        if aux_data_len is None:
            if len(aux_data) % 4:
                raise ProtocolError(f'{self.alias}: invalid aux_data: {len(aux_data)} octets '
                                    'are no whole number of 32-bit words')
            aux_data_len = len(aux_data) // 4
        return Schema_MulticastAddressRecord(
            record_type=self._make_index(record_type, Enum_RecordType, bits=8, name='record type'),
            aux_data_len=self._make_uint(aux_data_len, bits=8, name='aux_data_len'),
            num_sources=num_sources,
            multicast_address=multicast_address,
            sources=source_list,
            aux_data=aux_data,
        )

    def _verify_pseudo_checksum(self, pseudo: 'Optional[IP_Pseudo]') -> 'None':
        """Verify the checksum over the pseudo-header of the enclosing IP layer.

        That layer calls this once parsed, see
        :func:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.verify_upper`.

        Args:
            pseudo: Pseudo-header, or :data:`None` if the IP layer gives none.

        """
        from pcapkit.corekit.checksum.internet import ChecksumStatus, verify_checksum  # isort: skip # pylint: disable=import-outside-toplevel

        if pseudo is None:
            status = ChecksumStatus.NO_PSEUDO_HEADER
        else:
            status = verify_checksum(self.alias, self._data, self._info.checksum,
                                     length=pseudo.info.len, prefix=pseudo.data)
        self._info.__update__(checksum_status=status)

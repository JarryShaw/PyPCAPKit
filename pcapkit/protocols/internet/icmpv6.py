# -*- coding: utf-8 -*-
"""ICMPv6 - Internet Control Message Protocol for IPv6
===========================================================

.. module:: pcapkit.protocols.internet.icmpv6

:mod:`pcapkit.protocols.internet.icmpv6` contains
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6` only,
which implements extractor for Internet Control
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

"""
import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.icmpv6.type import Type as Enum_Type
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.icmpv6 import \
    DestinationUnreachable as Data_DestinationUnreachable
from pcapkit.protocols.data.internet.icmpv6 import Echo as Data_Echo
from pcapkit.protocols.data.internet.icmpv6 import ICMPv6 as Data_ICMPv6
from pcapkit.protocols.data.internet.icmpv6 import PacketTooBig as Data_PacketTooBig
from pcapkit.protocols.data.internet.icmpv6 import ParameterProblem as Data_ParameterProblem
from pcapkit.protocols.data.internet.icmpv6 import TimeExceeded as Data_TimeExceeded
from pcapkit.protocols.data.internet.icmpv6 import Unknown as Data_Unknown
from pcapkit.protocols.internet.icmp import ICMP
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.schema.internet.icmpv6 import \
    DestinationUnreachable as Schema_DestinationUnreachable
from pcapkit.protocols.schema.internet.icmpv6 import Echo as Schema_Echo
from pcapkit.protocols.schema.internet.icmpv6 import ICMPv6 as Schema_ICMPv6
from pcapkit.protocols.schema.internet.icmpv6 import ICMPv6Type as Schema_ICMPv6Type
from pcapkit.protocols.schema.internet.icmpv6 import PacketTooBig as Schema_PacketTooBig
from pcapkit.protocols.schema.internet.icmpv6 import ParameterProblem as Schema_ParameterProblem
from pcapkit.protocols.schema.internet.icmpv6 import TimeExceeded as Schema_TimeExceeded
from pcapkit.protocols.schema.internet.icmpv6 import Unknown as Schema_Unknown
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo

    TypeParser = Callable[[Schema_ICMPv6Type, NamedArg(Schema_ICMPv6, 'header'), NamedArg(int, 'length')],
                          Data_ICMPv6]
    TypeConstructor = Callable[[Enum_Type, DefaultArg(Optional[Data_ICMPv6]), KwArg(Any)], Schema_ICMPv6Type]

__all__ = ['ICMPv6']


class ICMPv6(ICMP[Data_ICMPv6, Schema_ICMPv6],
             schema=Schema_ICMPv6, data=Data_ICMPv6):
    """This class implements Internet Control Message Protocol for IPv6.

    This class parses the following ICMPv6 message
    types, which are registered in the
    :attr:`self.__type__ <pcapkit.protocols.internet.icmpv6.ICMPv6.__type__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Type
         - Data Parser
         - Data Constructor
       * - Destination Unreachable
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._read_data_type_destination_unreachable`
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._make_data_type_destination_unreachable`
       * - Packet Too Big
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._read_data_type_packet_too_big`
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._make_data_type_packet_too_big`
       * - Time Exceeded
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._read_data_type_time_exceeded`
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._make_data_type_time_exceeded`
       * - Parameter Problem
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._read_data_type_parameter_problem`
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._make_data_type_parameter_problem`
       * - Echo Request / Echo Reply
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._read_data_type_echo`
         - :meth:`~pcapkit.protocols.internet.icmpv6.ICMPv6._make_data_type_echo`

    Any other type, including Neighbor Discovery (:rfc:`4861`) and Multicast
    Listener Discovery (:rfc:`9777`), is kept as its raw message body, see
    :meth:`_read_data_type_none` and :meth:`_make_data_type_none`.

    .. versionchanged:: 1.6.0

       The checksum is computed when :meth:`make` is given none, over the
       ``pseudo`` it is given or by the enclosing IPv6 layer, and verified by
       that layer under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`
       (:issue:`2470`).

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
            Enum_Type.Destination_Unreachable: 'destination_unreachable',
            Enum_Type.Packet_Too_Big:          'packet_too_big',
            Enum_Type.Time_Exceeded:           'time_exceeded',
            Enum_Type.Parameter_Problem:       'parameter_problem',
            Enum_Type.Echo_Request:            'echo',
            Enum_Type.Echo_Reply:              'echo',
        },
    )  # type: DefaultDict[Enum_Type | int, str | tuple[TypeParser, TypeConstructor]]

    #: Whether :meth:`make` left the checksum for the enclosing IP layer to
    #: compute, see :mod:`pcapkit.protocols.misc.checksum.ip_pseudo`.
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

        # NOTE: The quoted original packet stays raw in the message body,
        # so there is no next layer; the schema has no ``payload`` field.
        self._next = NoPayload()  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias)  # pylint: disable=attribute-defined-outside-init
        return icmpv6

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.Echo_Request,  # pylint: disable=redefined-builtin
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             code: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             # Echo identifier and sequence number, the shortest body.
             body: 'bytes | Data_ICMPv6 | Schema_ICMPv6Type | dict[str, Any]' = b'\x00\x00\x00\x00',
             pseudo: 'Optional[IP_Pseudo]' = None,
             **kwargs: 'Any') -> 'Schema_ICMPv6':
        """Make (construct) packet data.

        Args:
            type: ICMPv6 type.
            type_default: Default value of ICMPv6 type.
            type_namespace: Namespace of ICMPv6 type.
            type_reversed: If the namespace of ICMPv6 type is reversed.
            code: ICMPv6 code; meaning is entirely ``type``-dependent.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on,
                computed over ``pseudo`` (:rfc:`4443#section-2.3`), or left to
                an IPv6 layer this message is the payload of; zero otherwise.
            body: Message body. :obj:`bytes` is parsed against ``type``'s own
                schema; a :obj:`dict` or a
                :class:`~pcapkit.protocols.data.internet.icmpv6.ICMPv6` data
                model is handed to that type's own constructor method (see
                :attr:`__type__`); any other
                :class:`~pcapkit.protocols.schema.internet.icmpv6.ICMPv6Type`
                is used as is.
            pseudo: Pseudo-header of the enclosing IPv6 layer; its length is
                replaced by this message's own.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``body`` is :obj:`bytes` that do not parse as
                the message body of ``type``, or is of none of the accepted
                types.

        """
        type_val = cast('Enum_Type',
                        self._make_index(type, type_default, namespace=type_namespace,
                                         reversed=type_reversed, pack=False))

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
            checksum=b'\x00\x00' if checksum is None else checksum,
            data=data_val,
        )

        self._checksum_pending = False
        if checksum is None and config.CHECKSUM_COMPUTE:
            if pseudo is None:
                self._checksum_pending = True
            else:
                from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
                from pcapkit.protocols.misc.checksum.ip_pseudo import pseudo_header  # isort: skip # pylint: disable=import-outside-toplevel
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

    def _verify_pseudo_checksum(self, pseudo: 'Optional[IP_Pseudo]') -> 'None':
        """Verify the checksum over the pseudo-header of the enclosing IP layer.

        That layer calls this once parsed, see
        :func:`~pcapkit.protocols.misc.checksum.ip_pseudo.verify_upper`.

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
            unused: the four unused octets, truncated or zero-filled to four
                octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            unused = getattr(message, 'unused', b'\x00\x00\x00\x00')
            data = message.data
        return Schema_DestinationUnreachable(unused=unused, data=data)

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
            unused: the four unused octets, truncated or zero-filled to four
                octets.
            data: as much of the invoking packet as fits the minimum IPv6
                MTU.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            unused = getattr(message, 'unused', b'\x00\x00\x00\x00')
            data = message.data
        return Schema_TimeExceeded(unused=unused, data=data)

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

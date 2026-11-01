# -*- coding: utf-8 -*-
"""ICMPv4 - Internet Control Message Protocol
=================================================

.. module:: pcapkit.protocols.internet.icmpv4

:mod:`pcapkit.protocols.internet.icmpv4` contains
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` only,
which implements extractor for Internet Control
Message Protocol (ICMP) [*]_, whose structure is
described as below:

======= ========= ======================= ===================================
Octets      Bits        Name                    Description
======= ========= ======================= ===================================
  0           0   ``icmpv4.type``           Type
  1           8   ``icmpv4.code``           Code
  2          16   ``icmpv4.checksum``       Checksum
  4          32   ``icmpv4.data``           Message Body
======= ========= ======================= ===================================

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

"""
import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.icmp.type import Type as Enum_Type
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.icmpv4 import \
    DestinationUnreachable as Data_DestinationUnreachable
from pcapkit.protocols.data.internet.icmpv4 import Echo as Data_Echo
from pcapkit.protocols.data.internet.icmpv4 import ICMPv4 as Data_ICMPv4
from pcapkit.protocols.data.internet.icmpv4 import ParameterProblem as Data_ParameterProblem
from pcapkit.protocols.data.internet.icmpv4 import TimeExceeded as Data_TimeExceeded
from pcapkit.protocols.data.internet.icmpv4 import Unknown as Data_Unknown
from pcapkit.protocols.internet.icmp import ICMP
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.schema.internet.icmpv4 import \
    DestinationUnreachable as Schema_DestinationUnreachable
from pcapkit.protocols.schema.internet.icmpv4 import Echo as Schema_Echo
from pcapkit.protocols.schema.internet.icmpv4 import ICMPv4 as Schema_ICMPv4
from pcapkit.protocols.schema.internet.icmpv4 import ICMPv4Type as Schema_ICMPv4Type
from pcapkit.protocols.schema.internet.icmpv4 import ParameterProblem as Schema_ParameterProblem
from pcapkit.protocols.schema.internet.icmpv4 import TimeExceeded as Schema_TimeExceeded
from pcapkit.protocols.schema.internet.icmpv4 import Unknown as Schema_Unknown
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    TypeParser = Callable[[Schema_ICMPv4Type, NamedArg(Schema_ICMPv4, 'header'), NamedArg(int, 'length')],
                          Data_ICMPv4]
    TypeConstructor = Callable[[Enum_Type, DefaultArg(Optional[Data_ICMPv4]), KwArg(Any)], Schema_ICMPv4Type]

__all__ = ['ICMPv4']


class ICMPv4(ICMP[Data_ICMPv4, Schema_ICMPv4],
             schema=Schema_ICMPv4, data=Data_ICMPv4):
    """This class implements Internet Control Message Protocol.

    This class parses the following ICMP message
    types, which are registered in the
    :attr:`self.__type__ <pcapkit.protocols.internet.icmpv4.ICMPv4.__type__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Type
         - Data Parser
         - Data Constructor
       * - Echo Reply / Echo Request
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._read_data_type_echo`
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._make_data_type_echo`
       * - Destination Unreachable
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._read_data_type_destination_unreachable`
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._make_data_type_destination_unreachable`
       * - Time Exceeded
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._read_data_type_time_exceeded`
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._make_data_type_time_exceeded`
       * - Parameter Problem
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._read_data_type_parameter_problem`
         - :meth:`~pcapkit.protocols.internet.icmpv4.ICMPv4._make_data_type_parameter_problem`

    Any other type is kept as its raw message body, see
    :meth:`_read_data_type_none` and :meth:`_make_data_type_none`.

    .. versionchanged:: 1.6.0

       The checksum is computed when :meth:`make` is given none, and verified
       on read under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`,
       unless the enclosing IP layer is a fragment (:issue:`2470`).

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
            Enum_Type.Echo_Reply:               'echo',
            Enum_Type.Echo:                     'echo',
            Enum_Type.Destination_Unreachable:  'destination_unreachable',
            Enum_Type.Time_Exceeded:            'time_exceeded',
            Enum_Type.Parameter_Problem:        'parameter_problem',
        },
    )  # type: DefaultDict[Enum_Type | int, str | tuple[TypeParser, TypeConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Control Message Protocol"]':
        """Name of current protocol."""
        return 'Internet Control Message Protocol'

    @property
    def alias(self) -> 'Literal["ICMP"]':
        """Acronym of corresponding protocol."""
        return 'ICMP'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ICMP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        :rfc:`792` names the protocol ``ICMP``, without a version.

        String ``==`` compares against ``(cls, *id())``, so ``== 'ICMPv4'`` is
        :data:`False`, while ``'ICMPv4' in`` matches by class.

        Returns:
            Index ID of the protocol.

        """
        return ('ICMP',)

    def read(self, length: 'Optional[int]' = None, *,
             __packet__: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Data_ICMPv4':  # pylint: disable=unused-argument
        """Read Internet Control Message Protocol (ICMP).

        Structure of ICMP header [:rfc:`792`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                         Message Body                         .
           .                                                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

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
        icmp = meth(schema.data, header=schema, length=length)

        # NOTE: The checksum covers the whole message, with no pseudo-header (RFC 792);
        # an IP fragment carries only part of one.
        if config.CHECKSUM_VERIFY:
            from pcapkit.corekit.checksum.internet import (  # isort: skip # pylint: disable=import-outside-toplevel
                ChecksumStatus, _in_fragment, verify_checksum)
            if _in_fragment.get():
                status = ChecksumStatus.NO_PSEUDO_HEADER
            else:
                status = verify_checksum(self.alias, self._data, schema.checksum, length=length)
            icmp.__update__([
                ('checksum_status', status),
            ])

        # NOTE: The quoted original datagram stays raw in the message body,
        # so there is no next layer; the schema has no ``payload`` field.
        self._next = NoPayload()  # pylint: disable=attribute-defined-outside-init
        self._protos = ProtoChain(self.__class__, self.alias)  # pylint: disable=attribute-defined-outside-init
        return icmp

    def make(self,
             type: 'Enum_Type | StdlibEnum | AenumEnum | str | int' = Enum_Type.Echo,  # pylint: disable=redefined-builtin
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             code: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             # Echo identifier and sequence number, the shortest body.
             body: 'bytes | Data_ICMPv4 | Schema_ICMPv4Type | dict[str, Any]' = b'\x00\x00\x00\x00',
             **kwargs: 'Any') -> 'Schema_ICMPv4':
        """Make (construct) packet data.

        Args:
            type: ICMP type.
            type_default: Default value of ICMP type.
            type_namespace: Namespace of ICMP type.
            type_reversed: If the namespace of ICMP type is reversed.
            code: ICMP code; meaning is entirely ``type``-dependent.
            checksum: Checksum; if :data:`None`, computed over the message
                (:rfc:`792`) when :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE`
                is on, zero when it is off.
            body: Message body. :obj:`bytes` is parsed against ``type``'s own
                schema; a :obj:`dict` or a :class:`~pcapkit.protocols.data.internet.icmpv4.ICMPv4`
                data model is handed to that type's own constructor method
                (see :attr:`__type__`); any other
                :class:`~pcapkit.protocols.schema.internet.icmpv4.ICMPv4Type` is
                used as is.
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
                data_val = Schema_ICMPv4Type.registry[type_val].unpack(  # pylint: disable=unsubscriptable-object
                    body, len(body), {})  # type: Schema_ICMPv4Type
            except Exception as exc:
                raise ProtocolError(f'{self.alias}: [TypeNo {type_val}] message body '
                                    f'{body.hex()} does not parse as this type') from exc
        elif isinstance(body, (dict, Data_ICMPv4)):
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
        elif isinstance(body, Schema_ICMPv4Type):
            data_val = body
        else:
            raise ProtocolError(f'{self.alias}: invalid message body type: {body.__class__}')

        schema = Schema_ICMPv4(
            type=type_val,
            code=code,
            checksum=b'\x00\x00' if checksum is None else checksum,
            data=data_val,
        )

        if checksum is None and config.CHECKSUM_COMPUTE:
            from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
            schema.checksum = compute_checksum(schema.pack())
        return schema

    @classmethod
    def register_type(cls, code: 'Enum_Type', meth: 'str | tuple[TypeParser, TypeConstructor]') -> 'None':
        """Register a message body parser.

        Args:
            code: ICMP type code.
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
        return Enum_TransType.ICMP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_ICMPv4') -> 'dict[str, Any]':  # type: ignore[override]
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

    def _read_data_type_none(self, schema: 'Schema_Unknown', *, header: 'Schema_ICMPv4',
                             length: 'int') -> 'Data_Unknown':
        """Read ICMP message of unknown type.

        Args:
            schema: parsed message body schema
            header: parsed ICMP header schema
            length: total length of the current ICMP message

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

    def _read_data_type_echo(self, schema: 'Schema_Echo', *, header: 'Schema_ICMPv4',
                             length: 'int') -> 'Data_Echo':
        """Read ICMP Echo Request/Reply message.

        Structure of ICMP Echo Request/Reply message [:rfc:`792`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Identifier          |        Sequence Number        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                             Data                              .
           .                                                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMP header schema
            length: total length of the current ICMP message

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

    def _read_data_type_destination_unreachable(self, schema: 'Schema_DestinationUnreachable', *,
                                                header: 'Schema_ICMPv4',
                                                length: 'int') -> 'Data_DestinationUnreachable':
        """Read ICMP Destination Unreachable message.

        Structure of ICMP Destination Unreachable message [:rfc:`792`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                             unused                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Internet Header + 64 bits of Original Data Datagram      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMP header schema
            length: total length of the current ICMP message

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

    def _read_data_type_time_exceeded(self, schema: 'Schema_TimeExceeded', *, header: 'Schema_ICMPv4',
                                      length: 'int') -> 'Data_TimeExceeded':
        """Read ICMP Time Exceeded message.

        Structure of ICMP Time Exceeded message [:rfc:`792`] is identical to
        that of :meth:`_read_data_type_destination_unreachable`, but for the
        type code.

        Args:
            schema: parsed message body schema
            header: parsed ICMP header schema
            length: total length of the current ICMP message

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
                                          header: 'Schema_ICMPv4',
                                          length: 'int') -> 'Data_ParameterProblem':
        """Read ICMP Parameter Problem message.

        Structure of ICMP Parameter Problem message [:rfc:`792`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |     Type      |     Code      |          Checksum             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Pointer    |                   unused                      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Internet Header + 64 bits of Original Data Datagram      |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed message body schema
            header: parsed ICMP header schema
            length: total length of the current ICMP message

        Returns:
            Parsed message data.

        """
        return Data_ParameterProblem(
            type=header.type,
            code=header.code,
            checksum=header.checksum,
            length=length,
            pointer=schema.pointer,
            unused=schema.unused,
            data=schema.data,
        )

    def _make_data_type_none(self, type: 'Enum_Type', message: 'Optional[Data_Unknown]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_Unknown':
        """Make ICMP message of unknown type.

        Args:
            type: ICMP type.
            message: message data.
            data: raw message body as :obj:`bytes`.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            data = message.data
        return Schema_Unknown(data=data)

    def _make_data_type_echo(self, type: 'Enum_Type', message: 'Optional[Data_Echo]' = None, *,  # pylint: disable=redefined-builtin,unused-argument
                             id: 'int' = 0, seq: 'int' = 0, data: 'bytes' = b'',  # pylint: disable=redefined-builtin
                             **kwargs: 'Any') -> 'Schema_Echo':
        """Make ICMP Echo Request/Reply message.

        Args:
            type: ICMP type.
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

    def _make_data_type_destination_unreachable(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                                message: 'Optional[Data_DestinationUnreachable]' = None, *,
                                                unused: 'bytes' = b'\x00\x00\x00\x00',
                                                data: 'bytes' = b'',
                                                **kwargs: 'Any') -> 'Schema_DestinationUnreachable':
        """Make ICMP Destination Unreachable message.

        Args:
            type: ICMP type.
            message: message data.
            unused: the four unused octets, truncated or zero-filled to four
                octets.
            data: internet header plus the first eight octets of the
                original datagram's payload.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            unused = getattr(message, 'unused', b'\x00\x00\x00\x00')
            data = message.data
        return Schema_DestinationUnreachable(unused=unused, data=data)

    def _make_data_type_time_exceeded(self, type: 'Enum_Type',  # pylint: disable=redefined-builtin,unused-argument
                                      message: 'Optional[Data_TimeExceeded]' = None, *,
                                      unused: 'bytes' = b'\x00\x00\x00\x00',
                                      data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_TimeExceeded':
        """Make ICMP Time Exceeded message.

        Args:
            type: ICMP type.
            message: message data.
            unused: the four unused octets, truncated or zero-filled to four
                octets.
            data: internet header plus the first eight octets of the
                original datagram's payload.
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
                                          pointer: 'int' = 0, unused: 'bytes' = b'\x00\x00\x00',
                                          data: 'bytes' = b'', **kwargs: 'Any') -> 'Schema_ParameterProblem':
        """Make ICMP Parameter Problem message.

        Args:
            type: ICMP type.
            message: message data.
            pointer: pointer to the octet of the original datagram that
                caused the error.
            unused: the three unused octets, truncated or zero-filled to
                three octets.
            data: internet header plus the first eight octets of the
                original datagram's payload.
            **kwargs: arbitrary keyword arguments.

        Returns:
            Constructed message body schema.

        """
        if message is not None:
            pointer = message.pointer
            unused = getattr(message, 'unused', b'\x00\x00\x00')
            data = message.data
        return Schema_ParameterProblem(pointer=pointer, unused=unused, data=data)

# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""DCCP - Datagram Congestion Control Protocol
=================================================

.. module:: pcapkit.protocols.transport.dccp

:mod:`pcapkit.protocols.transport.dccp` contains
:class:`~pcapkit.protocols.transport.dccp.DCCP` only,
which implements the extractor for Datagram Congestion
Control Protocol (DCCP) [*]_, whose generic header is
described as below:

======= ========= ========================= =======================================
Octets      Bits        Name                    Description
======= ========= ========================= =======================================
  0           0   ``dccp.srcport``          Source Port
  2          16   ``dccp.dstport``          Destination Port
  4          32   ``dccp.hdr_len``          Data Offset
  5          40   ``dccp.ccval``            HC-Sender CCID Value (CCVal)
  5          44   ``dccp.cscov``            Checksum Coverage (CsCov)
  6          48   ``dccp.checksum``         Checksum
  8          64   ``dccp.reserved``         Reserved (Res)
  8          67   ``dccp.type``             Packet Type
  8          71   ``dccp.x``                Extended Sequence Numbers (X)
  9          72   ``dccp.seq_reserved``     Reserved (if X set)
  10         80   ``dccp.seq``              Sequence Number (48 bits if X set)
======= ========= ========================= =======================================

With ``X`` clear, the Sequence Number is 24 bits at octet 9 and the generic
header 12 octets long. The fields of the packet type, then the options, follow.

.. [*] https://en.wikipedia.org/wiki/Datagram_Congestion_Control_Protocol

.. versionadded:: 1.6.0

"""
import collections
from typing import TYPE_CHECKING, cast

from pcapkit.const.dccp.ack_vector_state import AckVectorState as Enum_AckVectorState
from pcapkit.const.dccp.drop_code import DropCode as Enum_DropCode
from pcapkit.const.dccp.feature import Feature as Enum_Feature
from pcapkit.const.dccp.option import Option as Enum_Option
from pcapkit.const.dccp.packet_type import PacketType as Enum_PacketType
from pcapkit.const.dccp.reset_code import ResetCode as Enum_ResetCode
from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.data.transport.dccp import DCCP as Data_DCCP
from pcapkit.protocols.data.transport.dccp import AckVector as Data_AckVector
from pcapkit.protocols.data.transport.dccp import AckVectorRun as Data_AckVectorRun
from pcapkit.protocols.data.transport.dccp import Change as Data_Change
from pcapkit.protocols.data.transport.dccp import Confirm as Data_Confirm
from pcapkit.protocols.data.transport.dccp import DataChecksum as Data_DataChecksum
from pcapkit.protocols.data.transport.dccp import DataDropped as Data_DataDropped
from pcapkit.protocols.data.transport.dccp import DataDroppedBlock as Data_DataDroppedBlock
from pcapkit.protocols.data.transport.dccp import ElapsedTime as Data_ElapsedTime
from pcapkit.protocols.data.transport.dccp import InitCookie as Data_InitCookie
from pcapkit.protocols.data.transport.dccp import Mandatory as Data_Mandatory
from pcapkit.protocols.data.transport.dccp import NDPCount as Data_NDPCount
from pcapkit.protocols.data.transport.dccp import Padding as Data_Padding
from pcapkit.protocols.data.transport.dccp import SlowReceiver as Data_SlowReceiver
from pcapkit.protocols.data.transport.dccp import Timestamp as Data_Timestamp
from pcapkit.protocols.data.transport.dccp import TimestampEcho as Data_TimestampEcho
from pcapkit.protocols.data.transport.dccp import UnassignedOption as Data_UnassignedOption
from pcapkit.protocols.schema.schema import Schema
from pcapkit.protocols.schema.transport.dccp import ACK_TYPES
from pcapkit.protocols.schema.transport.dccp import DCCP as Schema_DCCP
from pcapkit.protocols.schema.transport.dccp import (DCCP_MIN_HEADER_LEN,
                                                     DCCP_SINGLE_OCTET_OPTION_MAX, RESET_TYPE,
                                                     SERVICE_TYPES)
from pcapkit.protocols.schema.transport.dccp import AckVector as Schema_AckVector
from pcapkit.protocols.schema.transport.dccp import Change as Schema_Change
from pcapkit.protocols.schema.transport.dccp import Confirm as Schema_Confirm
from pcapkit.protocols.schema.transport.dccp import DataChecksum as Schema_DataChecksum
from pcapkit.protocols.schema.transport.dccp import DataDropped as Schema_DataDropped
from pcapkit.protocols.schema.transport.dccp import ElapsedTime as Schema_ElapsedTime
from pcapkit.protocols.schema.transport.dccp import InitCookie as Schema_InitCookie
from pcapkit.protocols.schema.transport.dccp import Mandatory as Schema_Mandatory
from pcapkit.protocols.schema.transport.dccp import NDPCount as Schema_NDPCount
from pcapkit.protocols.schema.transport.dccp import Padding as Schema_Padding
from pcapkit.protocols.schema.transport.dccp import SlowReceiver as Schema_SlowReceiver
from pcapkit.protocols.schema.transport.dccp import Timestamp as Schema_Timestamp
from pcapkit.protocols.schema.transport.dccp import TimestampEcho as Schema_TimestampEcho
from pcapkit.protocols.schema.transport.dccp import UnassignedOption as Schema_UnassignedOption
from pcapkit.protocols.schema.transport.dccp import header_length
from pcapkit.protocols.transport.transport import Transport
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, ClassVar, DefaultDict, Iterable, Optional, Type

    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.data.transport.dccp import Option as Data_Option
    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.transport.dccp import Option as Schema_Option
    from pcapkit.protocols.schema.transport.dccp import TypeField as Schema_TypeField

    Option = OrderedMultiDict[Enum_Option, Data_Option]
    OptionParser = Callable[[Schema_Option, NamedArg(Option, 'options')], Data_Option]
    OptionConstructor = Callable[[Enum_Option, DefaultArg(Optional[Data_Option]),
                                  KwArg(Any)], Schema_Option]

__all__ = ['DCCP']

#: Longest a DCCP header can be: a Data Offset of 255 words, :rfc:`4340#section-5`.
DCCP_MAX_HEADER_LEN = 1020


class DCCP(Transport[Data_DCCP, Schema_DCCP],
           schema=Schema_DCCP, data=Data_DCCP):
    """This class implements Datagram Congestion Control Protocol.

    No application protocol is registered in :attr:`self.__proto__
    <pcapkit.protocols.transport.dccp.DCCP.__proto__>`, so the application data
    area is :class:`~pcapkit.protocols.misc.raw.Raw` unless one is.

    This class supports parsing of the following DCCP options, which are
    directly mapped to the :class:`pcapkit.const.dccp.option.Option`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Option Code
         - Option Parser
         - Option Constructor
       * - :attr:`~pcapkit.const.dccp.option.Option.Padding`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_padding`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_padding`
       * - :attr:`~pcapkit.const.dccp.option.Option.Mandatory`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_mandatory`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_mandatory`
       * - :attr:`~pcapkit.const.dccp.option.Option.Slow_Receiver`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_slow_receiver`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_slow_receiver`
       * - :attr:`~pcapkit.const.dccp.option.Option.Change_L`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_change`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_change`
       * - :attr:`~pcapkit.const.dccp.option.Option.Confirm_L`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_confirm`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_confirm`
       * - :attr:`~pcapkit.const.dccp.option.Option.Change_R`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_change`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_change`
       * - :attr:`~pcapkit.const.dccp.option.Option.Confirm_R`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_confirm`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_confirm`
       * - :attr:`~pcapkit.const.dccp.option.Option.Init_Cookie`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_init_cookie`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_init_cookie`
       * - :attr:`~pcapkit.const.dccp.option.Option.NDP_Count`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_ndp_count`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_ndp_count`
       * - :attr:`~pcapkit.const.dccp.option.Option.Ack_Vector_Nonce_0`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_ack_vector`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_ack_vector`
       * - :attr:`~pcapkit.const.dccp.option.Option.Ack_Vector_Nonce_1`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_ack_vector`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_ack_vector`
       * - :attr:`~pcapkit.const.dccp.option.Option.Data_Dropped`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_data_dropped`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_data_dropped`
       * - :attr:`~pcapkit.const.dccp.option.Option.Timestamp`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_timestamp`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_timestamp`
       * - :attr:`~pcapkit.const.dccp.option.Option.Timestamp_Echo`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_timestamp_echo`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_timestamp_echo`
       * - :attr:`~pcapkit.const.dccp.option.Option.Elapsed_Time`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_elapsed_time`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_elapsed_time`
       * - :attr:`~pcapkit.const.dccp.option.Option.Data_Checksum`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._read_opt_data_checksum`
         - :meth:`~pcapkit.protocols.transport.dccp.DCCP._make_opt_data_checksum`

    Any other option is kept as its type, length and data, through
    :meth:`_read_opt_unassigned` and :meth:`_make_opt_unassigned`.

    The checksum is computed when :meth:`make` is given none, over the
    ``pseudo`` it is given or by the enclosing IP layer, and verified by that
    layer under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, over the
    part of the packet the Checksum Coverage gives (:rfc:`4340#section-9`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.transport.transport.Transport._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.protocol.Protocol._import_next_layer>`. Keyed by
    #: port number, and empty until a protocol is registered.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by: the enum a key must be a member of,
    #: and whether a bare :class:`int` is a valid key there too, as for
    #: :attr:`TCP.__proto_key__ <pcapkit.protocols.transport.tcp.TCP.__proto_key__>`.
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_AppType, True)

    #: Option type to method mapping, see :meth:`_read_dccp_options` and
    #: :meth:`_make_dccp_options`. A :class:`str` value names the methods
    #: ``_read_opt_${name}`` and ``_make_opt_${name}``, falling back to
    #: :meth:`_read_opt_unassigned` and :meth:`_make_opt_unassigned` when the
    #: class has no such method; any other value is a ``(parser, constructor)``
    #: pair of callables.
    __option__ = collections.defaultdict(
        lambda: 'unassigned',
        {
            Enum_Option.Padding: 'padding',                 # [RFC 4340] Padding
            Enum_Option.Mandatory: 'mandatory',             # [RFC 4340] Mandatory
            Enum_Option.Slow_Receiver: 'slow_receiver',     # [RFC 4340] Slow Receiver
            Enum_Option.Change_L: 'change',                 # [RFC 4340] Change L
            Enum_Option.Confirm_L: 'confirm',               # [RFC 4340] Confirm L
            Enum_Option.Change_R: 'change',                 # [RFC 4340] Change R
            Enum_Option.Confirm_R: 'confirm',               # [RFC 4340] Confirm R
            Enum_Option.Init_Cookie: 'init_cookie',         # [RFC 4340] Init Cookie
            Enum_Option.NDP_Count: 'ndp_count',             # [RFC 4340] NDP Count
            Enum_Option.Ack_Vector_Nonce_0: 'ack_vector',   # [RFC 4340] Ack Vector [Nonce 0]
            Enum_Option.Ack_Vector_Nonce_1: 'ack_vector',   # [RFC 4340] Ack Vector [Nonce 1]
            Enum_Option.Data_Dropped: 'data_dropped',       # [RFC 4340] Data Dropped
            Enum_Option.Timestamp: 'timestamp',             # [RFC 4340] Timestamp
            Enum_Option.Timestamp_Echo: 'timestamp_echo',   # [RFC 4340] Timestamp Echo
            Enum_Option.Elapsed_Time: 'elapsed_time',       # [RFC 4340] Elapsed Time
            Enum_Option.Data_Checksum: 'data_checksum',     # [RFC 4340] Data Checksum
        },
    )  # type: DefaultDict[int, str | tuple[OptionParser, OptionConstructor]]

    #: Whether :meth:`make` left the checksum for the enclosing IP layer to
    #: compute, see :mod:`pcapkit.protocols.misc.checksum.ip_pseudo`.
    _checksum_pending = False

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Datagram Congestion Control Protocol"]':
        """Name of current protocol."""
        return 'Datagram Congestion Control Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def src(self) -> 'Enum_AppType':
        """Source port."""
        return self._info.srcport

    @property
    def dst(self) -> 'Enum_AppType':
        """Destination port."""
        return self._info.dstport

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DCCP':  # pylint: disable=unused-argument
        """Read Datagram Congestion Control Protocol (DCCP).

        Structure of DCCP generic header with ``X`` set [:rfc:`4340`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Source Port          |           Dest Port           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Data Offset  | CCVal | CsCov |           Checksum            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     |       |X|               |                               .
            | Res | Type  |=|   Reserved    |  Sequence Number (high bits)  .
            |     |       |1|               |                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                  Sequence Number (low bits)                   |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        The Acknowledgement Number Subheader of every packet type but
        DCCP-Request, DCCP-Data and DCCP-Listen follows, then the Service Code
        of a DCCP-Request, DCCP-Response or DCCP-Listen (:rfc:`5596`), or the
        Reset Code and Data octets of a DCCP-Reset, then the options.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Data Offset is smaller than the header the
                packet type has, or declares more header than the data holds
                (:rfc:`4340#section-5.1`).

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        code = schema.type['type']
        dccp = Data_DCCP(
            srcport=schema.srcport,
            dstport=schema.dstport,
            hdr_len=schema.offset * 4,
            ccval=schema.cscov['ccval'],
            cscov=schema.cscov['cscov'],
            checksum=schema.checksum,
            reserved=schema.type['reserved'],
            type=Enum_PacketType.get(code),
            x=bool(schema.type['x']),
            seq=schema.seq,
        )

        fixed = header_length(schema.type)
        if dccp.hdr_len < fixed:
            raise ProtocolError(f'{self.alias}: header length {dccp.hdr_len} is shorter than the '
                                f'{fixed} octets of a {dccp.type.name}')
        if len(self) < dccp.hdr_len:
            raise ProtocolError(f'{self.alias}: header length {dccp.hdr_len} runs past the end of '
                                f'the data ({len(self)} octets)')

        if dccp.x:
            dccp.__update__(seq_reserved=schema.seq_reserved)
        if code in ACK_TYPES:
            dccp.__update__(ack_reserved=schema.ack_reserved, ack=schema.ack)
        if code in SERVICE_TYPES:
            dccp.__update__(service_code=schema.service_code)
        if code == RESET_TYPE:
            dccp.__update__(reset_code=Enum_ResetCode.get(schema.reset_code),
                            reset_data=schema.reset_data)
        if dccp.hdr_len > fixed:
            dccp.__update__(options=self._read_dccp_options())

        return self._decode_next_layer(dccp, (dccp.srcport.port, dccp.dstport.port), length - dccp.hdr_len)

    def make(self,
             srcport: 'Enum_AppType | int' = 0,
             dstport: 'Enum_AppType | int' = 0,
             ccval: 'int' = 0,
             cscov: 'int' = 0,
             checksum: 'Optional[bytes]' = None,
             reserved: 'int' = 0,
             type: 'Enum_PacketType | int' = Enum_PacketType.DCCP_Request,  # pylint: disable=redefined-builtin
             x: 'bool' = True,
             seq_reserved: 'int' = 0,
             seq: 'int' = 0,
             ack_reserved: 'int' = 0,
             ack: 'int' = 0,
             service_code: 'int' = 0,
             reset_code: 'Enum_ResetCode | int' = Enum_ResetCode.Unspecified,
             reset_data: 'bytes' = bytes(3),
             options: 'Optional[list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option]' = None,  # pylint: disable=line-too-long
             payload: 'bytes | ProtocolBase | Schema' = b'',
             pseudo: 'Optional[IP_Pseudo]' = None,
             **kwargs: 'Any') -> 'Schema_DCCP':
        """Make (construct) packet data.

        Args:
            srcport: Source port.
            dstport: Destination port.
            ccval: Value used by the HC-Sender CCID.
            cscov: Checksum coverage, see :rfc:`4340#section-9.2`; written as
                zero where it reaches the end of the packet and the checksum is
                computed, as Linux did.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on,
                computed over ``pseudo`` and the part of the packet ``cscov``
                gives, or left to an IP layer this packet is the payload of;
                zero otherwise.
            reserved: Reserved bits (``Res``).
            type: Packet type.
            x: Whether the sequence and acknowledgement numbers are 48 bits
                rather than 24 bits.
            seq_reserved: Reserved octet ahead of a 48-bit sequence number.
            seq: Sequence number.
            ack_reserved: Reserved bits of the acknowledgement number
                subheader, in a packet type that carries one.
            ack: Acknowledgement number, in a packet type that carries one.
            service_code: Service code of a DCCP-Request, DCCP-Response or
                DCCP-Listen.
            reset_code: Reset code of a DCCP-Reset.
            reset_data: Data 1, Data 2 and Data 3 of a DCCP-Reset.
            options: DCCP options, padded with Padding options to a multiple
                of 32 bits.
            payload: Payload, i.e. the application data area.
            pseudo: Pseudo-header of the enclosing IP layer; its length is
                replaced by this packet's own.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``srcport`` or ``dstport`` is a :obj:`bool`, the
                header with its options runs past the 1020 octets a Data Offset
                can give, or an option maker rejects its option.
            EnumValueError: If ``type`` is out of its 4-bit range.

        """
        code = Enum_PacketType.get(type)
        type_field = {
            'reserved': reserved,
            'type': int(code),
            'x': int(x),
        }  # type: Schema_TypeField

        if options is not None:
            options_value, options_length = self._make_dccp_options(options)
        else:
            options_value, options_length = [], 0

        hdr_len = header_length(type_field) + options_length
        if hdr_len > DCCP_MAX_HEADER_LEN:
            raise ProtocolError(f'{self.alias}: header length {hdr_len} exceeds '
                                f'{DCCP_MAX_HEADER_LEN} octets')

        schema = Schema_DCCP(
            srcport=self._make_port(srcport, Enum_TransportProtocol.dccp),
            dstport=self._make_port(dstport, Enum_TransportProtocol.dccp),
            offset=hdr_len // 4,
            cscov={
                'ccval': ccval,
                'cscov': cscov,
            },
            checksum=b'\x00\x00' if checksum is None else checksum,
            type=type_field,
            seq_reserved=seq_reserved,
            seq=seq,
            ack_reserved=ack_reserved,
            ack=ack,
            service_code=service_code,
            reset_code=reset_code,
            reset_data=reset_data,
            options=options_value,
            payload=payload,
        )

        self._checksum_pending = False
        if checksum is None and config.CHECKSUM_COMPUTE:
            if pseudo is None:
                self._checksum_pending = True
            else:
                from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
                from pcapkit.protocols.misc.checksum.ip_pseudo import pseudo_header  # isort: skip # pylint: disable=import-outside-toplevel

                octets = schema.pack()
                coverage = self._checksum_coverage(cscov, hdr_len, len(octets))
                # NOTE: A coverage reaching the end is written as CsCov 0, as Linux's
                # dccp_csum_outgoing did, so a computed checksum never covers past it.
                if cscov and coverage >= len(octets):
                    schema.cscov = {'ccval': ccval, 'cscov': 0}
                    octets, coverage = schema.pack(), len(octets)
                schema.checksum = compute_checksum(octets[:coverage],
                                                   prefix=pseudo_header(pseudo, len(octets)))
        return schema

    @classmethod
    def register_option(cls, code: 'Enum_Option', meth: 'str | tuple[OptionParser, OptionConstructor]') -> 'None':
        """Register an option parser.

        Args:
            code: DCCP option type.
            meth: Method name, or a ``(parser, constructor)`` pair of
                callables, to parse and construct the option; see
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
            warn(f'option {code} already registered, overwriting', RegistryWarning)
        cls.__option__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[12]':
        """Return an estimated length for the object."""
        return DCCP_MIN_HEADER_LEN  # type: ignore[return-value]

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.DCCP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_DCCP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'srcport': data.srcport,
            'dstport': data.dstport,
            'ccval': data.ccval,
            'cscov': data.cscov,
            'checksum': data.checksum,
            'reserved': data.reserved,
            'type': data.type,
            'x': data.x,
            'seq_reserved': data.get('seq_reserved', 0),
            'seq': data.seq,
            'ack_reserved': data.get('ack_reserved', 0),
            'ack': data.get('ack', 0),
            'service_code': data.get('service_code', 0),
            'reset_code': data.get('reset_code', Enum_ResetCode.Unspecified),
            'reset_data': data.get('reset_data', bytes(3)),
            'options': data.get('options'),
            'payload': cls._make_payload(data),
        }

    def _read_dccp_options(self) -> 'Option':
        """Read DCCP option list.

        Returns:
            Extracted DCCP options.

        """
        options = OrderedMultiDict()  # type: Option
        for schema in self.__header__.options:
            code = schema.type
            name = self._lookup_registry(self.__option__, code)

            if isinstance(name, str):
                meth = cast('OptionParser',
                            getattr(self, f'_read_opt_{name}', self._read_opt_unassigned))
            else:
                meth = name[0]
            options.add(code, meth(schema, options=options))
        return options

    def _make_dccp_options(self, options: 'list[Schema_Option | tuple[Enum_Option, dict[str, Any]] | bytes] | Option') -> 'tuple[list[Schema_Option | bytes], int]':  # pylint: disable=line-too-long
        """Make options for DCCP.

        Args:
            options: DCCP options

        Returns:
            Tuple of options and total length of options.

        Note:
            The options are emitted in the given order, Padding included, so
            that a parsed option list re-emits the same octets. Padding
            options are added after them only when the list does not end on a
            32-bit boundary (:rfc:`4340#section-5.8`).

        """
        options_list = []  # type: list[Schema_Option | bytes]
        if isinstance(options, list):
            for item in options:
                if isinstance(item, (bytes, Schema)):
                    options_list.append(item)
                else:
                    code, args = cast('tuple[Enum_Option, dict[str, Any]]', item)
                    options_list.append(self._option_maker(code)(code, **args))
        else:
            for code, option in options.items(multi=True):
                options_list.append(self._option_maker(code)(code, option))

        total_length = sum(len(item) if isinstance(item, bytes) else len(item.pack())
                           for item in options_list)
        if total_length % 4:
            pad_len = 4 - total_length % 4
            options_list.extend(self._make_opt_padding(Enum_Option.Padding)  # type: ignore[arg-type]
                                for _ in range(pad_len))
            total_length += pad_len
        return options_list, total_length

    @staticmethod
    def _checksum_coverage(cscov: 'int', hdr_len: 'int', length: 'int') -> 'int':
        """Octets the checksum covers, pseudo-header aside (:rfc:`4340#section-9.2`).

        Args:
            cscov: Checksum coverage.
            hdr_len: Header length.
            length: Length of the packet.

        Returns:
            ``length`` if ``cscov`` is zero; otherwise the header and the first
            ``(cscov - 1) * 4`` octets of the application data, which may run
            past ``length``.

        """
        if not cscov:
            return length
        return hdr_len + (cscov - 1) * 4

    def _read_opt_unassigned(self, schema: 'Schema_UnassignedOption', *, options: 'Option') -> 'Data_UnassignedOption':  # pylint: disable=unused-argument
        """Read DCCP unassigned option.

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_UnassignedOption(
            type=schema.type,
            length=schema.length,
            data=schema.data if schema.type > DCCP_SINGLE_OCTET_OPTION_MAX else b'',
        )

    def _read_opt_padding(self, schema: 'Schema_Padding', *, options: 'Option') -> 'Data_Padding':  # pylint: disable=unused-argument
        """Read DCCP padding option.

        Structure of DCCP padding option [:rfc:`4340#section-5.8.1`]:

        .. code-block:: text

           +--------+
           |00000000|
           +--------+
             Type=0

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_Padding(
            type=schema.type,
            length=1,
        )

    def _read_opt_mandatory(self, schema: 'Schema_Mandatory', *, options: 'Option') -> 'Data_Mandatory':  # pylint: disable=unused-argument
        """Read DCCP mandatory option.

        Structure of DCCP mandatory option [:rfc:`4340#section-5.8.2`]:

        .. code-block:: text

           +--------+
           |00000001|
           +--------+
             Type=1

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_Mandatory(
            type=schema.type,
            length=1,
        )

    def _read_opt_slow_receiver(self, schema: 'Schema_SlowReceiver', *, options: 'Option') -> 'Data_SlowReceiver':  # pylint: disable=unused-argument
        """Read DCCP slow receiver option.

        Structure of DCCP slow receiver option [:rfc:`4340#section-11.6`]:

        .. code-block:: text

           +--------+
           |00000010|
           +--------+
             Type=2

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_SlowReceiver(
            type=schema.type,
            length=1,
        )

    def _read_opt_change(self, schema: 'Schema_Change', *, options: 'Option') -> 'Data_Change':  # pylint: disable=unused-argument
        """Read DCCP Change L or Change R option.

        Structure of DCCP Change options [:rfc:`4340#section-6.1`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------
           |  Type  | Length |Feature#| Value(s) ...
           +--------+--------+--------+--------+--------
           Type=32 or 34

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_Change(
            type=schema.type,
            length=schema.length,
            feature=Enum_Feature.get(schema.feature) if schema.length > 2 else None,
            value=schema.value,
        )

    def _read_opt_confirm(self, schema: 'Schema_Confirm', *, options: 'Option') -> 'Data_Confirm':  # pylint: disable=unused-argument
        """Read DCCP Confirm L or Confirm R option.

        Structure of DCCP Confirm options [:rfc:`4340#section-6.2`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------
           |  Type  | Length |Feature#| Value(s) ...
           +--------+--------+--------+--------+--------
           Type=33 or 35

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_Confirm(
            type=schema.type,
            length=schema.length,
            feature=Enum_Feature.get(schema.feature) if schema.length > 2 else None,
            value=schema.value,
        )

    def _read_opt_init_cookie(self, schema: 'Schema_InitCookie', *, options: 'Option') -> 'Data_InitCookie':  # pylint: disable=unused-argument
        """Read DCCP init cookie option.

        Structure of DCCP init cookie option [:rfc:`4340#section-8.1.4`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------
           |00100100| Length |         Init Cookie Value   ...
           +--------+--------+--------+--------+--------+--------
            Type=36

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_InitCookie(
            type=schema.type,
            length=schema.length,
            cookie=schema.cookie,
        )

    def _read_opt_ndp_count(self, schema: 'Schema_NDPCount', *, options: 'Option') -> 'Data_NDPCount':  # pylint: disable=unused-argument
        """Read DCCP NDP count option.

        Structure of DCCP NDP count option [:rfc:`4340#section-7.7`]:

        .. code-block:: text

           +--------+--------+-------- ... --------+
           |00100101| Length |      NDP Count      |
           +--------+--------+-------- ... --------+
            Type=37  Len=3-8       (1-6 bytes)

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_NDPCount(
            type=schema.type,
            length=schema.length,
            count=schema.count,
        )

    def _read_opt_ack_vector(self, schema: 'Schema_AckVector', *, options: 'Option') -> 'Data_AckVector':  # pylint: disable=unused-argument
        """Read DCCP Ack Vector option.

        Structure of DCCP Ack Vector options [:rfc:`4340#section-11.4`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------
           |0010011?| Length |SSLLLLLL|SSLLLLLL|SSLLLLLL|  ...
           +--------+--------+--------+--------+--------+--------
           Type=38/39         \\___________ Vector ___________...

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_AckVector(
            type=schema.type,
            length=schema.length,
            nonce=schema.type - Enum_Option.Ack_Vector_Nonce_0,
            vector=tuple(Data_AckVectorRun(
                state=Enum_AckVectorState.get(octet >> 6),
                run_length=octet & 0x3F,
            ) for octet in schema.vector),
        )

    def _read_opt_data_dropped(self, schema: 'Schema_DataDropped', *, options: 'Option') -> 'Data_DataDropped':  # pylint: disable=unused-argument
        """Read DCCP data dropped option.

        Structure of DCCP data dropped option [:rfc:`4340#section-11.7`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------
           |00101000| Length | Block  | Block  | Block  |  ...
           +--------+--------+--------+--------+--------+--------
            Type=40          \\___________ Vector ___________ ...

        A block is a normal block, ``0`` then a 7-bit run length, or a drop
        block, ``1`` then a 3-bit drop code and a 4-bit run length.

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_DataDropped(
            type=schema.type,
            length=schema.length,
            vector=tuple(Data_DataDroppedBlock(
                dropped=True,
                code=Enum_DropCode.get((octet >> 4) & 0x07),
                run_length=octet & 0x0F,
            ) if octet & 0x80 else Data_DataDroppedBlock(
                dropped=False,
                code=None,
                run_length=octet,
            ) for octet in schema.vector),
        )

    def _read_opt_timestamp(self, schema: 'Schema_Timestamp', *, options: 'Option') -> 'Data_Timestamp':  # pylint: disable=unused-argument
        """Read DCCP timestamp option.

        Structure of DCCP timestamp option [:rfc:`4340#section-13.1`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00101001|00000110|          Timestamp Value          |
           +--------+--------+--------+--------+--------+--------+
            Type=41  Length=6

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_Timestamp(
            type=schema.type,
            length=schema.length,
            timestamp=schema.timestamp,
        )

    def _read_opt_timestamp_echo(self, schema: 'Schema_TimestampEcho', *, options: 'Option') -> 'Data_TimestampEcho':  # pylint: disable=unused-argument
        """Read DCCP timestamp echo option.

        Structure of DCCP timestamp echo option [:rfc:`4340#section-13.3`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00101010| Length |           Timestamp Echo          |
           +--------+--------+--------+--------+--------+--------+
            Type=42
           +--------+--------+------- ... -------+
           |   Elapsed Time  |  (6 or 8 octets)  |  (Length 8 or 10)
           +--------+--------+------- ... -------+

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_TimestampEcho(
            type=schema.type,
            length=schema.length,
            timestamp=schema.timestamp,
            elapsed=schema.elapsed if schema.length > 6 else None,
        )

    def _read_opt_elapsed_time(self, schema: 'Schema_ElapsedTime', *, options: 'Option') -> 'Data_ElapsedTime':  # pylint: disable=unused-argument
        """Read DCCP elapsed time option.

        Structure of DCCP elapsed time option [:rfc:`4340#section-13.2`]:

        .. code-block:: text

           +--------+--------+--------+--------+
           |00101011|00000100|  Elapsed Time   |
           +--------+--------+--------+--------+
            Type=43    Len=4
           +--------+--------+--------+--------+--------+--------+
           |00101011|00000110|            Elapsed Time           |
           +--------+--------+--------+--------+--------+--------+
            Type=43    Len=6

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_ElapsedTime(
            type=schema.type,
            length=schema.length,
            elapsed=schema.elapsed,
        )

    def _read_opt_data_checksum(self, schema: 'Schema_DataChecksum', *, options: 'Option') -> 'Data_DataChecksum':  # pylint: disable=unused-argument
        """Read DCCP data checksum option.

        Structure of DCCP data checksum option [:rfc:`4340#section-9.3`]:

        .. code-block:: text

           +--------+--------+--------+--------+--------+--------+
           |00101100|00000110|         CRC-32c                   |
           +--------+--------+--------+--------+--------+--------+
            Type=44  Length=6

        Args:
            schema: parsed option schema
            options: extracted DCCP options

        Returns:
            Parsed option data.

        """
        return Data_DataChecksum(
            type=schema.type,
            length=schema.length,
            checksum=schema.checksum,
        )

    def _make_opt_unassigned(self, code: 'Enum_Option', opt: 'Optional[Data_UnassignedOption]' = None, *,
                             data: 'bytes' = b'',
                             **kwargs: 'Any') -> 'Schema_UnassignedOption':
        """Make DCCP unassigned option.

        Args:
            code: option type
            opt: option data
            data: option data in :obj:`bytes`, none for a single-octet type
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``data`` is given for a single-octet type.

        """
        if opt is not None:
            data = opt.data

        if code <= DCCP_SINGLE_OCTET_OPTION_MAX:
            if data:
                raise ProtocolError(f'{self.alias}: [Opt {code}] single-octet option carries no data')
            return Schema_UnassignedOption(
                type=code,
                length=1,
            )
        return Schema_UnassignedOption(
            type=code,
            length=self._option_length(code, len(data) + 2),
            data=data,
        )

    def _make_opt_padding(self, code: 'Enum_Option', opt: 'Optional[Data_Padding]' = None,
                          **kwargs: 'Any') -> 'Schema_Padding':
        """Make DCCP padding option.

        Args:
            code: option type
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_Padding(
            type=code,
            length=1,
        )

    def _make_opt_mandatory(self, code: 'Enum_Option', opt: 'Optional[Data_Mandatory]' = None,
                            **kwargs: 'Any') -> 'Schema_Mandatory':
        """Make DCCP mandatory option.

        Args:
            code: option type
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_Mandatory(
            type=code,
            length=1,
        )

    def _make_opt_slow_receiver(self, code: 'Enum_Option', opt: 'Optional[Data_SlowReceiver]' = None,
                                **kwargs: 'Any') -> 'Schema_SlowReceiver':
        """Make DCCP slow receiver option.

        Args:
            code: option type
            opt: option data
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        return Schema_SlowReceiver(
            type=code,
            length=1,
        )

    def _make_opt_change(self, code: 'Enum_Option', opt: 'Optional[Data_Change]' = None, *,
                         feature: 'Optional[Enum_Feature | int]' = Enum_Feature.Congestion_Control_ID,
                         value: 'bytes' = b'',
                         **kwargs: 'Any') -> 'Schema_Change':
        """Make DCCP Change L or Change R option.

        Args:
            code: option type
            opt: option data
            feature: feature number, none if :data:`None`
            value: preference list or value, as on the wire
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``value`` is given without a ``feature``.

        """
        if opt is not None:
            feature, value = opt.feature, opt.value

        if feature is None:
            if value:
                raise ProtocolError(f'{self.alias}: [Opt {code}] value without a feature number')
            return Schema_Change(
                type=code,
                length=2,
                value=b'',
            )
        return Schema_Change(
            type=code,
            length=self._option_length(code, len(value) + 3),
            feature=feature,
            value=value,
        )

    def _make_opt_confirm(self, code: 'Enum_Option', opt: 'Optional[Data_Confirm]' = None, *,
                          feature: 'Optional[Enum_Feature | int]' = Enum_Feature.Congestion_Control_ID,
                          value: 'bytes' = b'',
                          **kwargs: 'Any') -> 'Schema_Confirm':
        """Make DCCP Confirm L or Confirm R option.

        Args:
            code: option type
            opt: option data
            feature: feature number, none if :data:`None`
            value: value, then the preference list for a server-priority
                feature, as on the wire
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``value`` is given without a ``feature``.

        """
        if opt is not None:
            feature, value = opt.feature, opt.value

        if feature is None:
            if value:
                raise ProtocolError(f'{self.alias}: [Opt {code}] value without a feature number')
            return Schema_Confirm(
                type=code,
                length=2,
                value=b'',
            )
        return Schema_Confirm(
            type=code,
            length=self._option_length(code, len(value) + 3),
            feature=feature,
            value=value,
        )

    def _make_opt_init_cookie(self, code: 'Enum_Option', opt: 'Optional[Data_InitCookie]' = None, *,
                              cookie: 'bytes' = b'',
                              **kwargs: 'Any') -> 'Schema_InitCookie':
        """Make DCCP init cookie option.

        Args:
            code: option type
            opt: option data
            cookie: cookie
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            cookie = opt.cookie

        return Schema_InitCookie(
            type=code,
            length=self._option_length(code, len(cookie) + 2),
            cookie=cookie,
        )

    def _make_opt_ndp_count(self, code: 'Enum_Option', opt: 'Optional[Data_NDPCount]' = None, *,
                            count: 'int' = 0,
                            **kwargs: 'Any') -> 'Schema_NDPCount':
        """Make DCCP NDP count option.

        Args:
            code: option type
            opt: option data, whose length is kept, even past the 8 octets
                :rfc:`4340#section-7.7` allows
            count: count of consecutive non-data packets, written in as few
                octets as hold it
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If ``count`` does not fit six octets.

        """
        if opt is not None:
            count, length = opt.count, opt.length
        else:
            length = max((count.bit_length() + 7) // 8, 1) + 2
            if length > 8:
                raise ProtocolError(f'{self.alias}: [Opt {code}] NDP count {count} does not fit 6 octets')

        return Schema_NDPCount(
            type=code,
            length=length,
            count=count,
        )

    def _make_opt_ack_vector(self, code: 'Enum_Option', opt: 'Optional[Data_AckVector]' = None, *,
                             vector: 'Iterable[Data_AckVectorRun | tuple[Enum_AckVectorState | int, int]]' = (),  # pylint: disable=line-too-long
                             **kwargs: 'Any') -> 'Schema_AckVector':
        """Make DCCP Ack Vector option.

        Args:
            code: option type, whose nonce the option carries
            opt: option data
            vector: runs, each a :class:`~pcapkit.protocols.data.transport.dccp.AckVectorRun`
                or a ``(state, run_length)`` pair
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If a state does not fit 2 bits or a run length
                6 bits.

        """
        if opt is not None:
            vector = opt.vector

        octets = bytearray()
        for run in vector:
            state, run_length = (run.state, run.run_length) if isinstance(run, Data_AckVectorRun) else run
            if not (0 <= state <= 0x03 and 0 <= run_length <= 0x3F):
                raise ProtocolError(f'{self.alias}: [Opt {code}] invalid Ack Vector run '
                                    f'({state}, {run_length})')
            octets.append((state << 6) | run_length)

        return Schema_AckVector(
            type=code,
            length=self._option_length(code, len(octets) + 2),
            vector=bytes(octets),
        )

    def _make_opt_data_dropped(self, code: 'Enum_Option', opt: 'Optional[Data_DataDropped]' = None, *,
                               vector: 'Iterable[Data_DataDroppedBlock | tuple[Optional[Enum_DropCode | int], int]]' = (),  # pylint: disable=line-too-long
                               **kwargs: 'Any') -> 'Schema_DataDropped':
        """Make DCCP data dropped option.

        Args:
            code: option type
            opt: option data
            vector: blocks, each a
                :class:`~pcapkit.protocols.data.transport.dccp.DataDroppedBlock`
                or a ``(code, run_length)`` pair, ``code`` being :data:`None`
                for a normal block
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        Raises:
            ProtocolError: If a run length does not fit 7 bits in a normal
                block, or a drop code 3 bits or a run length 4 bits in a drop
                block.

        """
        if opt is not None:
            vector = opt.vector

        octets = bytearray()
        for block in vector:
            drop, run_length = (block.code, block.run_length) if isinstance(block, Data_DataDroppedBlock) else block
            if drop is None and 0 <= run_length <= 0x7F:
                octets.append(run_length)
            elif drop is not None and 0 <= drop <= 0x07 and 0 <= run_length <= 0x0F:
                octets.append(0x80 | (drop << 4) | run_length)
            else:
                raise ProtocolError(f'{self.alias}: [Opt {code}] invalid Data Dropped block '
                                    f'({drop}, {run_length})')

        return Schema_DataDropped(
            type=code,
            length=self._option_length(code, len(octets) + 2),
            vector=bytes(octets),
        )

    def _make_opt_timestamp(self, code: 'Enum_Option', opt: 'Optional[Data_Timestamp]' = None, *,
                            timestamp: 'int' = 0,
                            **kwargs: 'Any') -> 'Schema_Timestamp':
        """Make DCCP timestamp option.

        Args:
            code: option type
            opt: option data
            timestamp: timestamp, in units of 10 microseconds
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            timestamp, length = opt.timestamp, opt.length
        else:
            length = 6

        return Schema_Timestamp(
            type=code,
            length=length,
            timestamp=timestamp,
        )

    def _make_opt_timestamp_echo(self, code: 'Enum_Option', opt: 'Optional[Data_TimestampEcho]' = None, *,
                                 timestamp: 'int' = 0,
                                 elapsed: 'Optional[int]' = None,
                                 **kwargs: 'Any') -> 'Schema_TimestampEcho':
        """Make DCCP timestamp echo option.

        Args:
            code: option type
            opt: option data
            timestamp: timestamp echoed
            elapsed: elapsed time, in hundredths of milliseconds, in two
                octets if it fits and four otherwise; none if :data:`None`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            timestamp, elapsed, length = opt.timestamp, opt.elapsed, opt.length
        elif elapsed is None:
            length = 6
        else:
            length = 8 if elapsed <= 0xFFFF else 10

        return Schema_TimestampEcho(
            type=code,
            length=length,
            timestamp=timestamp,
            elapsed=elapsed,
        )

    def _make_opt_elapsed_time(self, code: 'Enum_Option', opt: 'Optional[Data_ElapsedTime]' = None, *,
                               elapsed: 'int' = 0,
                               **kwargs: 'Any') -> 'Schema_ElapsedTime':
        """Make DCCP elapsed time option.

        Args:
            code: option type
            opt: option data
            elapsed: elapsed time, in hundredths of milliseconds, in two
                octets if it fits and four otherwise
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            elapsed, length = opt.elapsed, opt.length
        else:
            length = 4 if elapsed <= 0xFFFF else 6

        return Schema_ElapsedTime(
            type=code,
            length=length,
            elapsed=elapsed,
        )

    def _make_opt_data_checksum(self, code: 'Enum_Option', opt: 'Optional[Data_DataChecksum]' = None, *,
                                checksum: 'bytes' = bytes(4),
                                **kwargs: 'Any') -> 'Schema_DataChecksum':
        """Make DCCP data checksum option.

        Args:
            code: option type
            opt: option data
            checksum: CRC-32c of the application data, as on the wire
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed option schema.

        """
        if opt is not None:
            checksum = opt.checksum

        return Schema_DataChecksum(
            type=code,
            length=self._option_length(code, len(checksum) + 2),
            checksum=checksum,
        )

    def _verify_pseudo_checksum(self, pseudo: 'Optional[IP_Pseudo]') -> 'None':
        """Verify the checksum over the pseudo-header of the enclosing IP layer.

        That layer calls this once parsed, see
        :func:`~pcapkit.protocols.misc.checksum.ip_pseudo.verify_upper`. The
        checksum covers what the Checksum Coverage gives; one covering past the
        end of the packet is invalid (:rfc:`4340#section-9.2`).

        Args:
            pseudo: Pseudo-header, or :data:`None` if the IP layer gives none.

        Warns:
            ChecksumWarning: If the checksum or its coverage is invalid.

        """
        from pcapkit.corekit.checksum.internet import ChecksumStatus, _rebuilding, verify_checksum  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.utilities.exceptions import stacklevel  # isort: skip # pylint: disable=import-outside-toplevel
        from pcapkit.utilities.warnings import ChecksumWarning  # isort: skip # pylint: disable=import-outside-toplevel

        if pseudo is None:
            status = ChecksumStatus.NO_PSEUDO_HEADER
        else:
            length = pseudo.info.len
            coverage = self._checksum_coverage(self._info.cscov, self._info.hdr_len, length)
            if coverage <= length:
                status = verify_checksum(self.alias, self._data, self._info.checksum,
                                         length=coverage, prefix=pseudo.data)
            else:
                if not _rebuilding.get():
                    warn(f'{self.alias}: checksum coverage {self._info.cscov} runs past the '
                         f'{length} octets of the packet', ChecksumWarning, stacklevel=stacklevel())
                status = ChecksumStatus.INVALID
        self._info.__update__(checksum_status=status)

    def _option_maker(self, code: 'Enum_Option') -> 'OptionConstructor':
        """The constructor :attr:`__option__` holds for ``code``.

        Args:
            code: option type

        Returns:
            The ``_make_opt_*`` method named, or the callable registered.

        """
        name = self._lookup_registry(self.__option__, code)
        if isinstance(name, str):
            return cast('OptionConstructor', getattr(self, f'_make_opt_{name}', self._make_opt_unassigned))
        return name[1]

    def _option_length(self, code: 'Enum_Option', length: 'int') -> 'int':
        """Check an option length fits its octet.

        Args:
            code: option type
            length: option length

        Returns:
            ``length``.

        Raises:
            ProtocolError: If ``length`` exceeds 255.

        """
        if length > 0xFF:
            raise ProtocolError(f'{self.alias}: [Opt {code}] option length {length} exceeds 255')
        return length

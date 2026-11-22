# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""PPP - Point-to-Point Protocol
===================================

.. module:: pcapkit.protocols.link.ppp.protocol

:mod:`pcapkit.protocols.link.ppp.protocol` contains
:class:`~pcapkit.protocols.link.ppp.protocol.PPP` only,
which implements the extractor for the Point-to-Point Protocol
(PPP) [*]_ frame of :rfc:`1661`, in the HDLC-like framing of
:rfc:`1662`, whose structure is described as below:

.. table::

   ====== ===== ================ =========================================
   Octets Bits  Name             Description
   ====== ===== ================ =========================================
   0          0 ``ppp.address``  Address (``0xFF``, optional)
   ------ ----- ---------------- -----------------------------------------
   1          8 ``ppp.control``  Control (``0x03``, optional)
   ------ ----- ---------------- -----------------------------------------
   2         16 ``ppp.protocol`` Protocol (one octet when compressed)
   ====== ===== ================ =========================================

.. [*] https://en.wikipedia.org/wiki/Point-to-Point_Protocol

"""
import collections
from collections.abc import Mapping
from typing import TYPE_CHECKING

from pcapkit.const.ppp.protocol import Protocol as Enum_Protocol
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.ppp.data import PPP as Data_PPP
from pcapkit.protocols.link.ppp.data import ControlPacket as Data_ControlPacket
from pcapkit.protocols.link.ppp.schema import PPP as Schema_PPP
from pcapkit.protocols.link.ppp.schema import ControlPacket as Schema_ControlPacket
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, Callable, ClassVar, DefaultDict, Optional, Type, Union

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.link.ppp.schema import ControlHeader as Schema_ControlHeader
    from pcapkit.protocols.link.ppp.schema import ControlTest
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

    #: Parser of a control packet registered as a callable -- the protocol
    #: number and the packet in its layout, to the data model.
    ControlParser = Callable[[Enum_Protocol, Schema_ControlPacket], Data_ControlPacket]
    #: Constructor of a control packet registered as a callable -- the protocol
    #: number and a data model or a mapping of its fields, to the layout.
    ControlConstructor = Callable[[Enum_Protocol, Union[Data_ControlPacket, Mapping[str, Any]]],
                                  Schema_ControlPacket]

__all__ = ['PPP']


class PPP(Link[Data_PPP, Schema_PPP],
          schema=Schema_PPP, data=Data_PPP):
    """This class implements Point-to-Point Protocol.

    The frame is dispatched from :attr:`Frame.__proto__
    <pcapkit.protocols.misc.pcap.frame.protocol.Frame.__proto__>` and
    :attr:`PCAPNG.__proto__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__proto__>`
    at ``LINKTYPE_PPP`` and ``LINKTYPE_PPP_HDLC``, from :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>` at EtherType ``0x880B``, and
    as the payload of a PPPoE session and an L2TPv2 data message.

    The Address and Control fields are read where the frame opens with
    ``0xFF 0x03``, and the Protocol field is one octet where its first octet is
    odd, as Address-and-Control-Field-Compression and
    Protocol-Field-Compression leave them (:rfc:`1661#section-6`). Under
    ``LINKTYPE_PPP_HDLC`` a frame not opening with ``0xFF 0x03`` is Cisco HDLC
    (:rfc:`1547#section-4.3.1`), which is refused.

    A protocol number the
    :class:`~pcapkit.protocols.link.ppp.schema.ControlPacket` registry holds a
    layout for -- LCP, IPCP, IPv6CP, PAP and CHAP -- is read as a control
    packet at header level, its Code, Identifier and Length, and the rest of
    the frame is the next layer as
    :class:`~pcapkit.protocols.misc.raw.protocol.Raw`. Any other protocol
    number dispatches the next layer, through the protocols registered in the
    :attr:`self.__proto__ <pcapkit.protocols.link.ppp.protocol.PPP.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.ppp.protocol.Protocol.Internet_Protocol_version_4`
         - :class:`pcapkit.protocols.internet.ipv4.protocol.IPv4`
       * - :attr:`~pcapkit.const.ppp.protocol.Protocol.Internet_Protocol_version_6`
         - :class:`pcapkit.protocols.internet.ipv6.protocol.IPv6`

    .. versionadded:: 1.7.0

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.protocol.Protocol._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.protocol.Protocol._import_next_layer>`. Keyed by PPP
    #: protocol number rather than by EtherType, so this class keeps a registry
    #: of its own instead of sharing :attr:`Link.__proto__
    #: <pcapkit.protocols.link.link.Link.__proto__>`; an entry is registered with
    #: :func:`~pcapkit.foundation.registry.protocols.link.register_ppp`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
        {
            Enum_Protocol.Internet_Protocol_version_4: ModuleDescriptor('pcapkit.protocols.internet.ipv4.protocol', 'IPv4'),
            Enum_Protocol.Internet_Protocol_version_6: ModuleDescriptor('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
        },
    )  # type: DefaultDict[int | Enum_Protocol, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: The enum the protocol map is keyed by, and that a bare int is no key,
    #: as :attr:`Link.__proto_key__ <pcapkit.protocols.link.link.Link.__proto_key__>`
    #: describes.
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_Protocol, False)

    #: Protocol number to control packet method mapping, see :meth:`read` and
    #: :meth:`make`. A :obj:`str` value names the methods ``_read_control_${name}``
    #: and ``_make_control_${name}``, any other value is a ``(parser,
    #: constructor)`` pair; either works on the layout the
    #: :class:`~pcapkit.protocols.link.ppp.schema.ControlPacket` registry holds
    #: for the protocol number, and one with no layout there is carried as the
    #: next layer instead. An entry is registered with :meth:`register_control`
    #: and :func:`~pcapkit.foundation.registry.protocols.link.register_ppp_control`.
    __control__ = collections.defaultdict(
        lambda: 'header',
        {
            Enum_Protocol.Internet_Protocol_Control_Protocol: 'header',
            Enum_Protocol.IPv6_Control_Protocol: 'header',
            Enum_Protocol.Link_Control_Protocol: 'header',
            Enum_Protocol.Password_Authentication_Protocol: 'header',
            Enum_Protocol.Challenge_Handshake_Authentication_Protocol: 'header',
        },
    )  # type: DefaultDict[Enum_Protocol | int, str | tuple[ControlParser, ControlConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Point-to-Point Protocol"]':
        """Name of current protocol."""
        return 'Point-to-Point Protocol'

    @property
    def length(self) -> 'int':
        """Header length of current protocol, a control packet included."""
        info = self._info
        size = (0 if info.address is None else 2) + (1 if info.pfc else 2)
        if info.control_packet is not None:
            size += max(info.control_packet.length, 4)
        return size

    @property
    def protocol(self) -> 'Enum_Protocol':
        """Protocol number of next layer protocol."""
        return self._info.protocol

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, alias: 'Optional[int]' = None,
             **kwargs: 'Any') -> 'Data_PPP':  # pylint: disable=unused-argument
        """Read Point-to-Point Protocol.

        Structure of PPP frame [:rfc:`1661`][:rfc:`1662`]:

        .. code-block:: text

           +----------+----------+----------+-------------+---------+
           |   Flag   | Address  | Control  |  Protocol   | Padding |
           | 01111110 | 11111111 | 00000011 | 8/16 bits   |    *    |
           +----------+----------+----------+-------------+---------+

        The Flag sequence and the Frame Check Sequence are not captured.

        Args:
            length: Length of packet data.
            alias: Code the frame was dispatched under, as
                :class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` and
                :class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` pass
                the link type.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the frame does not open with the Address and
                Control fields under ``LINKTYPE_PPP_HDLC``, or a control
                packet's Length is below its fixed fields.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        # NOTE: LINKTYPE_PPP_HDLC carries Cisco HDLC too, opening with 0x0F or 0x8F,
        # which is not PPP and would misread as a compressed Protocol field.
        if alias == Enum_LinkType.PPP_HDLC and schema.address is None:
            raise ProtocolError(f'{self.alias}: no HDLC-like framing under LINKTYPE_PPP_HDLC')

        packet = schema.control_packet
        control_packet = None
        if packet is not None:
            if packet.length < 4 and getattr(schema, '__short_read__', None) is None:
                raise ProtocolError(f'{self.alias}: invalid control packet length: {packet.length}')
            parser, _ = self._lookup_control(schema.protocol)
            control_packet = parser(schema.protocol, packet)

        ppp = Data_PPP(
            address=schema.address,
            control=schema.control,
            protocol=schema.protocol,
            pfc=bool(schema.pfc & 0x01),
            control_packet=control_packet,
        )
        self._info = ppp  # NOTE: :attr:`length` reads the data model.

        # NOTE: A control packet ends the frame's dissection; what follows it is padding.
        proto = -1 if control_packet is not None else schema.protocol
        return self._decode_next_layer(ppp, proto, length - self.length)

    def make(self,
             protocol: 'Enum_Protocol | int' = Enum_Protocol.Internet_Protocol_version_4,
             acfc: 'bool' = False,
             pfc: 'bool' = False,
             control_packet: 'Optional[Data_ControlPacket | Mapping[str, Any]]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_PPP':  # pylint: disable=unused-argument
        """Make (construct) packet data.

        Args:
            protocol: Protocol field.
            acfc: Whether the Address and Control fields are left out, under
                Address-and-Control-Field-Compression.
            pfc: Whether the Protocol field is one octet, under
                Protocol-Field-Compression.
            control_packet: Control packet, given as its ``code``,
                ``identifier`` and ``data`` and optionally its ``length``, for a
                protocol number the
                :class:`~pcapkit.protocols.link.ppp.schema.ControlPacket`
                registry holds a layout for.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``protocol`` is a name, or does not fit its field;
                if its first octet is odd in two octets, or even in one, since
                the frame would read back with the other width; if
                ``control_packet`` is missing for a protocol number with a
                layout, or given for one without; if a field of it does not fit;
                or if, with ``acfc``, the frame would open with ``0xFF 0x03``.

        """
        protocol_ = self._make_index(protocol, Enum_Protocol, bits=8 if pfc else 16, name='protocol')
        value = int(protocol_)
        # NOTE: The parse picks the width from the first octet's low bit (RFC 1661 Section 6.5),
        # so a value whose first octet says otherwise would not read back.
        if pfc and not value & 0x01:
            raise ProtocolError(f'{self.alias}: compressed protocol must be odd: {value:#04x}')
        if not pfc and (value >> 8) & 0x01:
            raise ProtocolError(f'{self.alias}: protocol with an odd first octet reads as compressed: '
                                f'{value:#06x}')

        layout = Schema_ControlPacket.registry[protocol_]  # pylint: disable=unsubscriptable-object
        packet = None  # type: Optional[Schema_ControlPacket]
        cp_test = None  # type: Optional[ControlTest]
        if layout is None and control_packet is not None:
            raise ProtocolError(f'{self.alias}: protocol {protocol_!r} carries no control packet')
        if layout is not None:
            if control_packet is None:
                raise ProtocolError(f'{self.alias}: protocol {protocol_!r} needs a control packet')
            if not isinstance(control_packet, Mapping):
                raise ProtocolError(f'{self.alias}: invalid control packet: must be a mapping of its '
                                    f'fields, not {control_packet!r}')
            _, constructor = self._lookup_control(protocol_)
            packet = constructor(protocol_, control_packet)
            # NOTE: Every layout opens with Code, Identifier and Length, which the parse
            # matches forward to size the packet.
            head = bytes(packet)[:4].ljust(4, b'\x00')
            cp_test = {'code': head[0], 'identifier': head[1], 'length': int.from_bytes(head[2:4], 'big')}

        if acfc:
            head = self._make_pack(value, size=1 if pfc else 2) + bytes(packet if packet is not None else payload)
            if head[:2] == b'\xff\x03':
                raise ProtocolError(f'{self.alias}: frame without Address and Control fields '
                                    'opens with 0xFF 0x03')

        return Schema_PPP(
            test=0 if acfc else 0xFF03,
            address=None if acfc else 0xFF,
            control=None if acfc else 0x03,
            pfc=1 if pfc else 0,
            protocol=protocol_,
            cp_test=cp_test,
            control_packet=packet,
            payload=payload,
        )

    @classmethod
    def register(cls, code: 'Enum_Protocol', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class for a PPP protocol number.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: PPP protocol number
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Important:
            This overrides :meth:`Link.register
            <pcapkit.protocols.link.link.Link.register>` because
            :attr:`self.__proto__ <PPP.__proto__>` is keyed by PPP protocol
            number rather than by EtherType (:issue:`2511`).

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this protocol number is
                already registered and the incumbent differs from the
                replacement; the message names both. See :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the guard,
                and for the shipped descriptor a restore puts back (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'PPP protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def register_control(cls, code: 'Enum_Protocol', meth: 'str | tuple[ControlParser, ControlConstructor]') -> 'None':
        """Register a control packet parser.

        Args:
            code: PPP protocol number.
            meth: Method name, or a ``(parser, constructor)`` pair of
                callables, to parse and construct its control packets; see
                :attr:`__control__`.

        Warns:
            RegistryWarning: If a different entry is already registered for
                ``code``; it is overwritten. Handing back the entry already
                stored, or one equal to it, is a silent no-op, so an override
                can be undone.

        """
        incumbent = cls.__control__.get(code)
        if incumbent is not None and incumbent == meth:
            return
        if incumbent is not None:
            warn(f'PPP control protocol {code} already registered, overwriting', RegistryWarning)
        cls.__control__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types. ``LINKTYPE_PPP_HDLC`` (50) and EtherType ``0x880B``
            are dispatched here as well.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.PPP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_PPP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'protocol': data.protocol,
            'acfc': data.address is None,
            'pfc': data.pfc,
            'control_packet': data.control_packet,
            'payload': cls._make_payload(data),
        }

    def _lookup_control(self, protocol: 'Enum_Protocol') -> 'tuple[ControlParser, ControlConstructor]':
        """Look up the parser and constructor of a protocol number's control packets.

        Args:
            protocol: PPP protocol number

        Returns:
            What :attr:`__control__` holds for ``protocol``, as callables.

        Raises:
            ProtocolError: If :attr:`__control__` names a method the class does
                not have.

        """
        name = self._lookup_registry(self.__control__, protocol)
        if not isinstance(name, str):
            return name[0], name[1]
        parser = getattr(self, f'_read_control_{name}', None)
        constructor = getattr(self, f'_make_control_{name}', None)
        if parser is None or constructor is None:
            raise ProtocolError(f'{self.alias}: no control packet methods named {name!r}')
        return parser, constructor

    def _read_control_header(self, protocol: 'Enum_Protocol',  # pylint: disable=unused-argument
                             packet: 'Schema_ControlHeader') -> 'Data_ControlPacket':
        """Read a control packet at header level.

        Args:
            protocol: PPP protocol number
            packet: parsed control packet

        Returns:
            Its Code, Identifier, Length and data.

        """
        return Data_ControlPacket(
            code=packet.code,
            identifier=packet.identifier,
            length=packet.length,
            data=packet.data,
        )

    def _make_control_header(self, protocol: 'Enum_Protocol',
                             packet: 'Data_ControlPacket | Mapping[str, Any]') -> 'Schema_ControlPacket':
        """Make a control packet at header level.

        Args:
            protocol: PPP protocol number
            packet: Its ``code``, ``identifier`` and ``data``, and optionally its
                ``length``, by default that of the fixed fields and the data.

        Returns:
            The control packet, in the layout the
            :class:`~pcapkit.protocols.link.ppp.schema.ControlPacket` registry
            holds for ``protocol``.

        Raises:
            ProtocolError: If a field does not fit, or ``length`` is short of
                the fixed fields and the data.

        """
        data = packet.get('data', b'')
        if not isinstance(data, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid control packet data: {data!r}')
        data = bytes(data)
        code = self._make_uint(packet.get('code', 0), bits=8, name='control packet code')
        identifier = self._make_uint(packet.get('identifier', 0), bits=8, name='control packet identifier')
        length = packet.get('length')
        length = self._make_uint(4 + len(data) if length is None else length, bits=16,
                                 name='control packet length')
        # NOTE: A shorter Length would read back with the data split off or refused, unless a
        # rebuild of a cut packet carries it, which ``pack`` cuts back to the octets read (#2761).
        if length < 4 + len(data) and self.__short_read__ is None:
            raise ProtocolError(f'{self.alias}: control packet length {length} is short of '
                                f'{4 + len(data)} octet(s)')
        layout = Schema_ControlPacket.registry[protocol]  # pylint: disable=unsubscriptable-object
        return layout(code=code, identifier=identifier, length=length, data=data)

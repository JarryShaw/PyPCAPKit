# -*- coding: utf-8 -*-
"""IPX - Internetwork Packet Exchange
========================================

.. module:: pcapkit.protocols.internet.ipx.protocol

:mod:`pcapkit.protocols.internet.ipx.protocol` contains
:class:`~pcapkit.protocols.internet.ipx.protocol.IPX` only,
which implements the extractor for Internetwork Packet
Exchange (IPX) [*]_, whose structure is described
as below:

======= ========= ====================== =====================================
Octets      Bits        Name                    Description
======= ========= ====================== =====================================
  0           0   ``ipx.chksum``            Checksum
  2          16   ``ipx.len``               Packet Length (header included)
  4          32   ``ipx.count``             Transport Control (hop count)
  5          40   ``ipx.type``              Packet Type
  6          48   ``ipx.dst``               Destination Address
  18        144   ``ipx.src``               Source Address
======= ========= ====================== =====================================

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange

"""
import collections
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.ipx.packet import Packet as Enum_Packet
from pcapkit.const.ipx.socket import Socket as Enum_Socket
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.internet.ipx.data import IPX as Data_IPX
from pcapkit.protocols.internet.ipx.data import Address as Data_Address
from pcapkit.protocols.internet.ipx.schema import IPX as Schema_IPX
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import Any, ClassVar, DefaultDict, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['IPX']


class IPX(Internet[Data_IPX, Schema_IPX],
          schema=Schema_IPX, data=Data_IPX):
    """This class implements Internetwork Packet Exchange.

    .. versionchanged:: 1.5.0

       :meth:`~pcapkit.protocols.internet.internet.Internet.from_data`
       rebuilds a parsed packet rather than raising
       :exc:`struct.error` (:issue:`1315`), and the octets past the IPX Length
       field are kept as
       :attr:`~pcapkit.protocols.internet.ipx.schema.IPX.trailer`
       (:issue:`1433`).

       The payload is dissected by IPX Packet Type from a registry of its own,
       :attr:`__proto__`, rather than looked up as an IP protocol number
       (:issue:`2169`).

    .. versionchanged:: 1.6.0

       The ``type`` of :meth:`make` takes a member or an :class:`int` code,
       resolved with the enumeration's ``get``; a name, a :obj:`bool`, or a
       code the field cannot carry raises
       :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than
       resolving against an enumeration inferred from the caller's frame or
       writing a different value (:issue:`2594`).

       :meth:`make` raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`
       for a checksum that is not two octets, or an address that is not
       twelve, rather than padding or cutting it (:issue:`2676`).

    .. versionremoved:: 1.6.0

       The ``type_default``, ``type_namespace`` and ``type_reversed``
       arguments that went with the ``type`` of :meth:`make`; resolve a name
       with :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.internet.internet.Internet._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.internet.internet.Internet._import_next_layer>`. Keyed by
    #: IPX Packet Type, as in :class:`~pcapkit.const.ipx.packet.Packet`, rather
    #: than by IP protocol number, so this class keeps a registry of its own
    #: instead of sharing :attr:`Internet.__proto__
    #: <pcapkit.protocols.internet.internet.Internet.__proto__>` (:issue:`2169`).
    #: No IPX-native protocol is shipped, so the payload is
    #: :class:`~pcapkit.protocols.misc.raw.protocol.Raw` unless one is registered with
    #: :func:`~pcapkit.foundation.registry.protocols.internet.register_ipx`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by, declared as
    #: :attr:`Internet.__proto_key__ <pcapkit.protocols.internet.internet.Internet.__proto_key__>`
    #: is, so a ``code=`` key is checked as
    #: :func:`~pcapkit.foundation.registry.protocols.internet.register_ipx` checks its own.
    #: A bare :class:`int` is a valid key too, because the IPX Packet Type is a
    #: number in its own right (:issue:`2268`, :issue:`2511`).
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_Packet, True)

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internetwork Packet Exchange"]':
        """Name of corresponding protocol."""
        return 'Internetwork Packet Exchange'

    @property
    def length(self) -> 'Literal[30]':
        """Header length of corresponding protocol."""
        return 30

    @property
    def protocol(self) -> 'Enum_Packet':
        """IPX Packet Type of next layer protocol."""
        return self._info.type

    @property
    def src(self) -> 'str':
        """Source IPX address."""
        return self._info.src.addr

    @property
    def dst(self) -> 'str':
        """Destination IPX address."""
        return self._info.dst.addr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IPX':
        """Read Internetwork Packet Exchange.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        ipx = Data_IPX(
            chksum=schema.chksum,
            len=schema.len,
            count=schema.count,
            type=schema.type,
            dst=self._read_ipx_address(schema.dst),
            src=self._read_ipx_address(schema.src),
        )

        # NOTE: Octets captured past the Packet Length belong to this layer,
        # since its own length field is what leaves them out of the payload: an
        # Ethernet carrier hands the whole rest of its frame here, padding
        # included, and the rebuild keeps them as captured (#1433).
        if schema.trailer:
            ipx.__update__([
                ('trailer', schema.trailer),
            ])

        return self._decode_next_layer(ipx, ipx.type, ipx.len - 30)

    def make(self,
             chksum: 'bytes' = b'\x00\x00',
             count: 'int' = 0,
             type: 'Enum_Packet | int' = Enum_Packet.Unknown,
             total_length: 'Optional[int]' = None,
             dst: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
             src: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_IPX':
        """Make (construct) packet data.

        Args:
            chksum: Checksum, two octets.
            count: Transport Control (hop count).
            type: Packet Type.
            total_length: Packet length (header included); computed as ``30`` plus
                the payload length when not given.
            dst: Destination Address, twelve octets.
            src: Source Address, twelve octets.
            payload: Payload data.
            trailer: Octets after the packet, outside the Packet Length, such as
                link-layer padding; written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is a name, a :obj:`bool`, or a member
                or code that does not fit in one octet, ``chksum`` is not two
                octets, or ``dst`` or ``src`` is not twelve.

        .. versionchanged:: 1.5.0

           Takes ``total_length`` ahead of ``dst`` (:issue:`1315`), which
           shifts every later positional argument.

        """
        type_val = self._make_index(type, Enum_Packet, bits=8, name='packet type')
        if total_length is None:
            total_length = 30 + len(payload)

        return Schema_IPX(
            chksum=self._make_octets(chksum, size=2, name='checksum'),
            len=total_length,
            count=count,
            type=type_val,
            dst=self._make_octets(dst, size=12, name='destination address'),
            src=self._make_octets(src, size=12, name='source address'),
            payload=payload,
            trailer=trailer,
        )

    @classmethod
    def register(cls, code: 'Enum_Packet | int', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # pylint: disable=line-too-long
        r"""Register a new protocol class for an IPX Packet Type.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: IPX Packet Type, as in :class:`~pcapkit.const.ipx.packet.Packet`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Important:
            This overrides :meth:`Internet.register
            <pcapkit.protocols.internet.internet.Internet.register>` because
            :attr:`self.__proto__ <IPX.__proto__>` is keyed by IPX Packet Type
            rather than by IP protocol number (:issue:`2511`).

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this packet type is
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
            warn(f'packet type {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[30]':
        """Return an estimated length for the object."""
        return 30

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPX_in_IP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPX') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'chksum': data.chksum,
            'count': data.count,
            'type': data.type,
            'total_length': data.len,
            'dst': cls._make_ipx_address(data.dst),
            'src': cls._make_ipx_address(data.src),
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Packet Length (#1433).
            'trailer': data.get('trailer', b''),
        }

    def _next_exthdr_depth(self, proto: 'Optional[int]', extension: 'bool' = False) -> 'int':  # pylint: disable=unused-argument
        """Place the next layer in its chain of IPv6 extension headers.

        Arguments:
            proto: next layer IPX Packet Type
            extension: if the next layer is parsed as an extension header

        Returns:
            Always ``0``: an IPX Packet Type is not an IP protocol number, so it
            never names an IPv6 extension header (:issue:`2169`).

        """
        return 0

    def _read_ipx_address(self, addr: 'bytes') -> 'Data_Address':
        """Read IPX address field.

        Args:
            addr: IPX address data.

        Returns:
            Parsed IPX address field.

        """
        # Address Number
        _ntwk = ':'.join(textwrap.wrap(addr[:4].hex(), 2))

        # Node Number (MAC)
        _node = ':'.join(textwrap.wrap(addr[4:10].hex(), 2))
        _maca = '-'.join(textwrap.wrap(addr[4:10].hex(), 2))

        # Socket Number
        _sock = addr[10:12]

        # Whole Address
        _list = [_ntwk, _node, ':'.join(textwrap.wrap(_sock.hex(), 2))]
        _addr = ':'.join(_list)

        ipx_addr = Data_Address(
            network=_ntwk,
            node=_maca,
            socket=Enum_Socket.get(int.from_bytes(_sock, 'big', signed=False)),
            addr=_addr,
        )
        return ipx_addr

    @staticmethod
    def _make_ipx_address(addr: 'Data_Address') -> 'bytes':
        """Make IPX address field.

        Args:
            addr: Parsed IPX address field.

        Returns:
            The 12-octet IPX address: network number, node number and
            socket number.

        """
        return (bytes.fromhex(addr.network.replace(':', ''))
                + bytes.fromhex(addr.node.replace('-', ''))
                + int(addr.socket).to_bytes(2, 'big', signed=False))

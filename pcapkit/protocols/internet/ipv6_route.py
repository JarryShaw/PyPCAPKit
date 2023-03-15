# -*- coding: utf-8 -*-
"""IPv6-Route - Routing Header for IPv6
==========================================

:mod:`pcapkit.protocols.internet.ipv6_route` contains
:class:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route`
only, which implements extractor for Routing Header for IPv6
(IPv6-Route) [*]_, whose structure is described as below:

======= ========= ==================== ===============================
Octets      Bits        Name                    Description
======= ========= ==================== ===============================
  0           0   ``route.next``            Next Header
  1           8   ``route.length``          Header Extensive Length
  2          16   ``route.type``            Routing Type
  3          24   ``route.seg_left``        Segments Left
  4          32   ``route.data``            Type-Specific Data
======= ========= ==================== ===============================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet#Routing

"""
import collections
import ipaddress
import math
from typing import TYPE_CHECKING, cast, overload

from pcapkit.const.ipv6.routing import Routing as Enum_Routing
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ipv6_route import RPL as Data_RPL
from pcapkit.protocols.data.internet.ipv6_route import IPv6_Route as Data_IPv6_Route
from pcapkit.protocols.data.internet.ipv6_route import SourceRoute as Data_SourceRoute
from pcapkit.protocols.data.internet.ipv6_route import Type2 as Data_Type2
from pcapkit.protocols.data.internet.ipv6_route import UnknownType as Data_UnknownType
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.ipv6_route import RPL as Schema_RPL
from pcapkit.protocols.schema.internet.ipv6_route import IPv6_Route as Schema_IPv6_Route
from pcapkit.protocols.schema.internet.ipv6_route import SourceRoute as Schema_SourceRoute
from pcapkit.protocols.schema.internet.ipv6_route import Type2 as Schema_Type2
from pcapkit.protocols.schema.internet.ipv6_route import UnknownType as Schema_UnknownType
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import Protocol
    from pcapkit.protocols.schema.internet.ipv6_route import RoutingType as Schema_RoutingType

    TypeParser = Callable[['IPv6_Route', Enum_Routing, int, bytes], Data_IPv6_Route]
    TypeConstructor = Callable[['IPv6_Route', Enum_Routing, DefaultArg(Optional[Data_IPv6_Route]),
                                DefaultArg(Optional[Data_IPv6_Route]), KwArg(Any)], Schema_RoutingType]

__all__ = ['IPv6_Route']


class IPv6_Route(Internet[Data_IPv6_Route, Schema_IPv6_Route],
                 schema=Schema_IPv6_Route, data=Data_IPv6_Route):
    """This class implements Routing Header for IPv6.

    This class currently supports parsing of the following Routing Header for IPv6
    routing data types, which are registered in the
    :attr:`self.__routing__ <pcapkit.protocols.internet.ipv6_route.IPv6_Route.__routing__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Routing Code
         - Data Parser
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.Source_Route`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_src`
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.Type_2_Routing_Header`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_2`
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.RPL_Source_Route_Header`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Routing, str | tuple[TypeParser, TypeConstructor]]:
    #: Type code to method mapping. Method names are expected to be referred to
    #: the class by ``_read_data_type_${name}`` and/or ``_make_data_type_${name}``,
    #: and if such name not found, the value should then be a method that can
    #: parse the routing type by itself.
    __routing__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Routing.Source_Route: 'src',             # [RFC 5095] DEPRECATED
            Enum_Routing.Type_2_Routing_Header: '2',      # [RFC 6275]
            Enum_Routing.RPL_Source_Route_Header: 'rpl',  # [RFC 6554]
        },
    )  # type: DefaultDict[Enum_Routing | int, str | tuple[TypeParser, TypeConstructor]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Routing Header for IPv6"]':
        """Name of current protocol."""
        return 'Routing Header for IPv6'

    @property
    def alias(self) -> 'Literal["IPv6-Route"]':
        """Acronym of corresponding protocol."""
        return 'IPv6-Route'

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self) -> 'Protocol | NoReturn':
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self) -> 'Optional[str] | NoReturn':
        """Name of next layer protocol (if any).

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")
        return super().protocol

    @property
    def protochain(self) -> 'ProtoChain | NoReturn':
        """Protocol chain of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protochain'")
        return super().protochain

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, extension: 'bool' = False,  # pylint: disable=arguments-differ
             **kwargs: 'Any') -> 'Data_IPv6_Route':  # pylint: disable=unused-argument
        """Read Routing Header for IPv6.

        Structure of IPv6-Route header [:rfc:`8200`][:rfc:`5095`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                       type-specific data                      .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            extension: If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        dlen = schema.length - 4
        data = cast('bytes', schema.data)

        name = self.__routing__[schema.type]
        if isinstance(name, str):
            name = f'_read_data_type_{name.lower()}'
            meth = cast('TypeParser',
                            getattr(self, name, self._read_data_type_none))
        else:
            meth = name[0]
        ipv6_route = meth(self, schema.type, dlen, data)

        if extension:
            return ipv6_route
        return self._decode_next_layer(ipv6_route, schema.next, length - ipv6_route.length)

    def make(self,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             type: 'Enum_Routing | StdlibEnum | AenumEnum | str | int' = Enum_Routing.Source_Route,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             seg_left: 'int' = 0,
             data: 'bytes | Schema_RoutingType | dict[str, Any]' = b'\x00\x00\x00\x00',
             payload: 'Protocol | Schema | bytes' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6_Route':
        """Make (construct) packet data.

        Args:
            next: Next header type.
            next_default: Default value of next header type.
            next_namespace: Namespace of next header type.
            next_reversed: If the namespace of next header type is reversed.
            type: Routing type.
            type_default: Default value of routing type.
            type_namespace: Namespace of routing type.
            type_reversed: If the namespace of routing type is reversed.
            seg_left: Segments left.
            data: Routing data.
            payload: Payload of current instance.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,  # type: ignore[call-overload]
                                    reversed=next_reversed, pack=False)
        type_val = self._make_index(type, type_default, namespace=type_namespace,  # type: ignore[call-overload]
                                    reversed=type_reversed, pack=False)

        if isinstance(data, bytes):
            length = math.ceil((len(data) + 4) / 8)
            data_val = data.ljust(length * 8 - 4, b'\x00')  # type: bytes | Schema_RoutingType
        elif isinstance(data, dict):
            name = self.__routing__[type_val]
            if isinstance(name, str):
                name = f'_make_data_type_{name.lower()}'
                meth = cast('TypeConstructor',
                            getattr(self, name, self._make_data_type_none))
            else:
                meth = name[1]

            data_val = meth(self, type_val, **data)
            length = len(data_val.pack())
        elif isinstance(data, Schema):
            length = math.ceil((len(data.pack()) + 4) / 8)
            data_val = data
        else:
            raise ProtocolError(f'{self.alias}: invalid routing data type: {data.__class__}')

        return Schema_IPv6_Route(
            next=next_val,
            length=length,
            type=type_val,
            seg_left=seg_left,
            data=data_val,
            payload=payload,
        )

    @classmethod
    def register_routing(cls, code: 'Enum_Routing', meth: 'str | tuple[TypeParser, TypeConstructor]') -> 'None':
        """Register an routing data parser.

        Args:
            code: IPv6-Route data type code.
            meth: Method name or callable to parse and/or construct the data.

        """
        if code in cls.__routing__:
            warn(f'routing {code} already registered, overwriting', RegistryWarning)
        cls.__routing__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)  # type: ignore[arg-type]

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
        return Enum_TransType.IPv6_Route  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6_Route') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'next': data.next,
            'type': data.type,
            'seg_left': data.seg_left,
            'data': data,
            'payload': cls._make_payload(data),
        }

    def _read_data_type_none(self, type: 'Enum_Routing', length: 'int', data: 'bytes') -> 'Data_UnknownType':
        """Read IPv6-Route unknown type data.

        Structure of IPv6-Route unknown type data [:rfc:`8200`][:rfc:`5095`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                       type-specific data                      .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            type: routing type
            length: route data length
            data: route data

        Returns:
            Parsed route data.

        """
        schema = Schema_UnknownType.unpack(data, length)  # type: Schema_UnknownType
        self.__header__.data = schema

        header = self.__header__
        ipv6_route = Data_UnknownType(
            next=header.next,
            length=header.length,
            type=header.type,
            seg_left=header.seg_left,
            data=schema.data,
        )
        return ipv6_route

    def _read_data_type_src(self, type: 'Enum_Routing', length: 'int', data: 'bytes') -> 'Data_SourceRoute':
        """Read IPv6-Route Source Route data.

        Structure of IPv6-Route Source Route data [:rfc:`5095`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  | Routing Type=0| Segments Left |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            Reserved                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                           Address[1]                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                           Address[2]                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           .                               .                               .
           .                               .                               .
           .                               .                               .
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                           Address[n]                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            type: routing type
            length: route data length
            data: route data

        Returns:
            Parsed route data.

        """
        if (length - 8) % 16 != 0:
            raise ProtocolError(f'{self.alias} [TypeNo {type}]: invalid format')

        schema = Schema_SourceRoute.unpack(data, length)  # type: Schema_SourceRoute
        self.__header__.data = schema

        header = self.__header__
        ipv6_route = Data_SourceRoute(
            next=header.next,
            length=header.length,
            type=header.type,
            seg_left=header.seg_left,
            ip=tuple(schema.ip),
        )
        return ipv6_route

    def _read_data_type_2(self, type: 'Enum_Routing', length: 'int', data: 'bytes') -> 'Data_Type2':
        """Read IPv6-Route Type 2 data.

        Structure of IPv6-Route Type 2 data [:rfc:`6275`]:

        .. code-block:: text

           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  | Hdr Ext Len=2 | Routing Type=2|Segments Left=1|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                            Reserved                           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                         Home Address                          +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            type: routing type
            length: route data length
            data: route data

        Returns:
            Parsed route data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``20``.

        """
        if length != 20:
            raise ProtocolError(f'{self.alias}: [TypeNo {type}] invalid format')

        schema = Schema_Type2.unpack(data, length)  # type: Schema_Type2
        self.__header__.data = schema

        header = self.__header__
        ipv6_route = Data_Type2(
            next=header.next,
            length=header.length,
            type=header.type,
            seg_left=header.seg_left,
            ip=schema.ip,
        )
        return ipv6_route

    def _read_data_type_rpl(self, type: 'Enum_Routing', length: 'int', data: 'bytes') -> 'Data_RPL':
        """Read IPv6-Route RPL Source data.

        Structure of IPv6-Route RPL Source data [:rfc:`6554`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  Next Header  |  Hdr Ext Len  | Routing Type  | Segments Left |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | CmprI | CmprE |  Pad  |               Reserved                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           .                                                               .
           .                        Addresses[1..n]                        .
           .                                                               .
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: route data length

        Returns:
            Parsed route data.

        """
        if length % 16 != 0:
            raise ProtocolError(f'{self.alias}: [TypeNo {type}] invalid format')

        schema = Schema_RPL.unpack(data, length)  # type: Schema_RPL
        self.__header__.data = schema
        header = self.__header__

        ilen = 16 - schema.cmpr_i
        elen = 16 - schema.cmpr_e
        addr = []  # type: list[IPv6Address | bytes]
        counter = 0

        # Addresses[1..n-1]
        for _ in range(header.length - 8 - schema.pad['pad_len'] - elen):
            buf = data[counter:counter + ilen]
            try:
                ip = cast('IPv6Address | bytes', ipaddress.ip_address(buf))
            except ValueError:
                ip = buf
            addr.append(ip)
            counter += ilen

        # Addresses[n]
        buf = data[counter:counter + elen]
        try:
            ip = cast('IPv6Address | bytes', ipaddress.ip_address(buf))
        except ValueError:
            ip = buf
        addr.append(ip)

        schema.ip = addr
        ipv6_route = Data_RPL(
            next=header.next,
            length=header.length,
            type=header.type,
            seg_left=header.seg_left,
            cmpr_i=schema.cmpr_i,
            cmpr_e=schema.cmpr_e,
            pad=schema.pad['pad_len'],
            ip=tuple(addr),
        )
        return ipv6_route

    def _make_data_type_none(self, type: 'Enum_Routing', route: 'Optional[Data_UnknownType]' = None, *,
                             data: 'bytes' = b'\x00\x00\x00\x00',
                             **kwargs: 'Any') -> 'Schema_UnknownType':
        """Make IPv6-Route unknown type data.

        Args:
            type: routing type
            route: route data
            data: raw route data as :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

        """
        if route is not None:
            data = route.data

        pad_len = 8 - (len(data) + 4) % 8
        if pad_len:
            data += bytes(pad_len)

        return Schema_UnknownType(
            data=data,
        )

    def _make_data_type_src(self, type: 'Enum_Routing', route: 'Optional[Data_SourceRoute]' = None, *,
                            ip: 'Optional[list[IPv6Address | str | bytes | int]]' = None,
                            **kwargs: 'Any') -> 'Schema_SourceRoute':
        """Make IPv6-Route Source Route data.

        Args:
            type: routing type
            route: route data
            ip: list of IPv6 addresses
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

        """
        if route is not None:
            ip = cast('list[IPv6Address | str | bytes | int]', route.ip)
        else:
            ip = [] if ip is None else ip

        return Schema_SourceRoute(
            ip=ip,
        )

    def _make_data_type_2(self, type: 'Enum_Routing', route: 'Optional[Data_Type2]' = None, *,
                          ip: 'IPv6Address | str | bytes | int' = '::',
                          **kwargs: 'Any') -> 'Schema_Type2':
        """Make IPv6-Route Type 2 data.

        Args:
            type: routing type
            route: route data
            ip: home address
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

        """
        if route is not None:
            ip = cast('IPv6Address | str | bytes | int', route.ip)

        return Schema_Type2(
            ip=ip,
        )

    def _make_data_type_rpl(self, type: 'Enum_Routing', route: 'Optional[Data_RPL]' = None, *,
                            ip: 'Optional[list[IPv6Address | str | bytes | int]]' = None,
                            **kwargs: 'Any') -> 'Schema_RPL':
        """Make IPv6-Route RPL Source data.

        Args:
            type: routing type
            route: route data
            cmpr_i: compression for intermediate nodes
            cmpr_e: compression for the last node
            pad: padding length
            ip: list of IPv6 addresses
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

        Notes:
            We did not implement the SRH prefix compression for simplicity.
            The ``ip`` argument is expected to be a list of IPv6 addresses,
            and the method will not perform any compression.

        """
        if route is not None:
            cmpr_i = route.cmpr_i
            cmpr_e = route.cmpr_e
            pad = route.pad
            ip_val = [
                addr if isinstance(addr, bytes) else addr.packed for addr in route.ip
            ]
        else:
            ip = [] if ip is None else ip

            pad = 0
            cmpr_i = 0
            cmpr_e = 0
            ip_val = [
                cast('IPv6Address', ipaddress.ip_address(addr)).packed for addr in ip
            ]

        return Schema_RPL(
            cmpr_i=cmpr_i,
            cmpr_e=cmpr_e,
            pad={
                'pad_len': pad,
            },
            ip=ip_val,
        )

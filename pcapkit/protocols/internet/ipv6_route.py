# -*- coding: utf-8 -*-
"""IPv6-Route - Routing Header for IPv6
==========================================

.. module:: pcapkit.protocols.internet.ipv6_route

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
import os.path as os_path
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
from pcapkit.protocols.schema.internet.ipv6_route import (ipv6_route_data_length,
                                                          ipv6_route_header_length)
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import IO, Any, Callable, DefaultDict, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.internet.ipv6_route import RoutingType as Schema_RoutingType

    TypeParser = Callable[[Schema_RoutingType, NamedArg(Schema_IPv6_Route, 'header')], Data_IPv6_Route]
    TypeConstructor = Callable[[Enum_Routing, DefaultArg(Optional[Data_IPv6_Route]),
                                NamedArg(Optional[IPv6Address], 'dst'), KwArg(Any)], Schema_RoutingType]

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
         - Data Constructor
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.Source_Route`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_src`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_data_type_src`
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.Type_2_Routing_Header`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_2`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_data_type_2`
       * - :attr:`~pcapkit.const.ipv6.routing.Routing.RPL_Source_Route_Header`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._read_data_type_rpl`
         - :meth:`~pcapkit.protocols.internet.ipv6_route.IPv6_Route._make_data_type_rpl`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Routing, str | tuple[TypeParser, TypeConstructor]]: Type
    #: code to method mapping. Method names are expected to be referred to
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

        name = self._lookup_registry(self.__routing__, schema.type)
        if isinstance(name, str):
            name = f'_read_data_type_{name.lower()}'
            meth = cast('TypeParser',
                            getattr(self, name, self._read_data_type_none))
        else:
            meth = name[0]
        ipv6_route = meth(schema.data, header=schema)

        if extension:
            return ipv6_route
        return self._decode_next_layer(ipv6_route, schema.next, length - ipv6_route.length)

    @staticmethod
    def _make_hdr_ext_len(data_length: 'int') -> 'int':
        """Compute ``Hdr Ext Len`` for a type-specific data payload of ``data_length`` octets.

        Per :rfc:`8200#section-4.4`, ``Hdr Ext Len`` is *"the length of the
        Routing header in 8-octet units, not including the first 8
        octets"*. The routing header's fixed part (``next``/``length``/
        ``type``/``seg_left``) is 4 octets, so the total on-the-wire header
        is ``4 + data_length`` octets; equating that to ``8 + 8 *
        hdr_ext_len`` and solving gives ``hdr_ext_len = (data_length - 4) /
        8``. ``ipv6_route_data_length`` in
        :mod:`pcapkit.protocols.schema.internet.ipv6_route` is this
        expression's inverse, used on the read side.

        This is the *only* place ``Hdr Ext Len`` is computed on the write
        side: :meth:`make` used to compute it twice, once per branch, in two
        different (and both wrong) units -- that duplication, not either
        expression individually, is what let the two drift and is why there
        is one helper now rather than two call sites. Do NOT "simplify" the
        ``- 4`` / ``/ 8`` away: the units either side of it differ (octets
        vs. 8-octet units), and dropping the offset silently reinterprets
        the field, which is exactly the defect #487 fixed (compare the
        ``* 8`` unit bug behind #483 in the scapy adapter).

        Args:
            data_length: packed length, in octets, of the type-specific data
                (i.e. ``len(data_val.pack())`` for a :class:`~pcapkit.protocols.
                schema.schema.Schema`-based payload, or the padded raw
                :obj:`bytes` length for the unknown/raw-bytes case).

        Returns:
            The ``Hdr Ext Len`` field value.

        """
        return math.ceil(max(0, data_length - 4) / 8)

    def make(self,
             dst: 'Optional[IPv6Address | str | int| bytes]' = None,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             type: 'Enum_Routing | StdlibEnum | AenumEnum | str | int' = Enum_Routing.Source_Route,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             seg_left: 'int' = 0,
             data: 'bytes | Data_IPv6_Route | Schema_RoutingType | dict[str, Any]' = b'\x00\x00\x00\x00',
             payload: 'Protocol | Schema | bytes' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6_Route':
        """Make (construct) packet data.

        Args:
            dst: Destination address.
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
        next_val = cast('Enum_TransType',
                        self._make_index(next, next_default, namespace=next_namespace,
                                         reversed=next_reversed, pack=False))
        type_val = cast('Enum_Routing',
                        self._make_index(type, type_default, namespace=type_namespace,
                                         reversed=type_reversed, pack=False))

        if isinstance(data, bytes):
            # ``data`` here *is* the type-specific data (no per-type
            # constructor involved), so pad it out to the next octet count
            # ``_make_hdr_ext_len`` can express exactly, then use that same
            # helper -- rather than a third, separate expression -- to derive
            # ``Hdr Ext Len`` from the now-aligned length.
            length = self._make_hdr_ext_len(len(data))
            data_val = data.ljust(ipv6_route_data_length(length), b'\x00')  # type: bytes | Schema_RoutingType
        elif isinstance(data, (dict, Data_IPv6_Route)):
            name = self._lookup_registry(self.__routing__, type_val)
            if isinstance(name, str):
                name = f'_make_data_type_{name.lower()}'
                meth = cast('TypeConstructor',
                            getattr(self, name, self._make_data_type_none))
            else:
                meth = name[1]

            dst_val = cast('IPv6Address', ipaddress.ip_address(dst)) if dst is not None else None
            if isinstance(data, dict):
                data_val = meth(type_val, dst=dst_val, **data)
            else:
                data_val = meth(type_val, data, dst=dst_val)
            length = self._make_hdr_ext_len(len(data_val.pack()))
        elif isinstance(data, Schema):
            length = self._make_hdr_ext_len(len(data.pack()))
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
                      extension: 'bool' = ..., src_ip: 'Optional[IPv6Address]'= ...,
                      dst_ip: 'Optional[IPv6Address]'= ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            extension: If the protocol is used as an IPv6 extension header.
            src_ip: source IP address
            dst_ip: destination IP address
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`self.make <IPv6_Route.make>`.

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

    def _read_data_type_none(self, schema: 'Schema_UnknownType', *, header: 'Schema_IPv6_Route') -> 'Data_UnknownType':
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
            schema: parsed routing data schema
            header: parsed IPv6-Route header schema

        Returns:
            Parsed route data.

        """
        ipv6_route = Data_UnknownType(
            next=header.next,
            length=ipv6_route_header_length(header.length),
            type=header.type,
            seg_left=header.seg_left,
            data=schema.data,
        )
        return ipv6_route

    def _read_data_type_src(self, schema: 'Schema_SourceRoute', *, header: 'Schema_IPv6_Route') -> 'Data_SourceRoute':
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
            schema: parsed routing data schema
            header: parsed IPv6-Route header schema

        Returns:
            Parsed route data.

        """
        # ``header.length`` is ``Hdr Ext Len``, in 8-octet units (:rfc:`8200
        # #section-4.4`), not octets -- each 16-octet address costs 2 of
        # those units, so a well-formed Source Route header always carries
        # an even ``Hdr Ext Len``. The previous ``(header.length - 8) % 16``
        # check assumed ``header.length`` was already a total octet count,
        # which is never true of this field; see #487.
        if header.length % 2 != 0:
            raise ProtocolError(f'{self.alias}: [TypeNo {header.type}] invalid format')

        ipv6_route = Data_SourceRoute(
            next=header.next,
            length=ipv6_route_header_length(header.length),
            type=header.type,
            seg_left=header.seg_left,
            ip=tuple(schema.ip),
        )
        return ipv6_route

    def _read_data_type_2(self, schema: 'Schema_Type2', *, header: 'Schema_IPv6_Route') -> 'Data_Type2':
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
            schema: parsed routing data schema
            header: parsed IPv6-Route header schema

        Returns:
            Parsed route data.

        Raises:
            ProtocolError: If ``Hdr Ext Len`` is **NOT** ``2``.

        """
        # A Type 2 Routing header is fixed at 24 octets total (4 fixed + 4
        # reserved + 16-octet home address), so its ``Hdr Ext Len`` -- in
        # 8-octet units, not octets (:rfc:`8200#section-4.4`) -- is always
        # ``2``; a literal ``24`` here could never match. See #487.
        if header.length != 2:
            raise ProtocolError(f'{self.alias}: [TypeNo {header.type}] invalid format')

        ipv6_route = Data_Type2(
            next=header.next,
            length=ipv6_route_header_length(header.length),
            type=header.type,
            seg_left=header.seg_left,
            ip=schema.ip,
        )
        return ipv6_route

    def _read_data_type_rpl(self, schema: 'Schema_RPL', *, header: 'Schema_IPv6_Route') -> 'Data_RPL':
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
            schema: parsed routing data schema
            header: parsed IPv6-Route header schema

        Returns:
            Parsed route data.

        """
        # NOTE: this guard has the same surface shape as the Source Route and
        # Type 2 unit confusion #487 fixed above -- ``header.length`` is
        # ``Hdr Ext Len`` in 8-octet units, not octets, and ``% 16`` reads
        # like a leftover assumption that it was already a total octet
        # count. It is left as-is here: RPL addresses are variable-length
        # (compressed by ``cmpr_i``/``cmpr_e``), so a fixed ``% 16`` bound is
        # not obviously the right invariant even under correct units, and
        # nothing here has been checked against a real RPL capture. Flagged
        # for follow-up rather than guessed at. (The round trip through
        # ``RPL.post_process`` this note used to say was broken -- it
        # treated a ``make``-built ``list[bytes]`` as ``bytes`` and raised
        # on pack -- was fixed by #556; that no longer blocks validating a
        # replacement here, but the replacement itself is still unwritten.)
        if header.length % 16 != 0:
            raise ProtocolError(f'{self.alias}: [TypeNo {header.type}] invalid format')

        ipv6_route = Data_RPL(
            next=header.next,
            length=ipv6_route_header_length(header.length),
            type=header.type,
            seg_left=header.seg_left,
            cmpr_i=schema.cmpr_i,
            cmpr_e=schema.cmpr_e,
            pad=schema.pad['pad_len'],
            ip=tuple(schema.ip),
        )
        return ipv6_route

    def _make_data_type_none(self, type: 'Enum_Routing', route: 'Optional[Data_UnknownType]' = None, *,
                             dst: 'Optional[IPv6Address]' = None,
                             data: 'bytes' = b'\x00\x00\x00\x00',
                             **kwargs: 'Any') -> 'Schema_UnknownType':
        """Make IPv6-Route unknown type data.

        Args:
            type: routing type
            route: route data
            dst: destination IPv6 address
            data: raw route data as :obj:`bytes`
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

        """
        if route is not None:
            data = route.data

        pad_len = (8 - (len(data) + 4) % 8) % 8
        if pad_len:
            data += bytes(pad_len)

        return Schema_UnknownType(
            data=data,
        )

    def _make_data_type_src(self, type: 'Enum_Routing', route: 'Optional[Data_SourceRoute]' = None, *,
                            dst: 'Optional[IPv6Address]' = None,
                            ip: 'Optional[list[IPv6Address | str | bytes | int]]' = None,
                            **kwargs: 'Any') -> 'Schema_SourceRoute':
        """Make IPv6-Route Source Route data.

        Args:
            type: routing type
            route: route data
            dst: destination IPv6 address
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
                          dst: 'Optional[IPv6Address]' = None,
                          ip: 'IPv6Address | str | bytes | int' = '::',
                          **kwargs: 'Any') -> 'Schema_Type2':
        """Make IPv6-Route Type 2 data.

        Args:
            type: routing type
            route: route data
            dst: destination IPv6 address
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
                            dst: 'Optional[IPv6Address]' = None,
                            ip: 'Optional[list[IPv6Address | str | bytes | int]]' = None,
                            **kwargs: 'Any') -> 'Schema_RPL':
        """Make IPv6-Route RPL Source data.

        Args:
            type: routing type
            route: route data
            dst: destination IPv6 address
            ip: list of IPv6 addresses
            **kwargs: arbitrary keyword arguments

        Returns:
            Constructed route data schema.

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

            if dst is None:
                pad = 0
                cmpr_i = 0
                cmpr_e = 0
                ip_val = [
                    cast('IPv6Address', ipaddress.ip_address(addr)).packed for addr in ip
                ]
            else:
                test_list = [dst.packed]  # type: list[bytes]
                for item in ip[:-1]:
                    if isinstance(item, bytes):
                        test_list.append(item)
                    else:
                        test_list.append(cast('IPv6Address', ipaddress.ip_address(item)).packed)
                prefix_i = os_path.commonprefix(test_list)
                cmpr_i = len(prefix_i)

                test_list = [dst.packed]
                if isinstance(ip[-1], bytes):
                    test_list.append(ip[-1])
                else:
                    test_list.append(cast('IPv6Address', ipaddress.ip_address(ip[-1])).packed)
                prefix_e = os_path.commonprefix(test_list)
                cmpr_e = len(prefix_e)

                pad = 8 - ((len(ip) - 1) * (16 - cmpr_i) + (16 - cmpr_e)) % 8

                ip_val = []
                for item in ip[:-1]:
                    if isinstance(item, bytes):
                        ip_val.append(item[cmpr_i:])
                    else:
                        ip_val.append(cast('IPv6Address', ipaddress.ip_address(item)).packed[cmpr_i:])
                if isinstance(ip[-1], bytes):
                    ip_val.append(ip[-1][cmpr_e:])
                else:
                    ip_val.append(cast('IPv6Address', ipaddress.ip_address(ip[-1])).packed[cmpr_e:])

        return Schema_RPL(
            cmpr_i=cmpr_i,
            cmpr_e=cmpr_e,
            pad={
                'pad_len': pad,
            },
            addresses=ip_val,
        )

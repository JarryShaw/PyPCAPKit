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
from typing import TYPE_CHECKING, overload

from pcapkit.const.ipv6.routing import Routing as RegType_Routing
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.protocols.data.internet.ipv6_route import RPL as DataType_RPL
from pcapkit.protocols.data.internet.ipv6_route import IPv6_Route as DataType_IPv6_Route
from pcapkit.protocols.data.internet.ipv6_route import SourceRoute as DataType_SourceRoute
from pcapkit.protocols.data.internet.ipv6_route import Type2 as DataType_Type2
from pcapkit.protocols.data.internet.ipv6_route import UnknownType as DataType_UnknownType
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, BinaryIO, Callable, DefaultDict, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.corekit.protochain import ProtoChain
    from pcapkit.protocols.data.internet.ipv6_route import RoutingType as DataType_RoutingType
    from pcapkit.protocols.protocol import Protocol

    TypeParser = Callable[['IPv6_Route', int], DataType_RoutingType]

__all__ = ['IPv6_Route']


class IPv6_Route(Internet[DataType_IPv6_Route]):
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

    #: DefaultDict[RegType_Routing, str | TypeParser]: Type code to method
    #: mapping. Method names are expected to be referred to the class by
    #: ``_read_data_type_${name}``, and if such name not found, the value should
    #: then be a method that can parse the routing type by itself.
    __routing__ = collections.defaultdict(
        lambda: 'none',
        {
            RegType_Routing.Source_Route: 'src',             # [RFC 5095] DEPRECATED
            RegType_Routing.Type_2_Routing_Header: '2',      # [RFC 6275]
            RegType_Routing.RPL_Source_Route_Header: 'rpl',  # [RFC 6554]
        },
    )  # type: DefaultDict[int, str | TypeParser]

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
             **kwargs: 'Any') -> 'DataType_IPv6_Route':  # pylint: disable=unused-argument
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

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_unpack(1)
        _left = self._read_unpack(1)

        ipv6_route = DataType_IPv6_Route(
            next=_next,
            length=(_hlen + 1) * 8,
            type=RegType_Routing.get(_type),
            seg_left=_left,
        )

        _dlen = _hlen * 8 - 4
        if _dlen:
            _name = self.__routing__[ipv6_route.type]  # type: str | TypeParser
            if isinstance(_name, str):
                _name = f'_read_data_type_{_name.lower()}'
                _meth = getattr(self, _name, self._read_data_type_none)  # type: Callable[[int], DataType_RoutingType]
                _data = _meth(_dlen)
            else:
                _data = _name(self, _dlen)
            ipv6_route.__update__(**_data)

        if extension:
            return ipv6_route
        return self._decode_next_layer(ipv6_route, _next, length - ipv6_route.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def register_routing(cls, code: 'RegType_Routing', meth: 'str | TypeParser') -> 'None':
        """Register an routing data parser.

        Args:
            code: IPv6-Route data type code.
            meth: Method name or callable to parse the data.

        """
        cls.__routing__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    @overload
    def __post_init__(self, file: 'BinaryIO', length: 'Optional[int]' = ..., *,  # pylint: disable=arguments-differ
                      extension: 'bool' = ..., **kwargs: 'Any') -> 'None': ...

    @overload
    def __post_init__(self, **kwargs: 'Any') -> 'None': ...  # pylint: disable=arguments-differ

    def __post_init__(self, file: 'Optional[BinaryIO]' = None, length: 'Optional[int]' = None, *,  # pylint: disable=arguments-differ
                      extension: 'bool' = False, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.

        Keyword Args:
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
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.IPv6_Route  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_data_type_none(self, length: 'int') -> 'DataType_UnknownType':
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
            length: route data length

        Returns:
            Parsed route data.

        """
        _data = self._read_fileng(length)

        data = DataType_UnknownType(
            data=_data,
        )

        return data

    def _read_data_type_src(self, length: 'int') -> 'DataType_SourceRoute':
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
            length: route data length

        Returns:
            Parsed route data.

        """
        _resv = self._read_fileng(4)
        _addr = []  # type: list[IPv6Address]
        for _ in range((length - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))  # type: ignore[arg-type]

        data = DataType_SourceRoute(
            ip=tuple(_addr),
        )

        return data

    def _read_data_type_2(self, length: 'int') -> 'DataType_Type2':
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
            length: route data length

        Returns:
            Parsed route data.

        Raises:
            ProtocolError: If ``length`` is **NOT** ``20``.

        """
        if length != 20:
            raise ProtocolError(f'{self.alias}: [TypeNo 2] invalid format')

        _resv = self._read_fileng(4)
        _home = self._read_fileng(16)

        data = DataType_Type2(
            ip=ipaddress.ip_address(_home),  # type: ignore[arg-type]  # type: ignore[arg-type]
        )

        return data

    def _read_data_type_rpl(self, length: 'int') -> 'DataType_RPL':
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

        Raises:
            ProtocolError: If ``length`` is **NOT** ``20``.

        """
        _cmpr = self._read_binary(1)
        _padr = self._read_binary(1)
        _resv = self._read_fileng(2)

        _inti = int(_cmpr[:4], base=2)
        _inte = int(_cmpr[4:], base=2)
        _plen = int(_padr[:4], base=2)

        _ilen = 16 - _inti
        _elen = 16 - _inte

        _addr = []  # type: list[IPv6Address]
        for _ in range(((length - 4) - _elen - _plen) // _ilen):
            _addr.append(ipaddress.ip_address(self._read_fileng(_ilen)))  # type: ignore[arg-type]
        _addr.append(ipaddress.ip_address(self._read_fileng(_elen)))  # type: ignore[arg-type]

        _pads = self._read_fileng(_plen)

        data = DataType_RPL(
            cmpr_i=_inti,
            cmpr_e=_inte,
            pad=_plen,
            ip=tuple(_addr),
        )

        return data

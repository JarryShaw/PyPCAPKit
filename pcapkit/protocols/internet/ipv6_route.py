# -*- coding: utf-8 -*-
"""routing header for IPv6

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
import ipaddress

from pcapkit.const.ipv6.routing import Routing as _ROUTING_TYPE
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['IPv6_Route']

# IPv6 Routing Processors
_ROUTE_PROC = {
    0: 'src',                          # [RFC 5095] DEPRECATED
    2: '2',                            # [RFC 6275]
    3: 'rpl',                          # [RFC 6554]
}


class IPv6_Route(Internet):
    """This class implements Routing Header for IPv6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Routeing Header for IPv6']
        """
        return 'Routing Header for IPv6'

    @property
    def alias(self):
        """Acronym of corresponding protocol.

        :rtype: Literal['IPv6-Route']
        """
        return 'IPv6-Route'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: int
        """
        return self._info.length  # pylint: disable=E1101

    @property
    def payload(self):
        """Payload of current instance.

        Raises:
            UnsupportedCall: if the protocol is used as an IPv6 extension header

        :rtype: pcapkit.protocols.protocol.Protocol
        """
        if self._extf:
            raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'payload'")
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.next  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ,unused-argument
        """Read Routing Header for IPv6.

        Structure of IPv6-Route header [:rfc:`8200`][:rfc:`5095`]::

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
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the packet is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPv6_Route: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_unpack(1)
        _left = self._read_unpack(1)

        ipv6_route = dict(
            next=_next,
            length=(_hlen + 1) * 8,
            type=_ROUTING_TYPE.get(_type, 'Unassigned'),
            seg_left=_left,
        )

        _dlen = _hlen * 8 - 4
        if _dlen:
            _func = _ROUTE_PROC.get(_type, 'none')
            _meth = getattr(self, f'_read_data_type_{_func}', '_read_data_type_none')
            _data = _meth(self, _dlen)
            ipv6_route.update(_data)

        length -= ipv6_route['length']
        ipv6_route['packet'] = self._read_packet(header=ipv6_route['length'], payload=length)

        if extension:
            self._protos = None
            return ipv6_route
        return self._decode_next_layer(ipv6_route, _next, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file, length=None, *, extension=False, **kwargs):  # pylint: disable=arguments-differ
        """Post initialisation hook.

        Args:
            file (io.BytesIO): Source packet stream.
            length (Optional[int]): Length of packet data.

        Keyword Args:
            extension (bool): If the protocol is used as an IPv6 extension header.
            **kwargs: Arbitrary keyword arguments.

        See Also:
            For construction argument, please refer to :meth:`make`.

        """
        #: bool: If the protocol is used as an IPv6 extension header.
        self._extf = extension

        # call super __post_init__
        super().__post_init__(file, length, extension=extension, **kwargs)

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[4]
        """
        return 4

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(43)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_data_type_none(self, length):
        """Read IPv6-Route unknown type data.

        Structure of IPv6-Route unknown type data [:rfc:`8200`][:rfc:`5095`]::

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
            length (int): route data length

        Returns:
            DataType_IPv6_Route_None: parsed route data

        """
        _data = self._read_fileng(length)

        data = dict(
            data=_data,
        )

        return data

    def _read_data_type_src(self, length):
        """Read IPv6-Route Source Route data.

        Structure of IPv6-Route Source Route data [:rfc:`5095`]::

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
            length (int): route data length

        Returns:
            DataType_IPv6_Route_Source: parsed route data

        """
        _resv = self._read_fileng(4)
        _addr = list()
        for _ in range((length - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))

        data = dict(
            ip=tuple(_addr),
        )

        return data

    def _read_data_type_2(self, length):
        """Read IPv6-Route Type 2 data.

        Structure of IPv6-Route Type 2 data [:rfc:`6275`]::

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
            length (int): route data length

        Returns:
            DataType_IPv6_Route_2: parsed route data

        Raises:
            ProtocolError: If ``length`` is **NOT** ``20``.

        """
        if length != 20:
            raise ProtocolError(f'{self.alias}: [TypeNo 2] invalid format')

        _resv = self._read_fileng(4)
        _home = self._read_fileng(16)

        data = dict(
            ip=ipaddress.ip_address(_home),
        )

        return data

    def _read_data_type_rpl(self, length):
        """Read IPv6-Route RPL Source data.

        Structure of IPv6-Route RPL Source data [:rfc:`6554`]::

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
            length (int): route data length

        Returns:
            DataType_IPv6_Route_RPL: parsed route data

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

        _addr = list()
        for _ in range(((length - 4) - _elen - _plen) // _ilen):
            _addr.append(ipaddress.ip_address(self._read_fileng(_ilen)))
        _addr.append(ipaddress.ip_address(self._read_fileng(_elen)))

        _pads = self._read_fileng(_plen)

        data = dict(
            cmpr_i=_inti,
            cmpr_e=_inte,
            pad=_plen,
            ip=tuple(_addr),
        )

        return data

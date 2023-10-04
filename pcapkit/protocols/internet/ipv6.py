# -*- coding: utf-8 -*-
"""IPv6 - Internet Protocol version 6
========================================

.. module:: pcapkit.protocols.internet.ipv6

:mod:`pcapkit.protocols.internet.ipv6` contains
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only,
which implements extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ip.version``              Version (``6``)
  0           4   ``ip.class``                Traffic Class
  1          12   ``ip.label``                Flow Label
  4          32   ``ip.payload``              Payload Length (header excludes)
  6          48   ``ip.next``                 Next Header
  7          56   ``ip.limit``                Hop Limit
  8          64   ``ip.src``                  Source Address
  24        192   ``ip.dst``                  Destination Address
======= ========= ===================== =======================================

.. [*] https://en.wikipedia.org/wiki/IPv6_packet

"""
import ipaddress
from typing import TYPE_CHECKING

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
from pcapkit.protocols.internet.ip import IP
from pcapkit.protocols.schema.internet.ipv6 import IPv6 as Schema_IPv6

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv6Address
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IPv6']


class IPv6(IP[Data_IPv6, Schema_IPv6],
           schema=Schema_IPv6, data=Data_IPv6):
    """This class implements Internet Protocol version 6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internet Protocol version 6"]':
        """Name of corresponding protocol."""
        return 'Internet Protocol version 6'

    @property
    def length(self) -> 'Literal[40]':
        """Header length of corresponding protocol."""
        return 40

    @property
    def protocol(self) -> 'Enum_TransType':
        """Name of next layer protocol."""
        return self._info.protocol

    # source IP address
    @property
    def src(self) -> 'IPv6Address':
        """Source IP address."""
        return self._info.src

    # destination IP address
    @property
    def dst(self) -> 'IPv6Address':
        """Destination IP address."""
        return self._info.dst

    @property
    def extension_headers(self) -> 'OrderedMultiDict[Enum_ExtensionHeader, Protocol]':
        """IPv6 extension header records."""
        return self._exthdr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *,
             __packet__: 'Optional[dict[str, Any]]' = None, **kwargs: 'Any') -> 'Data_IPv6':  # pylint: disable=unused-argument
        """Read Internet Protocol version 6 (IPv6).

        Structure of IPv6 header [:rfc:`2460`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |Version| Traffic Class |           Flow Label                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |         Payload Length        |  Next Header  |   Hop Limit   |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                         Source Address                        +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                                                               |
           +                                                               +
           |                                                               |
           +                      Destination Address                      +
           |                                                               |
           +                                                               +
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            __packet__: Optional packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        ipv6 = Data_IPv6.from_dict({
            'version': schema.hextet['version'],
            'class': schema.hextet['class'],
            'label': schema.hextet['label'],
            'payload': schema.length,
            'next': schema.next,
            'limit': schema.limit,
            'src': schema.src,
            'dst': schema.dst,
        })  # type: Data_IPv6

        # update packet info
        if __packet__ is None:
            __packet__ = {}
        __packet__.update({
            'src': ipv6.src,
            'dst': ipv6.dst,
        })

        return self._decode_next_layer(ipv6, schema.next, ipv6.payload, packet=__packet__)  # pylint: disable=no-member

    def make(self,
             traffic_class: 'int' = 0,
             flow_label: 'int' = 0,
             next: 'Enum_TransType | StdlibEnum | AenumEnum | str | int' = Enum_TransType.UDP,
             next_default: 'Optional[int]' = None,
             next_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             next_reversed: 'bool' = False,
             hop_limit: 'int' = 64,  # reasonable default
             src: 'IPv6Address | str | bytes | int' = '::1',
             dst: 'IPv6Address | str | bytes | int' = '::',
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IPv6':
        """Make (construct) packet data.

        Args:
            traffic_class: Traffic class.
            flow_label: Flow label.
            next: Next header.
            next_default: Default value of next header.
            next_namespace: Namespace of next header.
            next_reversed: Whether to reverse the namespace of next header.
            hop_limit: Hop limit.
            src: Source IP address.
            dst: Destination IP address.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        next_val = self._make_index(next, next_default, namespace=next_namespace,
                                    reversed=next_reversed, pack=False)

        return Schema_IPv6(
            hextet={
                'version': 6,
                'class': traffic_class,
                'label': flow_label,
            },
            length=len(payload),
            next=next_val,  # type: ignore[arg-type]
            limit=hop_limit,
            src=src,
            dst=dst,
            payload=payload,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["IPv6"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return ('IPv6',)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[40]':
        """Return an estimated length for the object."""
        return 40

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPv6  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPv6') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'traffic_class': data['class'],
            'flow_label': data.label,
            'next': data.next,
            'hop_limit': data.limit,
            'src': data.src,
            'dst': data.dst,
            'payload': cls._make_payload(data)
        }

    def _read_ip_hextet(self) -> 'tuple[int, int, int]':
        """Read first four hextets of IPv6.

        Returns:
            Parsed hextets data, including version number, traffic class and
            flow label.

        """
        _htet = self._read_fileng(4).hex()
        _vers = int(_htet[0], base=16)      # version number (6)
        _tcls = int(_htet[0:2], base=16)    # traffic class
        _flow = int(_htet[2:], base=16)     # flow label

        return (_vers, _tcls, _flow)

    def _read_ip_addr(self) -> 'IPv6Address':
        """Read IP address.

        Returns:
            Parsed IP address.

        """
        return ipaddress.ip_address(self._read_fileng(16))  # type: ignore[return-value]

    def _decode_next_layer(self, ipv6: 'Data_IPv6', proto: 'Optional[int]' = None,  # type: ignore[override] # pylint: disable=arguments-differ,arguments-renamed
                           length: 'Optional[int]' = None, *, packet: 'Optional[dict[str, Any]]' = None) -> 'Data_IPv6':  # pylint: disable=arguments-differ
        """Decode next layer extractor.

        Arguments:
            ipv6: info buffer
            proto: next layer protocol name
            length: valid (*not padding*) length
            packet: packet info (passed from :meth:`self.unpack <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Current protocol with next layer extracted.

        """
        #: Extension headers.
        self._exthdr = OrderedMultiDict()  # type: OrderedMultiDict[Enum_ExtensionHeader, Protocol] # pylint: disable=attribute-defined-outside-init

        hdr_len = self.length       # header length
        raw_len = ipv6.payload      # payload length
        _protos = []                # ProtoChain buffer

        # traverse if next header is an extensive header
        while True:
            try:
                ex_proto = Enum_ExtensionHeader(proto)
            except ValueError:
                break

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            next_ = self._import_next_layer(proto, packet=packet, version=6, extension=True)  # type: ignore[misc,call-arg,arg-type]
            info = next_.info
            name = next_.alias.lstrip('IPv6-').lower()
            ipv6.__update__({
                name: info,
            })

            # record protocol name
            # self._protos = ProtoChain(name, chain, alias)
            _protos.append(next_)
            proto = info.next

            # update header & payload length
            hdr_len += next_.length  # type: ignore[assignment]
            raw_len -= next_.length

            # keep record of extension headers
            self._exthdr.add(ex_proto, next_)

            # keep original data after fragment header
            if ex_proto == Enum_ExtensionHeader.IPv6_Frag:
                ipv6.__update__({
                    'fragment': self._read_packet(header=hdr_len, payload=raw_len),
                })
                break

        # record real header & payload length (headers exclude)
        ipv6.__update__({
            'hdr_len': hdr_len,
            'raw_len': raw_len,

            # update next header
            'protocol': proto,
        })

        ipv6_exthdr = ProtoChain.from_list(_protos)  # type: ignore[arg-type]
        return super()._decode_next_layer(ipv6, proto, raw_len, packet=packet, ipv6_exthdr=ipv6_exthdr)

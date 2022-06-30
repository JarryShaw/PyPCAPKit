# -*- coding: utf-8 -*-
"""IPv6 - Internet Protocol version 6
========================================

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

from pcapkit.const.ipv6.extension_header import ExtensionHeader as RegType_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.data.internet.ipv6 import IPv6 as DataType_IPv6
from pcapkit.protocols.internet.ip import IP

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import Protocol

__all__ = ['IPv6']


class IPv6(IP[DataType_IPv6]):
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
    def protocol(self) -> 'RegType_TransType':
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
    def extension_headers(self) -> 'OrderedMultiDict[RegType_ExtensionHeader, Protocol]':
        """IPv6 extension header records."""
        return self._exthdr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_IPv6':  # pylint: disable=unused-argument
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
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _htet = self._read_ip_hextet()
        _plen = self._read_unpack(2)
        _next = self._read_protos(1)
        _hlmt = self._read_unpack(1)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ipv6 = DataType_IPv6.from_dict({
            'version': _htet[0],
            'class': _htet[1],
            'label': _htet[2],
            'payload': _plen,
            'next': _next,
            'limit': _hlmt,
            'src': _srca,
            'dst': _dsta,
        })  # type: DataType_IPv6

        return self._decode_next_layer(ipv6, _next, ipv6.payload)  # pylint: disable=no-member

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

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
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.IPv6  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

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

    def _decode_next_layer(self, ipv6: 'DataType_IPv6', proto: 'Optional[int]' = None,  # type: ignore[override] # pylint: disable=arguments-differ,arguments-renamed
                           length: 'Optional[int]' = None) -> 'DataType_IPv6':  # pylint: disable=arguments-differ
        """Decode next layer extractor.

        Arguments:
            ipv6: info buffer
            proto: next layer protocol name
            length: valid (*not padding*) length

        Returns:
            Current protocol with next layer extracted.

        """
        #: Extension headers.
        self._exthdr = OrderedMultiDict()  # type: OrderedMultiDict[RegType_ExtensionHeader, Protocol] # pylint: disable=attribute-defined-outside-init

        hdr_len = self.length       # header length
        raw_len = ipv6.payload      # payload length
        _protos = []                # ProtoChain buffer

        # traverse if next header is an extensive header
        while True:
            try:
                ex_proto = RegType_ExtensionHeader(proto)
            except ValueError:
                break

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            next_ = self._import_next_layer(proto, version=6, extension=True)  # type: ignore[misc,call-arg,arg-type]
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
            if ex_proto == RegType_ExtensionHeader.IPv6_Frag:
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
        return super()._decode_next_layer(ipv6, proto, raw_len, ipv6_exthdr=ipv6_exthdr)

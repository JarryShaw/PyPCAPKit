# -*- coding: utf-8 -*-
"""internet protocol version 6

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

from pcapkit.const.ipv6.extension_header import ExtensionHeader as EXT_HDR
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.internet.ip import IP

__all__ = ['IPv6']


class IPv6(IP):
    """This class implements Internet Protocol version 6."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: Literal['Internet Protocol version 6']
        """
        return 'Internet Protocol version 6'

    @property
    def length(self):
        """Header length of corresponding protocol.

        :rtype: int
        """
        return self._info.hdr_len  # pylint: disable=E1101

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.protocol  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Internet Protocol version 6 (IPv6).

        Structure of IPv6 header [:rfc:`2460`]::

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
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPv6: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _htet = self._read_ip_hextet()
        _plen = self._read_unpack(2)
        _next = self._read_protos(1)
        _hlmt = self._read_unpack(1)
        _srca = self._read_ip_addr()
        _dsta = self._read_ip_addr()

        ipv6 = {
            'version': _htet[0],
            'class': _htet[1],
            'label': _htet[2],
            'payload': _plen,
            'next': _next,
            'limit': _hlmt,
            'src': _srca,
            'dst': _dsta,
        }

        hdr_len = 40
        raw_len = ipv6['payload']
        ipv6['packet'] = self._read_packet(header=hdr_len, payload=raw_len)

        return self._decode_next_layer(ipv6, _next, raw_len)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
           Literal['IPv6']: Index ID of the protocol.

        """
        return cls.__name__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[40]
        """
        return 40

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(41)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ip_hextet(self):
        """Read first four hextets of IPv6.

        Returns:
            Tuple[int, int, int]: Parsed hextets data, including version number,
            traffic class and flow label.

        """
        _htet = self._read_fileng(4).hex()
        _vers = int(_htet[0], base=16)      # version number (6)
        _tcls = int(_htet[0:2], base=16)    # traffic class
        _flow = int(_htet[2:], base=16)     # flow label

        return (_vers, _tcls, _flow)

    def _read_ip_addr(self):
        """Read IP address.

        Returns:
            ipaddress.IPv6Address: Parsed IP address.

        """
        return ipaddress.ip_address(self._read_fileng(16))

    def _decode_next_layer(self, ipv6, proto=None, length=None):  # pylint: disable=arguments-differ
        """Decode next layer extractor.

        Arguments:
            ipv6 (DataType_IPv6): info buffer
            proto (str): next layer protocol name
            length (int): valid (*not padding*) length

        Returns:
            DataType_IPv6: current protocol with next layer extracted

        """
        hdr_len = 40                # header length
        raw_len = ipv6['payload']   # payload length
        _protos = list()            # ProtoChain buffer

        # traverse if next header is an extensive header
        while proto in EXT_HDR:
            # keep original data after fragment header
            if proto.value == 44:
                ipv6['fragment'] = self._read_packet(header=hdr_len, payload=raw_len)

            # # directly break when No Next Header occurs
            # if proto.name == 'IPv6-NoNxt':
            #     proto = None
            #     break

            # make protocol name
            next_ = self._import_next_layer(proto, version=6, extension=True)
            info = next_.info
            name = next_.alias.lstrip('IPv6-').lower()
            ipv6[name] = info

            # record protocol name
            # self._protos = ProtoChain(name, chain, alias)
            _protos.append(next_)
            proto = info.next  # pylint: disable=E1101

            # update header & payload length
            hdr_len += info.length  # pylint: disable=E1101
            raw_len -= info.length  # pylint: disable=E1101

        # record real header & payload length (headers exclude)
        ipv6['hdr_len'] = hdr_len
        ipv6['raw_len'] = raw_len

        # update next header
        ipv6['protocol'] = proto
        return super()._decode_next_layer(ipv6, proto, raw_len, ipv6_exthdr=_protos)

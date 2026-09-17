# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""UDP - User Datagram Protocol
==================================

.. module:: pcapkit.protocols.transport.udp

:mod:`pcapkit.protocols.transport.udp` contains
:class:`~pcapkit.protocols.transport.udp.UDP` only,
which implements extractor for User Datagram Protocol
(UDP) [*]_, whose structure is described as below:

======= ========= ===================== ===============================
Octets      Bits        Name                    Description
======= ========= ===================== ===============================
  0           0   ``udp.srcport``             Source Port
  2          16   ``udp.dstport``             Destination Port
  4          32   ``udp.len``                 Length (header includes)
  6          48   ``udp.checksum``            Checksum
======= ========= ===================== ===============================

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol

"""
import collections
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.transport.udp import UDP as Data_UDP
from pcapkit.protocols.schema.transport.udp import UDP as Schema_UDP
from pcapkit.protocols.transport.transport import Transport

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.apptype import AppType as Enum_AppType
    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['UDP']


class UDP(Transport[Data_UDP, Schema_UDP],
          schema=Schema_UDP, data=Data_UDP):
    """This class implements User Datagram Protocol.

    This class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.transport.udp.UDP.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Port Number
         - Protocol
       * - 80
         - :class:`pcapkit.protocols.application.http.HTTP`
       * - 1701
         - :class:`pcapkit.protocols.link.l2tpv2.L2TPv2`
       * - 8080
         - :class:`pcapkit.protocols.application.http.HTTP`

    Note:
        Both HTTP ports here resolve to
        :class:`pcapkit.protocols.application.http.HTTP`, which sniffs HTTP/1
        against HTTP/2 and delegates, whereas
        :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
        binds :class:`pcapkit.protocols.application.httpv1.HTTP` directly for
        the same ports. The asymmetry predates the 8080 entries -- port 80 was
        already split this way -- and each table is left internally consistent
        rather than repointing port 80 and changing what existing captures
        parse to. Reconciling the two is left as its own change.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[int, ModuleDescriptor[Protocol] | ~typing.Type[Protocol]]: Protocol
    #: index mapping for decoding next layer, c.f.
    #: :meth:`self._decode_next_layer <pcapkit.protocols.transport.transport.Transport._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            # Ports are IANA service-name registry assignments, quoting that
            # registry's own service name and description:
            #
            #   80    http       World Wide Web HTTP
            #   1701  l2tp       l2tp
            #   8080  http-alt   HTTP Alternate (see port 80)
            #
            # Both HTTP entries keep pointing at the version-guessing
            # :class:`pcapkit.protocols.application.http.HTTP`, which is what
            # port 80 already used here -- unlike TCP, which binds HTTP/1
            # directly. c.f. the note in the class docstring.
            80: ModuleDescriptor('pcapkit.protocols.application.http', 'HTTP'),
            8080: ModuleDescriptor('pcapkit.protocols.application.http', 'HTTP'),

            # L2TPv2 (RFC 2661) is UDP-borne, and v2 is the only version the
            # package implements, so the concrete class is bound rather than the
            # abstract L2TP base. IANA protocol number 115 stays unbound because
            # it is L2TPv3 (RFC 3931), which has no class yet -- when it does, it
            # takes 115 and this entry becomes a version switch on the Ver
            # nibble. c.f. pcapkit.protocols.link.l2tp.
            1701: ModuleDescriptor('pcapkit.protocols.link.l2tpv2', 'L2TPv2'),
        },
    )

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["User Datagram Protocol"]':
        """Name of current protocol."""
        return 'User Datagram Protocol'

    @property
    def length(self) -> 'Literal[8]':
        """Header length of current protocol."""
        return 8

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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_UDP':  # pylint: disable=unused-argument
        """Read User Datagram Protocol (UDP).

        Structure of UDP header [:rfc:`768`]:

        .. code-block:: text

            0      7 8     15 16    23 24    31
           +--------+--------+--------+--------+
           |     Source      |   Destination   |
           |      Port       |      Port       |
           +--------+--------+--------+--------+
           |                 |                 |
           |     Length      |    Checksum     |
           +--------+--------+--------+--------+
           |
           |          data octets ...
           +---------------- ...

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        udp = Data_UDP(
            srcport=schema.srcport,
            dstport=schema.dstport,
            len=schema.len,
            checksum=schema.checksum,
        )

        return self._decode_next_layer(udp, (udp.srcport.port, udp.dstport.port), udp.len - 8)

    def make(self,
             srcport: 'Enum_AppType | int' = 0,
             dstport: 'Enum_AppType | int' = 0,
             checksum: 'bytes' = b'\x00\x00',
             payload: 'bytes | Schema | Protocol' = b'',
             **kwargs: 'Any') -> 'Schema_UDP':
        """Make (construct) packet data.

        Args:
            srcport: Source port.
            dstport: Destination port.
            checksum: Checksum.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        return Schema_UDP(
            srcport=self._make_port(srcport, Enum_TransportProtocol.udp),
            dstport=self._make_port(dstport, Enum_TransportProtocol.udp),
            len=8 + len(payload),
            checksum=checksum,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.UDP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_UDP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'srcport': data.srcport,
            'dstport': data.dstport,
            'checksum': data.checksum,
            'payload': cls._make_payload(data),
        }

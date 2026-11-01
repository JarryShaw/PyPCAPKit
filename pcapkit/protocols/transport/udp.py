# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""UDP - User Datagram Protocol
==================================

.. module:: pcapkit.protocols.transport.udp

:mod:`pcapkit.protocols.transport.udp` contains
:class:`~pcapkit.protocols.transport.udp.UDP` only,
which implements the extractor for User Datagram Protocol
(UDP) [*]_, whose structure is described as below:

======= ========= ===================== ===============================
Octets      Bits        Name                    Description
======= ========= ===================== ===============================
  0           0   ``udp.srcport``             Source Port
  2          16   ``udp.dstport``             Destination Port
  4          32   ``udp.len``                 Length (header included)
  6          48   ``udp.checksum``            Checksum
======= ========= ===================== ===============================

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol

"""
import collections
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import AppType as Enum_AppType
from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.transport.udp import UDP as Data_UDP
from pcapkit.protocols.schema.transport.udp import UDP as Schema_UDP
from pcapkit.protocols.transport.transport import Transport
from pcapkit.utilities import config

if TYPE_CHECKING:
    from typing import Any, ClassVar, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['UDP']


class UDP(Transport[Data_UDP, Schema_UDP],
          schema=Schema_UDP, data=Data_UDP):
    """This class implements User Datagram Protocol.

    This class supports parsing of the following protocols, which are
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
        The HTTP ports resolve to
        :class:`pcapkit.protocols.application.http.HTTP`, whose
        :meth:`~pcapkit.protocols.application.http.HTTP._dispatch_version` picks
        :class:`~pcapkit.protocols.application.httpv1.HTTPv1` or
        :class:`~pcapkit.protocols.application.httpv2.HTTPv2` from the payload.
        :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
        binds the same class for its HTTP ports.

    .. versionchanged:: 1.5.0

       :meth:`make` takes ``total_length``, which a
       :meth:`~pcapkit.protocols.protocol.Protocol.from_data` rebuild
       passes so that a truncated capture keeps its declared Length
       (:issue:`1155`), and ``trailer``, so that the octets past the Length
       field rebuild as captured (:issue:`1461`).

    .. versionchanged:: 1.6.0

       The checksum is computed when :meth:`make` is given none, over the
       ``pseudo`` it is given or by the enclosing IP layer, and verified by that
       layer under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`
       (:issue:`2474`).

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.transport.transport.Transport._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            # Ports are IANA service-name registry assignments, quoting that
            # registry's own service name and description:
            #
            #   80    http       World Wide Web HTTP
            #   1701  l2tp       l2tp
            #   5684  coaps      CoAP over DTLS
            #   8080  http-alt   HTTP Alternate (see port 80)
            #
            # The HTTP entries bind the version-dispatching
            # :class:`pcapkit.protocols.application.http.HTTP`, as TCP's table
            # does. See the note in the class docstring.
            80: ModuleDescriptor('pcapkit.protocols.application.http', 'HTTP'),
            8080: ModuleDescriptor('pcapkit.protocols.application.http', 'HTTP'),

            # CoAP over DTLS (RFC 7252) is bound here, but it is not the only
            # fixed port a DTLS-borne protocol is registered at -- IANA also
            # registers DTLS at 853 (domain-s), 4740 (ipfixs), 5349
            # (stuns/turns), 6514 (syslog-tls) and 10161/10162 (snmpdtls),
            # among others -- and plenty of deployments negotiate DTLS on a
            # dynamic port no registry can name. See
            # pcapkit.protocols.application.dtls.
            5684: ModuleDescriptor('pcapkit.protocols.application.dtls', 'DTLS'),

            # L2TPv2 (RFC 2661) is UDP-borne, and v2 is the only version
            # implemented, so the concrete class is bound rather than the
            # abstract L2TP base. IANA protocol number 115 (L2TPv3, RFC 3931)
            # stays unbound because that version has no class; once it has,
            # it takes 115 and this entry becomes a version switch on the Ver
            # nibble. See pcapkit.protocols.link.l2tp.
            1701: ModuleDescriptor('pcapkit.protocols.link.l2tpv2', 'L2TPv2'),
        },
    )

    #: What :attr:`__proto__` is keyed by: the enum a key must be a member of,
    #: and whether a bare :class:`int` is a valid key there too. Declared by the
    #: class *owning* the registry, and read from it by
    #: :func:`~pcapkit.foundation.registry.protocols.register_protocol_code` so a
    #: ``code=`` key is checked exactly as
    #: :func:`~pcapkit.foundation.registry.protocols.register_udp` checks its own
    #: -- a bare :class:`int` is accepted because the registry is keyed by
    #: port number, and an :class:`~pcapkit.const.reg.apptype.apptype.AppType`
    #: member carries one (:issue:`2268`).
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_AppType, True)

    #: Whether :meth:`make` left the checksum for the enclosing IP layer to
    #: compute, see :mod:`pcapkit.protocols.misc.checksum.checksum`.
    _checksum_pending = False

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

        # NOTE: Octets captured past the Length field belong to this layer,
        # since its own length field is what leaves them out of the payload,
        # and the rebuild keeps them as captured (#1461).
        if schema.trailer:
            udp.__update__([
                ('trailer', schema.trailer),
            ])

        return self._decode_next_layer(udp, (udp.srcport.port, udp.dstport.port), udp.len - 8)

    def make(self,
             srcport: 'Enum_AppType | int' = 0,
             dstport: 'Enum_AppType | int' = 0,
             checksum: 'Optional[bytes]' = None,
             total_length: 'Optional[int]' = None,
             payload: 'bytes | Schema | ProtocolBase' = b'',
             trailer: 'bytes' = b'',
             pseudo: 'Optional[IP_Pseudo]' = None,
             **kwargs: 'Any') -> 'Schema_UDP':
        """Make (construct) packet data.

        Args:
            srcport: Source port.
            dstport: Destination port.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on,
                computed over ``pseudo`` (:rfc:`768`), or left to an IP layer
                this datagram is the payload of; zero, i.e. none, otherwise.
            total_length: Length of the datagram, header included; computed from
                the header and the payload when omitted.
            payload: Payload data.
            trailer: Octets after the datagram, outside the Length field;
                written as is and not counted in a computed ``total_length``.
            pseudo: Pseudo-header of the enclosing IP layer; its length is
                replaced by ``total_length``, as the Length field gives it.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``srcport`` or ``dstport`` is a :obj:`bool`
                (:issue:`2287`).

        .. versionchanged:: 1.5.0

           An out-of-range ``srcport`` or ``dstport`` raises
           :exc:`ValueError` rather than being accepted (:issue:`758`).
           ``total_length`` sits before ``payload`` (:issue:`1155`), so a
           caller passing ``payload`` positionally sets ``total_length``
           instead.

        """
        # NOTE: An explicit ``total_length`` is written as given, so that a
        # ``from_data`` rebuild of a capture truncated by snaplen keeps the
        # length the sender declared instead of the one that was recorded
        # (#1155). Computed from the octets at hand otherwise, which is
        # what a plain ``UDP(payload=...)`` wants.
        if total_length is None:
            total_length = 8 + len(payload)

        schema = Schema_UDP(
            srcport=self._make_port(srcport, Enum_TransportProtocol.udp),
            dstport=self._make_port(dstport, Enum_TransportProtocol.udp),
            len=total_length,
            checksum=b'\x00\x00' if checksum is None else checksum,
            payload=payload,
            trailer=trailer,
        )

        self._checksum_pending = False
        if checksum is None and config.CHECKSUM_COMPUTE:
            if pseudo is None:
                self._checksum_pending = True
            else:
                from pcapkit.protocols.misc.checksum.checksum import compute_checksum, pseudo_header  # isort: skip # pylint: disable=import-outside-toplevel

                # NOTE: Over the datagram the Length field gives, or all but the trailer
                # for a jumbogram's zero one (RFC 2675); a computed zero is all ones.
                octets = schema.pack()
                length = total_length or len(octets) - len(trailer)
                schema.checksum = compute_checksum(octets[:length], nonzero=True,
                                                   prefix=pseudo_header(pseudo, length))
        return schema

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
            # NOTE: The parsed length is passed through rather than left to
            # ``make`` to recompute, so that a truncated capture rebuilds with
            # the length that was on the wire (#1155).
            'total_length': data.len,
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Length field (#1461).
            'trailer': data.get('trailer', b''),
        }

    def _verify_pseudo_checksum(self, pseudo: 'Optional[IP_Pseudo]') -> 'None':
        """Verify the checksum over the pseudo-header of the enclosing IP layer.

        That layer calls this once parsed, see
        :func:`~pcapkit.protocols.misc.checksum.checksum.verify_upper`. A zero
        checksum over IPv4, which means none (:rfc:`768`), and the
        pseudo-header's sum alone, which checksum offload leaves on the sending
        host, are
        :attr:`~pcapkit.protocols.misc.checksum.checksum.ChecksumStatus.NOT_COMPUTED`.
        A zero one over IPv6 is wrong, as one is mandatory there
        (:rfc:`8200#section-8.1`).

        Args:
            pseudo: Pseudo-header, or :data:`None` if the IP layer gives none.

        """
        from pcapkit.protocols.misc.checksum.checksum import (  # isort: skip # pylint: disable=import-outside-toplevel
            ChecksumStatus, partial_checksum, verify_checksum)

        if pseudo is None:
            status = ChecksumStatus.NO_PSEUDO_HEADER
        else:
            status = verify_checksum(self.alias, self._data, self._info.checksum, length=pseudo.info.len,
                                     prefix=pseudo.data, absent=b'\x00\x00' if pseudo.version == 4 else None,
                                     offload=(partial_checksum(pseudo.data),))
        self._info.__update__(checksum_status=status)

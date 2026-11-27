# -*- coding: utf-8 -*-
"""OSPFv1 - Open Shortest Path First version 1
=================================================

.. module:: pcapkit.protocols.application.ospfv1.protocol

:mod:`pcapkit.protocols.application.ospfv1.protocol` holds
:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`, the extractor for
Open Shortest Path First version 1 (OSPFv1) [:rfc:`1131`], obsoleted by
:rfc:`1247`. Its header (:rfc:`1131` Section A.2) is laid out as OSPFv2's:

.. table::

   ====== ===== ================== ===============================
   Octets Bits  Name               Description
   ====== ===== ================== ===============================
   0          0 ``ospf.version``   Version Number
   ------ ----- ------------------ -------------------------------
   1          8 ``ospf.type``      Type
   ------ ----- ------------------ -------------------------------
   2         16 ``ospf.len``       Packet Length (header included)
   ------ ----- ------------------ -------------------------------
   4         32 ``ospf.router_id`` Router ID
   ------ ----- ------------------ -------------------------------
   8         64 ``ospf.area_id``   Area ID
   ------ ----- ------------------ -------------------------------
   12        96 ``ospf.chksum``    Checksum
   ------ ----- ------------------ -------------------------------
   14       112 ``ospf.autype``    Authentication Type
   ------ ----- ------------------ -------------------------------
   16       128 ``ospf.auth``      Authentication
   ====== ===== ================== ===============================

It defines packet types 1 to 5 alone (Section A.2) and AuType 0 and 1 alone
(Appendix E), which :class:`~pcapkit.const.ospfv1.packet.Packet` and
:class:`~pcapkit.const.ospfv1.authentication.Authentication` name, rather than OSPFv2's
IANA registries. Its Authentication field is kept as captured: the cryptographic
authentication of :rfc:`2328#appendix-D.3` is OSPFv2's.

.. versionadded:: 1.8.1

"""
from typing import TYPE_CHECKING

from pcapkit.const.ospfv1.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospfv1.packet import Packet as Enum_Packet
from pcapkit.corekit.schema.short_read import cut_on_its_own
from pcapkit.protocols.application.ospf.protocol import OSPF
from pcapkit.protocols.application.ospfv1.data import OSPFv1 as Data_OSPFv1
from pcapkit.protocols.application.ospfv1.schema import OSPFv1 as Schema_OSPFv1
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['OSPFv1']


class OSPFv1(OSPF[Data_OSPFv1, Schema_OSPFv1],
             schema=Schema_OSPFv1, data=Data_OSPFv1):
    """This class implements Open Shortest Path First version 1.

    .. versionadded:: 1.8.1

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self) -> 'Literal[24]':
        """Header length of current protocol."""
        return 24

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["OSPFv1"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member.

        """
        return ('OSPFv1',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_OSPFv1':
        """Read Open Shortest Path First version 1.

        Structure of OSPFv1 header [:rfc:`1131`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Version #   |     Type      |         Packet length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          Router ID                            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                           Area ID                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Checksum            |             AuType            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Authentication                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                       Authentication                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Version is not 1.

        """
        schema = self.__header__
        if not cut_on_its_own(schema, 'version') and schema.version != 1:
            raise ProtocolError(f'OSPFv1: invalid version: {schema.version}')

        # Set before _decode_next_layer below, which reads self.alias.
        self._version = schema.version

        ospf = Data_OSPFv1(
            version=schema.version,
            type=schema.type,
            len=schema.length,
            router_id=schema.router_id,
            area_id=schema.area_id,
            chksum=schema.checksum,
            autype=schema.auth_type,
            auth=schema.auth_data,
        )
        length = schema.length if schema.length else (length or len(self))

        # NOTE: Octets past the Packet Length belong to this layer, as its length
        # leaves them out, and are rebuilt as captured (#1455).
        if schema.trailer:
            ospf.__update__([
                ('trailer', schema.trailer),
            ])

        # NOTE: Over the packet but the Authentication field, as for OSPFv2 (RFC 1131 A.2).
        self._verify_checksum(ospf)

        # NOTE: No next-protocol field, so the -1 sentinel is dispatched, as for OSPFv2.
        return self._decode_next_layer(ospf, -1, length - self.length)

    def make(self, *,
             version: 'int' = 1,
             type: 'Enum_Packet | int' = Enum_Packet.Hello,
             packet_length: 'Optional[int]' = None,
             router_id: 'IPv4Address | str | bytes' = '0.0.0.0',  # nosec: B104
             area_id: 'IPv4Address | str | bytes' = '0.0.0.0',  # nosec: B104
             checksum: 'Optional[bytes]' = None,
             auth_type: 'Enum_Authentication | int' = Enum_Authentication.No_authentication,
             auth_data: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_OSPFv1':
        """Make (construct) packet data.

        Args:
            version: OSPF version number, ``1``.
            type: OSPF packet type.
            packet_length: Packet length (header included). If not given, it is
                computed as 24 plus the length of ``payload``.
            router_id: Router ID.
            area_id: Area ID.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on, computed
                over the packet but its Authentication field (:rfc:`1131` Section
                A.2); zero otherwise.
            auth_type: Authentication type.
            auth_data: Authentication data, 8 octets.
            payload: Payload data.
            trailer: Octets after the packet, outside the Packet Length; written
                as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``version`` is not 1; if ``auth_data`` is not 8
                octets of :obj:`bytes`; if ``packet_length`` is not an :obj:`int`
                in ``0..65535``; if ``checksum`` is not two octets; or if ``type``
                (8 bits) or ``auth_type`` (16 bits) is a name, a :obj:`bool`, or a
                member or code its field cannot carry.

        """
        version = self._make_version(version)
        type_ = self._make_index(type, Enum_Packet, bits=8, name='type', alias='OSPF')
        auth_type_ = self._make_index(auth_type, Enum_Authentication, bits=16,
                                      name='authentication type', alias='OSPF')

        if packet_length is None:
            packet_length = 24 + len(payload)
        else:
            packet_length = self._make_uint(packet_length, bits=16, name='packet length', alias='OSPF')

        schema = Schema_OSPFv1(
            version=version,
            type=type_,
            length=packet_length,
            router_id=router_id,
            area_id=area_id,
            checksum=(b'\x00\x00' if checksum is None
                      else self._make_octets(checksum, size=2, name='checksum', alias='OSPF')),
            auth_type=auth_type_,
            auth_data=self._make_octets(auth_data, size=8, name='authentication data', alias='OSPF'),
            payload=payload,
            trailer=trailer,
        )
        if checksum is None and config.CHECKSUM_COMPUTE:
            self._compute_checksum(schema, packet_length)
        return schema

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[24]':
        """Return an estimated length for the object."""
        return 24

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_OSPFv1') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'version': cls._rebuilt_version(data, 1),
            'type': data.type,
            'packet_length': data.get('len'),
            'router_id': data.router_id,
            'area_id': data.area_id,
            'checksum': data.chksum,
            'auth_type': data.autype,
            'auth_data': data.auth,
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Packet Length (#1455).
            'trailer': data.get('trailer', b''),
        }

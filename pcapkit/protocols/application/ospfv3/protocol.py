# -*- coding: utf-8 -*-
"""OSPFv3 - Open Shortest Path First version 3
=================================================

.. module:: pcapkit.protocols.application.ospfv3.protocol

:mod:`pcapkit.protocols.application.ospfv3.protocol` holds
:class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`, the extractor for
OSPF for IPv6 (OSPFv3) [:rfc:`5340`], whose 16-octet header
(:rfc:`5340#appendix-A.3.1`) has an Instance ID and a reserved octet in place of
OSPFv2's AuType and Authentication:

.. table::

   ====== ===== ==================== ===============================
   Octets Bits  Name                 Description
   ====== ===== ==================== ===============================
   0          0 ``ospf.version``     Version Number
   ------ ----- -------------------- -------------------------------
   1          8 ``ospf.type``        Type
   ------ ----- -------------------- -------------------------------
   2         16 ``ospf.len``         Packet Length (header included)
   ------ ----- -------------------- -------------------------------
   4         32 ``ospf.router_id``   Router ID
   ------ ----- -------------------- -------------------------------
   8         64 ``ospf.area_id``     Area ID
   ------ ----- -------------------- -------------------------------
   12        96 ``ospf.chksum``      Checksum
   ------ ----- -------------------- -------------------------------
   14       112 ``ospf.instance_id`` Instance ID
   ------ ----- -------------------- -------------------------------
   15       120 ``ospf.reserved``    Reserved
   ====== ===== ==================== ===============================

.. versionadded:: 1.8.1

"""
from typing import TYPE_CHECKING

from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.schema.shortread import cut_on_its_own
from pcapkit.protocols.application.ospf.protocol import OSPF
from pcapkit.protocols.application.ospfv3.data import OSPFv3 as Data_OSPFv3
from pcapkit.protocols.application.ospfv3.schema import OSPFv3 as Schema_OSPFv3
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['OSPFv3']


class OSPFv3(OSPF[Data_OSPFv3, Schema_OSPFv3],
             schema=Schema_OSPFv3, data=Data_OSPFv3):
    """This class implements OSPF for IPv6 (OSPF version 3).

    Its checksum covers an IPv6 pseudo-header (:rfc:`5340#appendix-A.3.1`), so it is
    neither verified nor computed.

    .. versionadded:: 1.8.1

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self) -> 'Literal[16]':
        """Header length of current protocol."""
        return 16

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["OSPFv3"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member.

        """
        return ('OSPFv3',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_OSPFv3':
        """Read OSPF for IPv6.

        Structure of OSPFv3 header [:rfc:`5340`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |   Version #   |     Type      |         Packet length         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Router ID                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                          Area ID                              |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Checksum             |  Instance ID  |      0        |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the Version is not 3.

        """
        schema = self.__header__
        if not cut_on_its_own(schema, 'version') and schema.version != 3:
            raise ProtocolError(f'OSPFv3: invalid version: {schema.version}')

        # Set before _decode_next_layer below, which reads self.alias.
        self._version = schema.version

        ospf = Data_OSPFv3(
            version=schema.version,
            type=schema.type,
            len=schema.length,
            router_id=schema.router_id,
            area_id=schema.area_id,
            chksum=schema.checksum,
            instance_id=schema.instance_id,
            reserved=schema.reserved,
        )
        length = schema.length if schema.length else (length or len(self))

        # NOTE: Octets past the Packet Length belong to this layer, as its length
        # leaves them out, and are rebuilt as captured (#1455).
        if schema.trailer:
            ospf.__update__([
                ('trailer', schema.trailer),
            ])

        # NOTE: The body is handed on at octet 16, on the -1 sentinel, as for OSPFv2 (#3105).
        return self._decode_next_layer(ospf, -1, length - self.length)

    def make(self, *,
             version: 'int' = 3,
             type: 'Enum_Packet | int' = Enum_Packet.Hello,
             packet_length: 'Optional[int]' = None,
             router_id: 'IPv4Address | str | bytes' = '0.0.0.0',  # nosec: B104
             area_id: 'IPv4Address | str | bytes' = '0.0.0.0',  # nosec: B104
             checksum: 'Optional[bytes]' = None,
             instance_id: 'int' = 0,
             reserved: 'bytes' = b'\x00',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_OSPFv3':
        """Make (construct) packet data.

        Args:
            version: OSPF version number, ``3``.
            type: OSPF packet type.
            packet_length: Packet length (header included). If not given, it is
                computed as 16 plus the length of ``payload``.
            router_id: Router ID.
            area_id: Area ID.
            checksum: Checksum, zero if :data:`None`: it covers an IPv6
                pseudo-header, so none is computed.
            instance_id: Instance ID.
            reserved: The reserved octet after the Instance ID.
            payload: Payload data.
            trailer: Octets after the packet, outside the Packet Length; written
                as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``version`` is not 3; if ``packet_length`` is not an
                :obj:`int` in ``0..65535``; if ``checksum`` is not two octets; if
                ``instance_id`` is not an :obj:`int` in ``0..255``; if
                ``reserved`` is not one octet; or if ``type`` is a name, a
                :obj:`bool`, or a member or code its 8 bits cannot carry.

        """
        version = self._make_version(version)
        type_ = self._make_index(type, Enum_Packet, bits=8, name='type', alias='OSPF')
        return Schema_OSPFv3(
            version=version,
            type=type_,
            length=(16 + len(payload) if packet_length is None
                    else self._make_uint(packet_length, bits=16, name='packet length', alias='OSPF')),
            router_id=router_id,
            area_id=area_id,
            checksum=(b'\x00\x00' if checksum is None
                      else self._make_octets(checksum, size=2, name='checksum', alias='OSPF')),
            instance_id=self._make_uint(instance_id, bits=8, name='instance ID', alias='OSPF'),
            reserved=self._make_octets(reserved, size=1, name='reserved octet', alias='OSPF'),
            payload=payload,
            trailer=trailer,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_OSPFv3') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'version': cls._rebuilt_version(data, 3),
            'type': data.type,
            'packet_length': data.get('len'),
            'router_id': data.router_id,
            'area_id': data.area_id,
            'checksum': data.chksum,
            'instance_id': data.instance_id,
            # NOTE: A reserved octet a capture cut is zero-filled (#1458).
            'reserved': cls._fill_short_read(data.get('reserved', b'\x00'), size=1,
                                             model=data, field='reserved'),
            'payload': cls._make_payload(data),
            'trailer': data.get('trailer', b''),
        }

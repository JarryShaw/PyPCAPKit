# -*- coding: utf-8 -*-
"""OSPFv2 - Open Shortest Path First version 2
=================================================

.. module:: pcapkit.protocols.application.ospfv2.protocol

:mod:`pcapkit.protocols.application.ospfv2.protocol` holds
:class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`, the extractor for
Open Shortest Path First version 2 (OSPFv2) [:rfc:`2328`], whose header
(:rfc:`2328#appendix-A.3.1`) is:

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

.. versionadded:: 1.8.1

   Takes over the parsing that :class:`~pcapkit.protocols.application.ospf.protocol.OSPF`
   carried, with its header schema and data model (:issue:`3105`).

"""
import collections.abc
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.corekit.schema.ipaddress import parse_ip_address
from pcapkit.corekit.schema.shortread import cut_on_its_own
from pcapkit.protocols.application.ospf.protocol import OSPF
from pcapkit.protocols.application.ospfv2.data import \
    CryptographicAuthentication as Data_CryptographicAuthentication
from pcapkit.protocols.application.ospfv2.data import OSPFv2 as Data_OSPFv2
from pcapkit.protocols.application.ospfv2.schema import \
    CryptographicAuthentication as Schema_CryptographicAuthentication
from pcapkit.protocols.application.ospfv2.schema import OSPFv2 as Schema_OSPFv2
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.schema import Schema

__all__ = ['OSPFv2']


class OSPFv2(OSPF[Data_OSPFv2, Schema_OSPFv2],
             schema=Schema_OSPFv2, data=Data_OSPFv2):
    """This class implements Open Shortest Path First version 2.

    .. versionadded:: 1.8.1

       Takes over the parsing that :class:`~pcapkit.protocols.application.ospf.protocol.OSPF`
       carried (:issue:`3105`).

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
    def id(cls) -> 'tuple[Literal["OSPFv2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member.

        """
        return ('OSPFv2',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_OSPFv2':
        """Read Open Shortest Path First version 2.

        Structure of OSPFv2 header [:rfc:`2328`]:

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
            ProtocolError: If the Version is not 2 (:rfc:`2328#section-8.2`).

        """
        schema = self.__header__
        if not cut_on_its_own(schema, 'version') and schema.version != 2:
            raise ProtocolError(f'OSPFv2: invalid version: {schema.version}')

        # Set before _decode_next_layer below, which reads self.alias.
        self._version = schema.version

        ospf = Data_OSPFv2(
            version=schema.version,
            type=schema.type,
            len=schema.length,
            router_id=schema.router_id,
            area_id=schema.area_id,
            chksum=schema.checksum,
            autype=schema.auth_type,
        )
        length = schema.length if schema.length else (length or len(self))

        if ospf.autype == Enum_Authentication.Cryptographic_authentication:
            ospf.__update__([
                ('auth', self._read_encrypt_auth(
                    cast('Schema_CryptographicAuthentication', schema.auth_data),
                )),
            ])
        else:
            ospf.__update__([
                ('auth', cast('bytes', schema.auth_data)),
            ])

        # NOTE: Octets past the Packet Length (a cryptographic digest among them) belong to
        # this layer, as its length leaves them out, and are rebuilt as captured (#1455).
        if schema.trailer:
            ospf.__update__([
                ('trailer', schema.trailer),
            ])

        # NOTE: Cryptographic authentication leaves it unused (RFC 2328 D.4.3), and a cut
        # before the Version octet leaves nothing to verify.
        if ospf.version == 2:
            self._verify_checksum(ospf, ospf.autype == Enum_Authentication.Cryptographic_authentication)

        # OSPF carries no next-protocol field -- the body is LSAs and packet-type
        # specific fields, which pcapkit does not dissect -- so dispatch on the
        # -1 sentinel, as ARP does, rather than on a code read off the wire;
        # ``Application._decode_next_layer`` refuses any other value.
        return self._decode_next_layer(ospf, -1, length - self.length)

    def make(self, *,
             version: 'int' = 2,
             type: 'Enum_Packet | int' = Enum_Packet.Hello,
             packet_length: 'Optional[int]' = None,
             router_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             area_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             checksum: 'Optional[bytes]' = None,
             auth_type: 'Enum_Authentication | int' = Enum_Authentication.No_Authentication,
             auth_data: 'bytes | Schema_CryptographicAuthentication | Data_CryptographicAuthentication | dict[str, Any]' = b'\x00\x00\x00\x00\x00\x00\x00\x00',  # pylint: disable=line-too-long
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_OSPFv2':
        """Make (construct) packet data.

        Args:
            version: OSPF version number, ``2``.
            type: OSPF packet type.
            packet_length: Packet length (header included). If not given, it is
                computed as 24 plus the length of ``payload``. Give it
                explicitly when ``payload`` carries octets outside the OSPF
                packet, or pass those as ``trailer`` instead.
            router_id: Router ID.
            area_id: Area ID.
            checksum: Checksum; if :data:`None` and
                :data:`~pcapkit.utilities.config.CHECKSUM_COMPUTE` is on, computed
                for version 2 over the packet but its authentication field
                (:rfc:`2328#appendix-A.3.1`); zero otherwise, as cryptographic
                authentication leaves it (:rfc:`2328#appendix-D.4.3`).
            auth_type: Authentication type.
            auth_data: Authentication data: 8 octets, or, under cryptographic
                authentication, also a schema, a data model, or the
                :obj:`dict` form of a data model.
            payload: Payload data.
            trailer: Octets after the packet, outside the Packet Length, such
                as the message digest appended under cryptographic
                authentication (:rfc:`2328#appendix-D.4.3`); written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``version`` is not 2; if ``auth_data`` is of an invalid
                type, is :obj:`bytes` that are not exactly 8 octets long, is a
                :obj:`dict` missing a required key, or carries ``reserved`` octets
                that are not two; if
                ``packet_length`` is not an :obj:`int` in ``0..65535``; if
                ``checksum`` is not two octets; or if ``type`` (8 bits) or
                ``auth_type`` (16 bits) is a name, a :obj:`bool`, or a member or
                code its field cannot carry.

        """
        version = self._make_version(version)
        type_ = self._make_index(type, Enum_Packet, bits=8, name='type', alias='OSPF')
        auth_type_ = self._make_index(auth_type, Enum_Authentication, bits=16,
                                      name='authentication type', alias='OSPF')

        data: 'bytes | Schema_CryptographicAuthentication'
        if auth_type_ == Enum_Authentication.Cryptographic_authentication:
            data = self._make_encrypt_auth(auth_data)
        else:
            if not isinstance(auth_data, bytes):
                raise ProtocolError(f'OSPF: invalid type for authentication data: {auth_data!r}')
            if len(auth_data) != 8:
                raise ProtocolError(f'OSPF: authentication data must be 8 octets: {auth_data!r}')
            data = auth_data

        if packet_length is None:
            packet_length = 24 + len(payload)
        else:
            packet_length = self._make_uint(packet_length, bits=16, name='packet length', alias='OSPF')

        schema = Schema_OSPFv2(
            version=version,
            type=type_,
            length=packet_length,
            router_id=router_id,
            area_id=area_id,
            checksum=(b'\x00\x00' if checksum is None
                      else self._make_octets(checksum, size=2, name='checksum', alias='OSPF')),
            auth_type=auth_type_,
            auth_data=data,
            payload=payload,
            trailer=trailer,
        )

        if (checksum is None and config.CHECKSUM_COMPUTE and version == 2
                and auth_type_ != Enum_Authentication.Cryptographic_authentication):
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
    def _make_data(cls, data: 'Data_OSPFv2') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        auth = data.auth  # type: Any
        # NOTE: Reserved octets a capture cut inside are zero-filled (#1458), in
        # the data model or the dict form ``to_dict()`` gives of it.
        if isinstance(auth, collections.abc.Mapping):
            reserved = auth.get('reserved', b'\x00\x00')
            filled = cls._fill_short_read(reserved, size=2, model=data, field='auth_data')
            if filled is not reserved:
                auth = {**auth, 'reserved': filled}
        return {
            'version': cls._rebuilt_version(data, 2),
            'type': data.type,
            'packet_length': data.get('len'),
            'router_id': data.router_id,
            'area_id': data.area_id,
            'checksum': data.chksum,
            'auth_type': data.autype,
            'auth_data': auth,
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Packet Length (#1455).
            'trailer': data.get('trailer', b''),
        }

    def _read_encrypt_auth(self, schema: 'Schema_CryptographicAuthentication') -> 'Data_CryptographicAuthentication':
        """Read Authentication field when Cryptographic Authentication is employed,
        i.e. :attr:`~pcapkit.protocols.application.ospfv2.data.OSPFv2.autype` is ``2``.

        Structure of Cryptographic Authentication [:rfc:`2328`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              0                |    Key ID     | Auth Data Len |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Cryptographic sequence number                 |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            schema: parsed authentication data

        Returns:
            Parsed packet data.

        """
        auth = Data_CryptographicAuthentication(
            reserved=schema.reserved,
            key_id=schema.key_id,
            len=schema.len,
            seq=schema.seq,
        )
        return auth

    def _make_encrypt_auth(self,
                           auth_data: 'bytes | Schema_CryptographicAuthentication | Data_CryptographicAuthentication | dict[str, Any]'  # pylint: disable=line-too-long
                           ) -> 'Schema_CryptographicAuthentication':
        """Make Authentication field when Cryptographic Authentication is employed.

        Args:
            auth_data: Authentication data, as raw octets, a schema, a data
                model, or the :obj:`dict` form of a data model.

        Returns:
            Authentication schema.

        Raises:
            ProtocolError: If ``auth_data`` is of an invalid type, is
                :obj:`bytes` that are not exactly 8 octets long, is a
                :obj:`dict` missing a required key, or carries ``reserved``
                octets that are not two.

        """
        if isinstance(auth_data, Schema_CryptographicAuthentication):
            return auth_data
        if isinstance(auth_data, bytes):
            if len(auth_data) != 8:
                raise ProtocolError(f'OSPF: authentication data must be 8 octets: {auth_data!r}')
            return Schema_CryptographicAuthentication.unpack(auth_data)  # type: ignore[call-arg,misc]
        if isinstance(auth_data, Data_CryptographicAuthentication):
            return Schema_CryptographicAuthentication(
                reserved=self._make_octets(getattr(auth_data, 'reserved', b'\x00\x00'), size=2,
                                           name='reserved octets', alias='OSPF'),
                key_id=auth_data.key_id,
                len=auth_data.len,
                seq=auth_data.seq,
            )
        # NOTE: The ``to_dict()`` form of the info above, which ``from_data``
        # passes through as is (#1464).
        if isinstance(auth_data, dict):
            try:
                return Schema_CryptographicAuthentication(
                    reserved=self._make_octets(auth_data.get('reserved', b'\x00\x00'), size=2,
                                               name='reserved octets', alias='OSPF'),
                    key_id=auth_data['key_id'],
                    len=auth_data['len'],
                    seq=auth_data['seq'],
                )
            except KeyError as exc:
                raise ProtocolError(f'OSPF: missing {exc} in auth_data: {auth_data!r}') from None
        raise ProtocolError(f'OSPF: invalid type for auth_data: {auth_data!r}')

    def _read_id_numbers(self, id: 'bytes') -> 'IPv4Address':
        """Read router and area IDs.

        Args:
            id: ID bytes.

        Returns:
            Parsed IDs as an IPv4 address.

        """
        #_byte = self._read_fileng(4)
        #_addr = '.'.join(str(_) for _ in _byte)
        return ipaddress.ip_address(id)  # type: ignore[return-value]

    def _make_id_numbers(self, id: 'IPv4Address | str | bytes | bytearray') -> 'bytes':
        """Make router and area IDs.

        Args:
            id: ID.

        Returns:
            ID bytes.

        Raises:
            FieldValueError: If ``id`` is a :obj:`bool` (see
                :func:`~pcapkit.corekit.schema.ipaddress.parse_ip_address`).

        Notes:
            Latent rather than live: nothing in this module calls this method
            (:meth:`make` builds ``router_id``/``area_id`` straight from its
            own arguments), so the only caller is a unit test. It is routed
            through :func:`~pcapkit.corekit.schema.ipaddress.parse_ip_address`
            anyway, so that a future caller passing a :obj:`bool` gets
            :exc:`~pcapkit.utilities.exceptions.FieldValueError` rather than a
            silent ``0.0.0.1``.

        """
        return cast('IPv4Address', parse_ip_address(
            id, f'{self.__class__.__name__}: invalid ID', version=4)).packed

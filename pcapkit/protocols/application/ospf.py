# -*- coding: utf-8 -*-
"""OSPF - Open Shortest Path First
=====================================

.. module:: pcapkit.protocols.application.ospf

:mod:`pcapkit.protocols.application.ospf` contains
:class:`~pcapkit.protocols.application.ospf.OSPF` only,
which implements extractor for Open Shortest Path
First (OSPF) [*]_, whose structure is described
as below:

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

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First

"""
import ipaddress
import re
from typing import TYPE_CHECKING, cast

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import parse_ip_address
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.data.application.ospf import OSPF as Data_OSPF
from pcapkit.protocols.data.application.ospf import \
    CryptographicAuthentication as Data_CryptographicAuthentication
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.schema.application.ospf import OSPF as Schema_OSPF
from pcapkit.protocols.schema.application.ospf import \
    CryptographicAuthentication as Schema_CryptographicAuthentication
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.schema.schema import Schema

__all__ = ['OSPF']

# Ethernet address pattern
PAT_MAC_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


class OSPF(Application[Data_OSPF, Schema_OSPF],
           schema=Schema_OSPF, data=Data_OSPF):
    """This class implements Open Shortest Path First.

    A routing protocol computes the forwarding table rather than forwarding
    packets, so it is a *user* of the stack rather than part of its forwarding
    path. :rfc:`1812#section-7` places it accordingly, titling that chapter
    "APPLICATION LAYER - ROUTING PROTOCOLS" with OSPF at §7.2.2, while
    :rfc:`1812#section-4.1` confines the internet layer to IP, ICMP and IGMP.
    Hence :class:`~pcapkit.protocols.application.application.Application` as the
    base, and ``layer == 'Application'``. See
    :doc:`/contributing/conventions/protocol-layer-placement`.

    Note:
        The subpackage does not track the dispatch tier. OSPF is dispatched
        from :attr:`Internet.__proto__
        <pcapkit.protocols.internet.internet.Internet.__proto__>` at
        :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP` (IANA protocol
        number 89), since IP is what carries it.

    """
    #: Version number of corresponding protocol, as read off the header. Held on
    #: the instance rather than read back out of :attr:`self._info
    #: <pcapkit.protocols.protocol.Protocol._info>` because :attr:`name` and
    #: :attr:`alias` are needed *during* :meth:`read` -- :meth:`self._decode_next_layer
    #: <pcapkit.protocols.protocol.Protocol._decode_next_layer>` builds the
    #: protocol chain out of :attr:`alias` -- and ``_info`` is not assigned until
    #: :meth:`read` has returned. c.f. ``ARP._acnm`` on
    #: :class:`~pcapkit.protocols.link.arp.ARP`, which has the same constraint.
    _version: 'int'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of current protocol."""
        return f'Open Shortest Path First version {self._version}'

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol."""
        return f'OSPFv{self._version}'

    @property
    def length(self) -> 'Literal[24]':
        """Header length of current protocol."""
        return 24

    @property
    def type(self) -> 'Enum_Packet':
        """OSPF packet type."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_OSPF':
        """Read Open Shortest Path First.

        Structure of OSPF header [:rfc:`2328`]:

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

        """
        schema = self.__header__

        # Set before _decode_next_layer below, which reads self.alias.
        self._version = schema.version

        ospf = Data_OSPF(
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

        # NOTE: Octets captured past the Packet Length belong to this layer,
        # since its own length field is what leaves them out of the payload --
        # the message digest of cryptographic authentication among them -- and
        # the rebuild keeps them as captured (:issue:`1455`).
        if schema.trailer:
            ospf.__update__([
                ('trailer', schema.trailer),
            ])
        # OSPF carries no next-protocol field -- the body is LSAs and packet-type
        # specific fields, which pcapkit does not dissect -- so dispatch on the
        # -1 sentinel, as ARP does, rather than on a code read off the wire;
        # ``Application._decode_next_layer`` refuses any other value.
        return self._decode_next_layer(ospf, -1, length - self.length)

    def make(self,
             version: 'int' = 2,
             type: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.Hello,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             packet_length: 'Optional[int]' = None,
             router_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             area_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             checksum: 'bytes' = b'\x00\x00',
             auth_type: 'Enum_Authentication | StdlibEnum | AenumEnum | str | int' = Enum_Authentication.No_Authentication,
             auth_type_default: 'Optional[int]' = None,
             auth_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             auth_type_reversed: 'bool' = False,
             auth_data: 'bytes | Schema_CryptographicAuthentication | Data_CryptographicAuthentication' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_OSPF':
        """Make (construct) packet data.

        Args:
            version: OSPF version number.
            type: OSPF packet type.
            type_default: Default value for ``type`` if not specified.
            type_namespace: Namespace for ``type``.
            type_reversed: Reverse namespace for ``type``.
            packet_length: Packet length (header included). If not given, it is
                computed as 24 plus the length of ``payload``. Give it
                explicitly when ``payload`` carries octets outside the OSPF
                packet, or pass those as ``trailer`` instead.
            router_id: Router ID.
            area_id: Area ID.
            checksum: Checksum.
            auth_type: Authentication type.
            auth_type_default: Default value for ``auth_type`` if not specified.
            auth_type_namespace: Namespace for ``auth_type``.
            auth_type_reversed: Reverse namespace for ``auth_type``.
            auth_data: Authentication data.
            payload: Payload data.
            trailer: Octets after the packet, outside the Packet Length, such
                as the message digest appended under cryptographic
                authentication (:rfc:`2328#appendix-D.4.3`); written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``auth_data`` is of an invalid type, or is
                :obj:`bytes` that are not exactly 8 octets long; or if
                ``packet_length`` is not an :obj:`int` in ``0..65535``.

        """
        type_ = self._make_index(type, type_default, namespace=type_namespace,
                                 reversed=type_reversed, pack=False)
        auth_type_ = self._make_index(auth_type, auth_type_default, namespace=auth_type_namespace,
                                      reversed=auth_type_reversed, pack=False)

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
        elif (not isinstance(packet_length, int) or isinstance(packet_length, bool)
              or not 0 <= packet_length <= 0xFFFF):
            raise ProtocolError(f'OSPF: invalid packet length: {packet_length!r}')

        return Schema_OSPF(
            version=version,
            type=type_,  # type: ignore[arg-type]
            length=packet_length,
            router_id=router_id,
            area_id=area_id,
            checksum=checksum,
            auth_type=auth_type_,  # type: ignore[arg-type]
            auth_data=data,
            payload=payload,
            trailer=trailer,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[24]':
        """Return an estimated length for the object."""
        return 24

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.OSPFIGP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_OSPF') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'version': data.version,
            'type': data.type,
            'packet_length': data.get('len'),
            'router_id': data.router_id,
            'area_id': data.area_id,
            'checksum': data.chksum,
            'auth_type': data.autype,
            'auth_data': data.auth,
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Packet Length (:issue:`1455`).
            'trailer': data.get('trailer', b''),
        }

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
            FieldValueError: If ``id`` is a :obj:`bool` (c.f.
                :func:`~pcapkit.corekit.fields.ipaddress.parse_ip_address`).

        Notes:
            Latent rather than live: nothing in this module calls this method
            (:meth:`make` builds ``router_id``/``area_id`` straight from its
            own arguments), so the only caller is a unit test. It is routed
            through :func:`parse_ip_address` anyway, so that a future caller passing a
            :obj:`bool` gets :exc:`~pcapkit.utilities.exceptions.FieldValueError`
            rather than a silent ``0.0.0.1``.

            The description below uses :attr:`self.__class__.__name__
            <type.__name__>` rather than :attr:`self.alias
            <pcapkit.protocols.protocol.Protocol.alias>`, because ``alias``
            here reads ``self._version``, which :meth:`read` only assigns
            from the wire -- unavailable to a construction-only instance that
            never went through :meth:`read`.

        """
        return cast('IPv4Address', parse_ip_address(
            id, f'{self.__class__.__name__}: invalid ID', version=4)).packed

    def _read_encrypt_auth(self, schema: 'Schema_CryptographicAuthentication') -> 'Data_CryptographicAuthentication':
        """Read Authentication field when Cryptographic Authentication is employed,
        i.e. :attr:`~OSPF.autype` is ``2``.

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
                           auth_data: 'bytes | Schema_CryptographicAuthentication | Data_CryptographicAuthentication'  # pylint: disable=line-too-long
                           ) -> 'Schema_CryptographicAuthentication':
        """Make Authentication field when Cryptographic Authentication is employed.

        Args:
            auth_data: Authentication data.

        Returns:
            Authentication schema.

        Raises:
            ProtocolError: If ``auth_data`` is of an invalid type, or is
                :obj:`bytes` that are not exactly 8 octets long.

        """
        if isinstance(auth_data, Schema_CryptographicAuthentication):
            return auth_data
        if isinstance(auth_data, bytes):
            if len(auth_data) != 8:
                raise ProtocolError(f'OSPF: authentication data must be 8 octets: {auth_data!r}')
            return Schema_CryptographicAuthentication.unpack(auth_data)  # type: ignore[call-arg,misc]
        if isinstance(auth_data, Data_CryptographicAuthentication):
            return Schema_CryptographicAuthentication(
                reserved=getattr(auth_data, 'reserved', b'\x00\x00'),
                key_id=auth_data.key_id,
                len=auth_data.len,
                seq=auth_data.seq,
            )
        raise ProtocolError(f'OSPF: invalid type for auth_data: {auth_data!r}')

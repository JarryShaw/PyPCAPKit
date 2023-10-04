# -*- coding: utf-8 -*-
"""OSPF - Open Shortest Path First
=====================================

.. module:: pcapkit.protocols.link.ospf

:mod:`pcapkit.protocols.link.ospf` contains
:class:`~pcapkit.protocols.link.ospf.OSPF` only,
which implements extractor for Open Shortest Path
First (OSPF) [*]_, whose structure is described
as below:

.. table::

   ====== ===== ================== ===============================
   Octets Bits  Name               Description
   ====== ===== ================== ===============================
   0          0 ``ospf.version``   Version Number
   ------ ----- ------------------ -------------------------------
   0          0 ``ospf.type``      Type
   ------ ----- ------------------ -------------------------------
   0          1 ``ospf.len``       Packet Length (header included)
   ------ ----- ------------------ -------------------------------
   0          2 ``ospf.router_id`` Router ID
   ------ ----- ------------------ -------------------------------
   0          4 ``ospf.area_id``   Area ID
   ------ ----- ------------------ -------------------------------
   0          6 ``ospf.chksum``    Checksum
   ------ ----- ------------------ -------------------------------
   0          7 ``ospf.autype``    Authentication Type
   ------ ----- ------------------ -------------------------------
   1          8 ``ospf.auth``      Authentication
   ====== ===== ================== ===============================

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First

"""
import ipaddress
import re
from typing import TYPE_CHECKING, cast

from pcapkit.const.ospf.authentication import Authentication as Enum_Authentication
from pcapkit.const.ospf.packet import Packet as Enum_Packet
from pcapkit.protocols.data.link.ospf import OSPF as Data_OSPF
from pcapkit.protocols.data.link.ospf import \
    CrytographicAuthentication as Data_CrytographicAuthentication
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.ospf import OSPF as Schema_OSPF
from pcapkit.protocols.schema.link.ospf import \
    CrytographicAuthentication as Schema_CrytographicAuthentication
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address
    from typing import Any, NoReturn, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['OSPF']

# Ethernet address pattern
PAT_MAC_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


class OSPF(Link[Data_OSPF, Schema_OSPF],
           schema=Schema_OSPF, data=Data_OSPF):
    """This class implements Open Shortest Path First."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of current protocol."""
        return f'Open Shortest Path First version {self._info.version}'

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol."""
        return f'OSPFv{self._info.version}'

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
        schema = self.__schema__

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
                    cast('Schema_CrytographicAuthentication', schema.auth_data),
                )),
            ])
        else:
            ospf.__update__([
                ('auth', cast('bytes', schema.auth_data)),
            ])
        return self._decode_next_layer(ospf, length - self.length)

    def make(self,
             version: 'int' = 2,
             type: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.Hello,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             router_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             area_id: 'IPv4Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             checksum: 'bytes' = b'\x00\x00',
             auth_type: 'Enum_Authentication | StdlibEnum | AenumEnum | str | int' = Enum_Authentication.No_Authentication,
             auth_type_default: 'Optional[int]' = None,
             auth_type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             auth_type_reversed: 'bool' = False,
             auth_data: 'bytes | Schema_CrytographicAuthentication | Data_CrytographicAuthentication' = b'\x00\x00\x00\x00\x00\x00\x00\x00',
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_OSPF':
        """Make (construct) packet data.

        Args:
            version: OSPF version number.
            type: OSPF packet type.
            type_default: Default value for ``type`` if not specified.
            type_namespace: Namespace for ``type``.
            type_reversed: Reverse namespace for ``type``.
            router_id: Router ID.
            area_id: Area ID.
            checksum: Checksum.
            auth_type: Authentication type.
            auth_type_default: Default value for ``auth_type`` if not specified.
            auth_type_namespace: Namespace for ``auth_type``.
            auth_type_reversed: Reverse namespace for ``auth_type``.
            auth_data: Authentication data.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        type_ = self._make_index(type, type_default, namespace=type_namespace,
                                 reversed=type_reversed, pack=False)
        auth_type_ = self._make_index(auth_type, auth_type_default, namespace=auth_type_namespace,
                                      reversed=auth_type_reversed, pack=False)

        if auth_type_ == Enum_Authentication.Cryptographic_authentication:
            data = self._make_encrypt_auth(auth_data)
        else:
            if not isinstance(auth_data, bytes):
                raise ProtocolError(f'OSPF: invalid type for authentication data: {auth_data!r}')
            data = auth_data

        return Schema_OSPF(
            version=version,
            type=type_,  # type: ignore[arg-type]
            length=24 + len(payload),
            router_id=router_id,
            area_id=area_id,
            checksum=checksum,
            auth_type=auth_type_,  # type: ignore[arg-type]
            auth_data=data,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[24]':
        """Return an estimated length for the object."""
        return 24

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

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
            'router_id': data.router_id,
            'area_id': data.area_id,
            'checksum': data.chksum,
            'auth_type': data.autype,
            'auth_data': data.auth,
            'payload': cls._make_payload(data)
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

        """
        return ipaddress.ip_address(id).packed

    def _read_encrypt_auth(self, schema: 'Schema_CrytographicAuthentication') -> 'Data_CrytographicAuthentication':
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
        auth = Data_CrytographicAuthentication(
            key_id=schema.key_id,
            len=schema.len,
            seq=schema.seq,
        )
        return auth

    def _make_encrypt_auth(self,
                           auth_data: 'bytes | Schema_CrytographicAuthentication | Data_CrytographicAuthentication'  # pylint: disable=line-too-long
                           ) -> 'bytes | Schema_CrytographicAuthentication':
        """Make Authentication field when Cryptographic Authentication is employed.

        Args:
            auth_type: Authentication type.
            auth_data: Authentication data.

        Returns:
            Authentication bytes.

        """
        if isinstance(auth_data, (Schema_CrytographicAuthentication, bytes)):
            return auth_data
        if isinstance(auth_data, Data_CrytographicAuthentication):
            return Schema_CrytographicAuthentication(
                key_id=auth_data.key_id,
                len=auth_data.len,
                seq=auth_data.seq,
            )
        raise ProtocolError(f'OSPF: invalid type for auth_data: {auth_data!r}')

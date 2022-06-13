# -*- coding: utf-8 -*-
"""OSPF - Open Shortest Path First
=====================================

:mod:`pcapkit.protocols.link.ospf` contains
:class:`~pcapkit.protocols.link.ospf.OSPF` only,
which implements extractor for Open Shortest Path
First (OSPF) [*]_, whose structure is described
as below:

+========+=======+====================+=================================+
| Octets | Bits  | Name               | Description                     |
+========+=======+====================+=================================+
| 0      |     0 | ``ospf.version``   | Version Number                  |
+--------+-------+--------------------+---------------------------------+
| 0      |     0 | ``ospf.type``      | Type                            |
+--------+-------+--------------------+---------------------------------+
| 0      |     1 | ``ospf.len``       | Packet Length (header included) |
+--------+-------+--------------------+---------------------------------+
| 0      |     2 | ``ospf.router_id`` | Router ID                       |
+--------+-------+--------------------+---------------------------------+
| 0      |     4 | ``ospf.area_id``   | Area ID                         |
+--------+-------+--------------------+---------------------------------+
| 0      |     6 | ``ospf.chksum``    | Checksum                        |
+--------+-------+--------------------+---------------------------------+
| 0      |     7 | ``ospf.autype``    | Authentication Type             |
+--------+-------+--------------------+---------------------------------+
| 1      |     8 | ``ospf.auth``      | Authentication                  |
+--------+-------+--------------------+---------------------------------+

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First

"""
import ipaddress
from typing import TYPE_CHECKING

from pcapkit.const.ospf.authentication import Authentication as RegType_Authentication
from pcapkit.const.ospf.packet import Packet as RegType_Packet
from pcapkit.protocols.data.link.ospf import OSPF as DataType_OSPF
from pcapkit.protocols.data.link.ospf import \
    CrytographicAuthentication as DataType_CrytographicAuthentication
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['OSPF']


class OSPF(Link[DataType_OSPF]):
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
    def type(self) -> 'RegType_Packet':
        """OSPF packet type."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_OSPF':
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
        if length is None:
            length = len(self)

        _vers = self._read_unpack(1)
        _type = self._read_unpack(1)
        _tlen = self._read_unpack(2)
        _rtid = self._read_id_numbers()
        _area = self._read_id_numbers()
        _csum = self._read_fileng(2)
        _autp = self._read_unpack(2)

        ospf = DataType_OSPF(
            version=_vers,
            type=RegType_Packet.get(_type),
            len=_tlen,
            router_id=_rtid,
            area_id=_area,
            chksum=_csum,
            autype=RegType_Authentication.get(_autp),
        )

        if ospf.autype == RegType_Authentication.Cryptographic_authentication:
            ospf.__update__([
                ('auth', self._read_encrypt_auth()),
            ])
        else:
            ospf.__update__([
                ('auth', self._read_fileng(8)),
            ])
        return self._decode_next_layer(ospf, length - self.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

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

    def _read_id_numbers(self) -> 'IPv4Address':
        """Read router and area IDs.

        Returns:
            Parsed IDs as an IPv4 address.

        """
        #_byte = self._read_fileng(4)
        #_addr = '.'.join(str(_) for _ in _byte)
        return ipaddress.ip_address(self._read_fileng(4))  # type: ignore[return-value]

    def _read_encrypt_auth(self) -> 'DataType_CrytographicAuthentication':
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
            length: packet length

        Returns:
            Parsed packet data.

        """
        _resv = self._read_fileng(2)
        _keys = self._read_unpack(1)
        _alen = self._read_unpack(1)
        _seqn = self._read_unpack(4)

        auth = DataType_CrytographicAuthentication(
            key_id=_keys,
            len=_alen,
            seq=_seqn,
        )
        return auth

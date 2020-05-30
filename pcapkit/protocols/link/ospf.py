# -*- coding: utf-8 -*-
"""open shortest path first

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

from pcapkit.const.ospf.authentication import Authentication as AUTH
from pcapkit.const.ospf.packet import Packet as TYPE
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['OSPF']


class OSPF(Link):
    """This class implements Open Shortest Path First."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: str
        """
        return f'Open Shortest Path First version {self._info.version}'  # pylint: disable=E1101

    @property
    def alias(self):
        """Acronym of current protocol.

        :rtype: str
        """
        return f'OSPFv{self._info.version}'  # pylint: disable=E1101

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: Literal[24]
        """
        return 24

    @property
    def type(self):
        """OSPF packet type.

        :rtype: pcapkit.const.ospf.packet.Packet
        """
        return self._info.type  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Open Shortest Path First.

        Structure of OSPF header [:rfc:`2328`]::

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
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_OSPF: Parsed packet data.

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

        ospf = dict(
            version=_vers,
            type=TYPE.get(_type),
            len=_tlen,
            router_id=_rtid,
            area_id=_area,
            chksum=_csum,
            autype=AUTH.get(_autp) or 'Reserved',
        )

        if _autp == 2:
            ospf['auth'] = self._read_encrypt_auth()
        else:
            ospf['auth'] = self._read_fileng(8)

        length = ospf['len'] - 24
        ospf['packet'] = self._read_packet(header=24, payload=length)

        return self._decode_next_layer(ospf, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[24]
        """
        return 24

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_id_numbers(self):
        """Read router and area IDs.

        Returns:
            IPv4Address: Parsed IDs as an IPv4 address.

        """
        #_byte = self._read_fileng(4)
        #_addr = '.'.join(str(_) for _ in _byte)
        return ipaddress.ip_address(self._read_fileng(4))

    def _read_encrypt_auth(self):
        """Read Authentication field when Cryptographic Authentication is employed,
        i.e. :attr:`~OSPF.autype` is ``2``.

        Structure of Cryptographic Authentication [:rfc:`2328`]::

             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |              0                |    Key ID     | Auth Data Len |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                 Cryptographic sequence number                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length (int): packet length

        Returns:
            DataType_Auth: Parsed packet data.

                class Auth(TypedDict):
                    \"\"\"Cryptographic  authentication.\"\"\"

                    #: key ID
                    key_id: int
                    #: authentication data length
                    len: int
                    #: cryptographic sequence number
                    seq: int

        """
        _resv = self._read_fileng(2)
        _keys = self._read_unpack(1)
        _alen = self._read_unpack(1)
        _seqn = self._read_unpack(4)

        auth = dict(
            key_id=_keys,
            len=_alen,
            seq=_seqn,
        )

        return auth

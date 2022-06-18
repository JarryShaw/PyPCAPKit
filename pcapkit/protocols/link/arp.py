# -*- coding: utf-8 -*-
"""ARP/InARP - (Inverse) Address Resolution Protocol
=======================================================

:mod:`pcapkit.protocols.link.arp` contains
:class:`~pcapkit.protocols.link.arp.ARP` only,
which implements extractor for (Inverse) Address Resolution
Protocol (ARP/InARP) [*]_, whose structure is described as
below:

+========+=======+===============+=========================+
| Octets | Bits  | Name          | Description             |
+========+=======+===============+=========================+
| 0      |     0 | ``arp.htype`` | Hardware Type           |
+--------+-------+---------------+-------------------------+
| 2      |    16 | ``arp.ptype`` | Protocol Type           |
+--------+-------+---------------+-------------------------+
| 4      |    32 | ``arp.hlen``  | Hardware Address Length |
+--------+-------+---------------+-------------------------+
| 5      |    40 | ``arp.plen``  | Protocol Address Length |
+--------+-------+---------------+-------------------------+
| 6      |    48 | ``arp.oper``  | Operation               |
+--------+-------+---------------+-------------------------+
| 8      |    64 | ``arp.sha``   | Sender Hardware Address |
+--------+-------+---------------+-------------------------+
| 14     |   112 | ``arp.spa``   | Sender Protocol Address |
+--------+-------+---------------+-------------------------+
| 18     |   144 | ``arp.tha``   | Target Hardware Address |
+--------+-------+---------------+-------------------------+
| 24     |   192 | ``arp.tpa``   | Target Protocol Address |
+--------+-------+---------------+-------------------------+

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol

"""
import ipaddress
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as RegType_Hardware
from pcapkit.const.arp.operation import Operation as RegType_Operation
from pcapkit.const.reg.ethertype import EtherType as RegType_EtherType
from pcapkit.protocols.data.link.arp import ARP as DataType_ARP
from pcapkit.protocols.data.link.arp import Address as DataType_Address
from pcapkit.protocols.data.link.arp import Type as DataType_Type
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.compat import cached_property

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['ARP']

# check Python version
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)


class ARP(Link[DataType_ARP]):
    """This class implements all protocols in ARP family.

    - Address Resolution Protocol (:class:`~pcapkit.protocols.link.arp.ARP`) [:rfc:`826`]
    - Reverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.rarp.RARP`) [:rfc:`903`]
    - Dynamic Reverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.DRARP`) [:rfc:`1931`]
    - Inverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.InARP`) [:rfc:`2390`]

    """
    #: Name of corresponding protocol.
    _name: 'Literal["Address Resolution Protocol", "Inverse Address Resolution Protocol", "Reverse Address Resolution Protocol", "Dynamic Reverse Address Resolution Protocol"]'  # pylint: disable=line-too-long
    #: Acronym of corresponding protocol.
    _acnm: 'Literal["ARP", "InARP", "RARP", "DRARP"]'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Dynamic Reverse Address Resolution Protocol", "Inverse Address Resolution Protocol", "Reverse Address Resolution Protocol", "Address Resolution Protocol"]':  # pylint: disable=line-too-long
        """Name of current protocol."""
        return self._name

    @property
    def alias(self) -> 'Literal["ARP", "InARP", "RARP", "DRARP"]':
        """Acronym of corresponding protocol."""
        return self._acnm

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.len

    @cached_property
    def src(self) -> 'DataType_Address':
        """Sender hardware & protocol address."""
        return DataType_Address(self._info.sha, self._info.spa)

    @cached_property
    def dst(self) -> 'DataType_Address':
        """Target hardware & protocol address."""
        return DataType_Address(self._info.tha, self._info.tpa)

    @cached_property
    def type(self) -> 'DataType_Type':
        """Hardware & protocol type."""
        return DataType_Type(self._info.htype, self._info.ptype)

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ARP"], Literal["InARP"]]':
        """Index ID of the protocol."""
        return ('ARP', 'InARP')

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_ARP':  # pylint: disable=unused-argument
        r"""Read Address Resolution Protocol.

        Data structure of ARP Request header [:rfc:`826`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Hdr Type             |         Proto Type            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |    Hdr Len    |   Proto Len   |          Operation            |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \                       Sender Hdr Addr                         \
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \                      Sender Proto Addr                        \
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \                       Target Hdr Addr                         \
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           \                      Target Proto Addr                        \
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = self.__len__()

        _hwty = self._read_unpack(2)
        _ptty = self._read_unpack(2)
        _hlen = self._read_unpack(1)
        _plen = self._read_unpack(1)
        _oper = self._read_unpack(2)
        _shwa = self._read_addr_resolve(_hlen, _hwty)
        _spta = self._read_proto_resolve(_plen, _ptty)
        _thwa = self._read_addr_resolve(_hlen, _hwty)
        _tpta = self._read_proto_resolve(_plen, _ptty)

        if _oper in (5, 6, 7):
            self._acnm = 'DRARP'
            self._name = 'Dynamic Reverse Address Resolution Protocol'
        elif _oper in (8, 9):
            self._acnm = 'InARP'
            self._name = 'Inverse Address Resolution Protocol'
        elif _oper in (3, 4):
            self._acnm = 'RARP'
            self._name = 'Reverse Address Resolution Protocol'
        else:
            self._acnm = 'ARP'
            self._name = 'Address Resolution Protocol'

        _htype = RegType_Hardware.get(_hwty)
        _ptype = RegType_EtherType.get(_ptty)

        arp = DataType_ARP(
            htype=_htype,
            ptype=_ptype,
            hlen=_hlen,
            plen=_plen,
            oper=RegType_Operation.get(_oper),
            sha=_shwa,
            spa=_spta,
            tha=_thwa,
            tpa=_tpta,
            len=8 + _hlen * 2 + _plen * 2,
        )
        return self._decode_next_layer(arp, -1, length - arp.len)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[28]':
        """Return an estimated length for the object."""
        return 28

    @classmethod
    def __index__(cls) -> 'RegType_EtherType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

        """
        return RegType_EtherType.Address_Resolution_Protocol  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_addr_resolve(self, length: 'int', htype: 'int') -> 'str':
        """Resolve headware address according to protocol.

        Arguments:
            length: Hardware address length.
            htype: Hardware type.

        Returns:
            Hardware address. If ``htype`` is ``1``, i.e. MAC address,
            returns ``:`` seperated *hex* encoded MAC address.

        """
        if htype == 1:  # Ethernet
            _byte = self._read_fileng(length)
            if py38:
                _addr = _byte.hex(':')
            else:
                _addr = ':'.join(textwrap.wrap(_byte.hex(), 2))
        else:
            _addr = self._read_fileng(length).hex()
        return _addr

    def _read_proto_resolve(self, length: 'int', ptype: 'int') -> 'str | IPv4Address | IPv6Address':
        """Resolve protocol address according to protocol.

        Arguments:
            length: Protocol address length.
            ptype: Protocol type.

        Returns:
            Protocol address. If ``ptype`` is ``0x0800``, i.e. IPv4 adddress,
            returns an :class:`~ipaddress.IPv4Address` object; if ``ptype`` is
            ``0x86dd``, i.e. IPv6 address, returns an :class:`~ipaddress.IPv6Address`
            object; otherwise, returns a raw :data:`str` representing the
            protocol address.

        """
        if ptype == RegType_EtherType.Internet_Protocol_version_4:  # IPv4
            return ipaddress.ip_address(self._read_fileng(length))
        if ptype == RegType_EtherType.Internet_Protocol_version_6:  # IPv6
            return ipaddress.ip_address(self._read_fileng(length))
        return self._read_fileng(length).hex()

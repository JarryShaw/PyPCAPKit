# -*- coding: utf-8 -*-
"""ARP/InARP - (Inverse) Address Resolution Protocol
=======================================================

.. module:: pcapkit.protocols.link.arp

:mod:`pcapkit.protocols.link.arp` contains
:class:`~pcapkit.protocols.link.arp.ARP` only,
which implements extractor for (Inverse) Address Resolution
Protocol (ARP/InARP) [*]_, whose structure is described as
below:

.. table::

   ====== ==== ============= =======================
   Octets Bits Name          Description
   ====== ==== ============= =======================
   0      0    ``arp.htype`` Hardware Type
   ------ ---- ------------- -----------------------
   2      16   ``arp.ptype`` Protocol Type
   ------ ---- ------------- -----------------------
   4      32   ``arp.hlen``  Hardware Address Length
   ------ ---- ------------- -----------------------
   5      40   ``arp.plen``  Protocol Address Length
   ------ ---- ------------- -----------------------
   6      48   ``arp.oper``  Operation
   ------ ---- ------------- -----------------------
   8      64   ``arp.sha``   Sender Hardware Address
   ------ ---- ------------- -----------------------
   14     112  ``arp.spa``   Sender Protocol Address
   ------ ---- ------------- -----------------------
   18     144  ``arp.tha``   Target Hardware Address
   ------ ---- ------------- -----------------------
   24     192  ``arp.tpa``   Target Protocol Address
   ====== ==== ============= =======================

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol

"""
import ipaddress
import re
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.arp.operation import Operation as Enum_Operation
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.protocols.data.link.arp import ARP as Data_ARP
from pcapkit.protocols.data.link.arp import Address as Data_Address
from pcapkit.protocols.data.link.arp import Type as Data_Type
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.arp import ARP as Schema_ARP
from pcapkit.utilities.compat import cached_property
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['ARP', 'InARP']

# check Python version
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)

# Ethernet address pattern
PAT_MAC_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


class ARP(Link[Data_ARP, Schema_ARP],
          schema=Schema_ARP, data=Data_ARP):
    """This class implements all protocols in ARP family.

    - Address Resolution Protocol (:class:`~pcapkit.protocols.link.arp.ARP`) [:rfc:`826`]
    - Reverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.rarp.RARP`) [:rfc:`903`]
    - Dynamic Reverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.rarp.DRARP`) [:rfc:`1931`]
    - Inverse Address Resolution Protocol (:class:`~pcapkit.protocols.link.arp.InARP`) [:rfc:`2390`]

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
    def src(self) -> 'Data_Address':
        """Sender hardware & protocol address."""
        return Data_Address(self._info.sha, self._info.spa)

    @cached_property
    def dst(self) -> 'Data_Address':
        """Target hardware & protocol address."""
        return Data_Address(self._info.tha, self._info.tpa)

    @cached_property
    def type(self) -> 'Data_Type':
        """Hardware & protocol type."""
        return Data_Type(self._info.htype, self._info.ptype)

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["ARP"]]':
        """Index ID of the protocol."""
        return ('ARP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_ARP':  # pylint: disable=unused-argument
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
        schema = self.__header__

        _hwty = schema.htype
        _ptty = schema.ptype
        _hlen = schema.hlen
        _plen = schema.plen
        _oper = schema.oper
        _shwa = self._read_addr_resolve(schema.sha, _hwty)
        _spta = self._read_proto_resolve(schema.spa, _ptty)
        _thwa = self._read_addr_resolve(schema.tha, _hwty)
        _tpta = self._read_proto_resolve(schema.tpa, _ptty)

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

        arp = Data_ARP(
            htype=_hwty,
            ptype=_ptty,
            hlen=_hlen,
            plen=_plen,
            oper=_oper,
            sha=_shwa,
            spa=_spta,
            tha=_thwa,
            tpa=_tpta,
            len=8 + _hlen * 2 + _plen * 2,
        )
        return self._decode_next_layer(arp, -1, length - arp.len)

    def make(self, *,
             htype: 'Enum_Hardware | StdlibEnum | AenumEnum | str | int' = Enum_Hardware.Ethernet,
             htype_default: 'Optional[int]' = None,
             htype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             htype_reversed: 'bool' = False,
             ptype: 'Enum_EtherType | StdlibEnum | AenumEnum | str | int' = Enum_EtherType.Internet_Protocol_version_4,
             ptype_default: 'Optional[int]' = None,
             ptype_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             ptype_reversed: 'bool' = False,
             hlen: 'int' = 6,
             plen: 'int' = 4,
             oper: 'Enum_Operation | StdlibEnum | AenumEnum | str | int' = Enum_Operation.REQUEST,
             oper_default: 'Optional[int]' = None,
             oper_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             oper_reversed: 'bool' = False,
             sha: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             spa: 'IPv4Address | IPv6Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             tha: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             tpa: 'IPv4Address | IPv6Address | str | bytes | bytearray' = '0.0.0.0',  # nosec: B104
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_ARP':
        """Make (construct) packet data.

        Args:
            htype: Hardware type.
            htype_default: Default value of hardware type.
            htype_namespace: Namespace of hardware type.
            htype_reversed: Reversed flag of hardware type.
            ptype: Protocol type.
            ptype_default: Default value of protocol type.
            ptype_namespace: Namespace of protocol type.
            ptype_reversed: Reversed flag of protocol type.
            hlen: Hardware address length.
            plen: Protocol address length.
            oper: Operation.
            oper_default: Default value of operation.
            oper_namespace: Namespace of operation.
            oper_reversed: Reversed flag of operation.
            sha: Sender hardware address.
            spa: Sender protocol address.
            tha: Target hardware address.
            tpa: Target protocol address.
            payload: Payload.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        _htype = self._make_index(htype, htype_default, namespace=htype_namespace,
                                  reversed=htype_reversed, pack=False)
        _ptype = self._make_index(ptype, ptype_default, namespace=ptype_namespace,
                                  reversed=ptype_reversed, pack=False)
        _oper = self._make_index(oper, oper_default, namespace=oper_namespace,
                                 reversed=oper_reversed, pack=False)

        return Schema_ARP(
            htype=_htype,
            ptype=_ptype,
            hlen=hlen,
            plen=plen,
            oper=_oper,
            sha=self._make_addr_resolve(sha, _htype),
            spa=self._make_proto_resolve(spa, _ptype),
            tha=self._make_addr_resolve(tha, _htype),
            tpa=self._make_proto_resolve(tpa, _ptype),
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[28]':
        """Return an estimated length for the object."""
        return 28

    @classmethod
    def __index__(cls) -> 'Enum_EtherType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml

        """
        return Enum_EtherType.Address_Resolution_Protocol  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_ARP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'htype': data.htype,
            'ptype': data.ptype,
            'hlen': data.hlen,
            'plen': data.plen,
            'oper': data.oper,
            'sha': data.sha,
            'spa': data.spa,
            'tha': data.tha,
            'tpa': data.tpa,
            'payload': cls._make_payload(data),
        }

    def _read_addr_resolve(self, addr: 'bytes', htype: 'int') -> 'str':
        """Resolve headware address according to protocol.

        Arguments:
            addr: Hardware address.
            htype: Hardware type.

        Returns:
            Hardware address. If ``htype`` is ``1``, i.e. MAC address,
            returns ``:`` seperated *hex* encoded MAC address.

        """
        if htype == Enum_Hardware.Ethernet:  # Ethernet
            if py38:
                _addr = addr.hex(':')
            else:
                _addr = ':'.join(textwrap.wrap(addr.hex(), 2))
        else:
            _addr = addr.hex()
        return _addr

    def _read_proto_resolve(self, addr: 'bytes', ptype: 'int') -> 'str | IPv4Address | IPv6Address':
        """Resolve protocol address according to protocol.

        Arguments:
            addr: Protocol address.
            ptype: Protocol type.

        Returns:
            Protocol address. If ``ptype`` is ``0x0800``, i.e. IPv4 adddress,
            returns an :class:`~ipaddress.IPv4Address` object; if ``ptype`` is
            ``0x86dd``, i.e. IPv6 address, returns an :class:`~ipaddress.IPv6Address`
            object; otherwise, returns a raw :data:`str` representing the
            protocol address.

        """
        if ptype == Enum_EtherType.Internet_Protocol_version_4:  # IPv4
            return ipaddress.ip_address(addr)
        if ptype == Enum_EtherType.Internet_Protocol_version_6:  # IPv6
            return ipaddress.ip_address(addr)
        return addr.hex()

    def _make_addr_resolve(self, addr: 'str | bytes', htype: 'int') -> 'bytes':
        """Resolve headware address according to protocol.

        Arguments:
            addr: Hardware address.

        Returns:
            Hardware address. If ``htype`` is ``1``, i.e. MAC address,
            returns ``:`` seperated *hex* encoded MAC address.

        """
        _addr = addr.encode() if isinstance(addr, str) else addr

        if htype == Enum_Hardware.Ethernet:
            if PAT_MAC_ADDR.fullmatch(_addr) is not None:
                return _addr.replace(b':', b'').replace(b'-', b'')
            raise ProtocolError(f'Invalid MAC address: {addr!r}')
        return _addr

    def _make_proto_resolve(self, addr: 'IPv4Address | IPv6Address | str | bytes', ptype: 'int') -> 'bytes':
        """Resolve protocol address according to protocol.

        Arguments:
            addr: Protocol address.

        Returns:
            Protocol address. If ``ptype`` is ``0x0800``, i.e. IPv4 adddress,
            returns an :class:`~ipaddress.IPv4Address` object; if ``ptype`` is
            ``0x86dd``, i.e. IPv6 address, returns an :class:`~ipaddress.IPv6Address`
            object; otherwise, returns a raw :data:`str` representing the
            protocol address.

        """
        if ptype == Enum_EtherType.Internet_Protocol_version_4:
            return ipaddress.IPv4Address(addr).packed
        if ptype == Enum_EtherType.Internet_Protocol_version_6:
            return ipaddress.IPv6Address(addr).packed

        if isinstance(addr, str):
            return addr.encode()
        if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return addr.packed
        return addr


class InARP(ARP):
    """This class implements Inverse Address Resolution Protocol."""

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["InARP"]]':  # type: ignore[override]
        """Index ID of the protocol."""
        return ('InARP',)

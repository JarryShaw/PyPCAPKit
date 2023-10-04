# -*- coding: utf-8 -*-
"""Ethernet Protocol
=======================

.. module:: pcapkit.protocols.link.ethernet

:mod:`pcapkit.protocols.link.ethernet` contains
:class:`~pcapkit.protocols.link.ethernet.Ethernet`
only, which implements extractor for Ethernet
Protocol [*]_, whose structure is described as
below:

.. table::

   ====== ===== ============ =========================
   Octets Bits  Name         Description
   ====== ===== ============ =========================
   0          0 ``eth.dst``  Destination MAC Address
   ------ ----- ------------ -------------------------
   1          8 ``eth.src``  Source MAC Address
   ------ ----- ------------ -------------------------
   2         16 ``eth.type`` Protocol (Internet Layer)
   ====== ===== ============ =========================

.. [*] https://en.wikipedia.org/wiki/Ethernet

"""
import re
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.protocols.data.link.ethernet import Ethernet as Data_Ethernet
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.ethernet import Ethernet as Schema_Ethernet
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['Ethernet']

# check Python version
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)

# Ethernet address pattern
PAT_MAC_ADDR = re.compile(rb'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


class Ethernet(Link[Data_Ethernet, Schema_Ethernet],
               schema=Schema_Ethernet, data=Data_Ethernet):
    """This class implements Ethernet Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Ethernet Protocol"]':
        """Name of current protocol."""
        return 'Ethernet Protocol'

    @property
    def length(self) -> 'Literal[14]':
        """Header length of current protocol."""
        return 14

    @property
    def protocol(self) -> 'Enum_EtherType':
        """Name of next layer protocol."""
        return self._info.type

    # source mac address
    @property
    def src(self) -> 'str':
        """Source mac address."""
        return self._info.src

    # destination mac address
    @property
    def dst(self) -> 'str':
        """Destination mac address."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Ethernet':  # pylint: disable=unused-argument
        """Read Ethernet Protocol.

        Structure of Ethernet header [:rfc:`7042`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Dst MAC Addr                          |
           +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                               |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |                         Src MAC Addr                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Ether Type           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        _dstm = self._read_mac_addr(schema.dst)
        _srcm = self._read_mac_addr(schema.src)
        _type = schema.type

        ethernet = Data_Ethernet(
            dst=_dstm,
            src=_srcm,
            type=_type,
        )
        return self._decode_next_layer(ethernet, _type, length - self.length)

    def make(self,
             dst: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             src: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             type: 'Enum_EtherType | StdlibEnum | AenumEnum | str | int' = Enum_EtherType.Internet_Protocol_version_4,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_Ethernet':
        """Make (construct) packet data.

        Args:
            dst: Destination MAC address.
            src: Source MAC address.
            type: EtherType.
            type_default: Default EtherType.
            type_namespace: EtherType namespace.
            type_reversed: Whether EtherType is reversed.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        _type = self._make_index(type, type_default, namespace=type_namespace,
                                 reversed=type_reversed, pack=False)

        return Schema_Ethernet(
            dst=self._make_mac_addr(dst),
            src=self._make_mac_addr(src),
            type=_type,  # type: ignore[arg-type]
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[14]':
        """Return an estimated length for the object."""
        return 14

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.ETHERNET  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Ethernet') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'dst': data.dst,
            'src': data.src,
            'type': data.type,
            'payload': cls._make_payload(data),
        }

    def _read_mac_addr(self, addr: 'bytes') -> 'str':
        """Read MAC address.

        Args:
            addr: MAC address.

        Returns:
            Colon (``:``) seperated *hex* encoded MAC address.

        """
        if py38:
            _addr = addr.hex(':')
        else:
            _addr = ':'.join(textwrap.wrap(addr.hex(), 2))
        return _addr

    def _make_mac_addr(self, addr: 'str | bytes | bytearray') -> 'bytes':
        """Make MAC address.

        Args:
            addr: MAC address.

        Returns:
            MAC address.

        """
        _addr = addr.encode() if isinstance(addr, str) else addr

        if PAT_MAC_ADDR.fullmatch(_addr) is not None:
            return _addr.replace(b':', b'').replace(b'-', b'')
        raise ProtocolError(f'invalid MAC address: {addr!r}')

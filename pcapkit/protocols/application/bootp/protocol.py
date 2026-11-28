# -*- coding: utf-8 -*-
"""BOOTP - Bootstrap Protocol
================================

.. module:: pcapkit.protocols.application.bootp.protocol

:mod:`pcapkit.protocols.application.bootp.protocol` holds
:class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`, the extractor for
Bootstrap Protocol (BOOTP) messages [:rfc:`951`, :rfc:`1542`], laid out as
:mod:`~pcapkit.protocols.application.dhcp.protocol` gives. Its last field,
``vend``, holds the vendor extensions of :rfc:`1497` and :rfc:`2132` sections 3
to 8 where the magic cookie opens it, and is vendor-specific octets otherwise.

.. versionadded:: 1.10.0

"""
import collections.abc
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.dhcp.opcode import Opcode as Enum_Opcode
from pcapkit.protocols.application.bootp.const import VENDOR_EXTENSIONS
from pcapkit.protocols.application.bootp.data import BOOTP as Data_BOOTP
from pcapkit.protocols.application.dhcp.const import FILE_LENGTH, MAGIC_COOKIE, SNAME_LENGTH
from pcapkit.protocols.application.dhcp.protocol import DHCP
from pcapkit.protocols.application.dhcp.schema import DHCP as Schema_DHCP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Iterable, Mapping, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['BOOTP']


# NOTE: ``schema`` is restated: with no such module in this package,
# ProtocolBase.__init_subclass__ would bind Raw's, as C_Tag notes.
class BOOTP(DHCP[Data_BOOTP, Schema_DHCP], schema=Schema_DHCP, data=Data_BOOTP):
    """This class implements the Bootstrap Protocol.

    A message whose options carry the DHCP Message Type option is a DHCP one,
    which :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4` reads, so
    this class refuses it, on both paths. Its vendor extensions decode as
    :class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` gives, for the codes
    of :data:`~pcapkit.protocols.application.bootp.const.VENDOR_EXTENSIONS` alone;
    the ``sname`` and ``file`` fields are text, which no Option Overload option
    overloads here. A vendor extension the area ends inside, as a capture cut
    leaves one, keeps its octets as the padding, and the cut is recorded as
    :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4` records it.

    .. versionadded:: 1.10.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Bootstrap Protocol"]':
        """Name of current protocol."""
        return 'Bootstrap Protocol'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["BOOTP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member's canonical name.

        """
        return ('BOOTP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_BOOTP':  # pylint: disable=unused-argument
        """Read Bootstrap Protocol.

        Structure of a BOOTP message [:rfc:`951#section-3`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +---------------+---------------+---------------+---------------+
           |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
           +---------------+---------------+---------------+---------------+
           |                            xid (4)                            |
           +-------------------------------+-------------------------------+
           |           secs (2)            |           flags (2)           |
           +-------------------------------+-------------------------------+
           |                          ciaddr  (4)                          |
           +---------------------------------------------------------------+
           |                          yiaddr  (4)                          |
           +---------------------------------------------------------------+
           |                          siaddr  (4)                          |
           +---------------------------------------------------------------+
           |                          giaddr  (4)                          |
           +---------------------------------------------------------------+
           |                          chaddr  (16)                         |
           +---------------------------------------------------------------+
           |                          sname   (64)                         |
           +---------------------------------------------------------------+
           |                          file    (128)                        |
           +---------------------------------------------------------------+
           |                          vend    (64)                         |
           +---------------------------------------------------------------+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the options carry the DHCP Message Type option.

        """
        schema = self.__header__
        header = self._read_dhcp_header()
        area = schema.options

        cookie = None  # type: Optional[bytes]
        vend = area  # type: Any
        padding = b''
        if area[:len(MAGIC_COOKIE)] == MAGIC_COOKIE:
            if self._classify(bytes(44) + schema.sname + schema.file + area) is not BOOTP:
                raise ProtocolError(f'{self.alias}: invalid format: the DHCP Message Type option '
                                    'makes it a DHCP message')
            entries, padding = self._read_dhcp_area(area)
            cookie = MAGIC_COOKIE
            vend = self._read_dhcp_options(entries, self._count_options(entries), VENDOR_EXTENSIONS)

        bootp = Data_BOOTP(
            **header,
            sname=schema.sname.rstrip(b'\x00'),
            file=schema.file.rstrip(b'\x00'),
            magic_cookie=cookie,
            vend=vend,
            padding=padding,
        )
        rest = (len(self._data) if length is None else length) - self._length
        return self._decode_next_layer(bootp, -1, max(rest, 0))

    def make(self, *,
             op: 'Enum_Opcode | int' = Enum_Opcode.BOOTREQUEST,
             htype: 'Enum_Hardware | int' = Enum_Hardware.Ethernet,
             hlen: 'Optional[int]' = None,
             hops: 'int' = 0,
             xid: 'int' = 0,
             secs: 'int' = 0,
             flags: 'Mapping[str, Any] | int' = 0,
             ciaddr: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             yiaddr: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             siaddr: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             giaddr: 'IPv4Address | str | bytes | int' = '0.0.0.0',  # nosec: B104
             chaddr: 'str | bytes' = b'',
             chaddr_padding: 'Optional[bytes]' = None,
             sname: 'bytes' = b'',
             file: 'bytes' = b'',
             vend: 'Iterable[Mapping[str, Any]] | bytes' = (),
             padding: 'bytes' = b'',
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_DHCP':
        """Make (construct) packet data.

        Args:
            op: Message op code.
            htype: Hardware address type.
            hlen: Hardware address length; that of ``chaddr`` if :obj:`None`.
            hops: Hops.
            xid: Transaction ID.
            secs: Seconds elapsed since the client began.
            flags: Flags, as their data model or a mapping of its keys, or the
                two octets as an integer.
            ciaddr: Client IP address.
            yiaddr: Your (client) IP address.
            siaddr: Server IP address.
            giaddr: Gateway IP address.
            chaddr: Client hardware address: a MAC address for an Ethernet or
                IEEE 802 type, or its octets.
            chaddr_padding: Octets of ``chaddr`` after the address; zeros filling
                the field if :obj:`None`.
            sname: Server host name, which NULs fill out.
            file: Boot file name, which NULs fill out.
            vend: Vendor area: its vendor extensions, each a mapping as
                :class:`~pcapkit.protocols.application.dhcp.data.Option` holds it,
                written after the magic cookie, or its raw octets.
            padding: Octets after the End option, or with none, the vendor
                extension the area ends inside; given with vendor extensions.
            payload: Octets after the message.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If a field does not fit its width; if an option is
                malformed or builds a code outside the vendor extensions from
                fields; or if the vendor extensions carry the DHCP Message Type
                option, which makes a DHCP message.

        """
        header = self._make_dhcp_header(op=op, htype=htype, hlen=hlen, hops=hops, xid=xid, secs=secs, flags=flags,
                                        ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr, giaddr=giaddr,
                                        chaddr=chaddr, chaddr_padding=chaddr_padding)
        if isinstance(vend, (bytes, bytearray)):
            if padding:
                raise ProtocolError(f'{self.alias}: invalid padding: raw vendor octets take none')
            area = bytes(vend)
        elif isinstance(vend, collections.abc.Iterable):
            area = MAGIC_COOKIE + self._make_dhcp_options(vend, padding, codes=VENDOR_EXTENSIONS)
        else:
            raise ProtocolError(f'{self.alias}: invalid vendor area: {vend!r}')
        sname_field = self._make_dhcp_field(sname, size=SNAME_LENGTH, name='server host name')
        file_field = self._make_dhcp_field(file, size=FILE_LENGTH, name='boot file name')
        if self._classify(bytes(44) + sname_field + file_field + area) is not BOOTP:
            raise ProtocolError(f'{self.alias}: the DHCP Message Type option makes a DHCP message; build DHCPv4')
        return Schema_DHCP(
            **header,
            sname=sname_field,
            file=file_field,
            options=area,
            payload=payload,
        )

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_BOOTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'op': data.op,
            'htype': data.htype,
            'hlen': data.hlen,
            'hops': data.hops,
            'xid': data.xid,
            'secs': data.secs,
            'flags': data.flags,
            'ciaddr': data.ciaddr,
            'yiaddr': data.yiaddr,
            'siaddr': data.siaddr,
            'giaddr': data.giaddr,
            'chaddr': data.chaddr,
            'chaddr_padding': data.chaddr_padding,
            'sname': data.sname,
            'file': data.file,
            'vend': data.vend,
            'padding': data.padding,
            'payload': cls._make_payload(data),
        }

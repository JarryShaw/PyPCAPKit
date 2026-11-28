# -*- coding: utf-8 -*-
"""DHCPv4 - Dynamic Host Configuration Protocol
==================================================

.. module:: pcapkit.protocols.application.dhcpv4.protocol

:mod:`pcapkit.protocols.application.dhcpv4.protocol` holds
:class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4`, the extractor for
Dynamic Host Configuration Protocol (DHCP) messages [:rfc:`2131`], laid out as
:mod:`~pcapkit.protocols.application.dhcp.protocol` gives. Its last field,
``options``, opens with the magic cookie, and the ``sname`` and ``file`` fields
hold options too where the Option Overload option says so
(:rfc:`2131#section-4.1`).

.. versionadded:: 1.10.0

"""
import collections.abc
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.dhcp.opcode import Opcode as Enum_Opcode
from pcapkit.const.dhcp.option import Option as Enum_Option
from pcapkit.protocols.application.dhcp.const import FILE_LENGTH, MAGIC_COOKIE, SNAME_LENGTH
from pcapkit.protocols.application.dhcp.data import MessageType as Data_MessageType
from pcapkit.protocols.application.dhcp.data import OverloadedField as Data_OverloadedField
from pcapkit.protocols.application.dhcp.protocol import DHCP
from pcapkit.protocols.application.dhcp.schema import DHCP as Schema_DHCP
from pcapkit.protocols.application.dhcpv4.data import DHCPv4 as Data_DHCPv4
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any, Iterable, Mapping, Optional

    from typing_extensions import Literal

    from pcapkit.const.dhcp.message_type import MessageType as Enum_MessageType
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['DHCPv4']


# NOTE: ``schema`` is restated: with no such module in this package,
# ProtocolBase.__init_subclass__ would bind Raw's, as C_Tag notes.
class DHCPv4(DHCP[Data_DHCPv4, Schema_DHCP], schema=Schema_DHCP, data=Data_DHCPv4):
    """This class implements the Dynamic Host Configuration Protocol.

    A message is a DHCP one where its options carry the DHCP Message Type option
    (:rfc:`2131#section-3`), so this class refuses one without it, on both paths;
    :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP` reads it. Its
    options decode as :class:`~pcapkit.protocols.application.dhcp.protocol.DHCP`
    gives, in the ``options`` field, then in the ``file`` and ``sname`` fields
    the Option Overload option there overloads, in that order.

    .. versionadded:: 1.10.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Dynamic Host Configuration Protocol"]':
        """Name of current protocol."""
        return 'Dynamic Host Configuration Protocol'

    @property
    def message_type(self) -> 'Optional[Enum_MessageType]':
        """DHCP message type, or :obj:`None` where its option keeps its octets."""
        areas = [self._info.options]
        areas.extend(field.options for field in (self._info.file, self._info.sname)
                     if isinstance(field, Data_OverloadedField))
        for area in areas:
            for option in area:
                if option.code == Enum_Option.DHCP_Msg_Type and isinstance(option.data, Data_MessageType):
                    return option.data.type
        return None

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["DHCP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, narrowed to this member's canonical name:
            :rfc:`2131` names it plain ``DHCP``, as :rfc:`792` names ICMPv4's.

        """
        return ('DHCP',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_DHCPv4':  # pylint: disable=unused-argument
        """Read Dynamic Host Configuration Protocol.

        Structure of a DHCP message [:rfc:`2131#section-2`]:

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
           |                          options (variable)                   |
           +---------------------------------------------------------------+

        An option that runs past its field, as a capture cut leaves one, keeps
        its octets as the field's padding, and the options field records the cut
        as its header schema would.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If no magic cookie opens the options field, or the
                options carry no DHCP Message Type option whole before any option
                runs past its field.

        """
        schema = self.__header__
        header = self._read_dhcp_header()
        area = schema.options
        if area[:len(MAGIC_COOKIE)] != MAGIC_COOKIE:
            raise ProtocolError(f'{self.alias}: invalid format: no magic cookie opens the options field')
        if self._classify(bytes(44) + schema.sname + schema.file + area) is not DHCPv4:
            raise ProtocolError(f'{self.alias}: invalid format: no DHCP Message Type option')
        entries, padding = self._read_dhcp_area(area)

        overloaded = {}  # type: dict[int, Any]
        for start, _ in self._overloaded_fields(entries):
            field = schema.file if start == 108 else schema.sname
            inner, end, _ = self._split_options(field)
            overloaded[start] = (inner, field[end:])
        counts = self._count_options(entries, *(inner for inner, _ in overloaded.values()))

        fields = {}  # type: dict[str, Any]
        for name, start, field in (('file', 108, schema.file), ('sname', 44, schema.sname)):
            if start in overloaded:
                inner, rest = overloaded[start]
                fields[name] = Data_OverloadedField(options=self._read_dhcp_options(inner, counts), padding=rest)
            else:
                fields[name] = field.rstrip(b'\x00')

        dhcp = Data_DHCPv4(
            **header,
            sname=fields['sname'],
            file=fields['file'],
            magic_cookie=MAGIC_COOKIE,
            options=self._read_dhcp_options(entries, counts),
            padding=padding,
        )
        rest = (len(self._data) if length is None else length) - self._length
        return self._decode_next_layer(dhcp, -1, max(rest, 0))

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
             sname: 'bytes | Mapping[str, Any]' = b'',
             file: 'bytes | Mapping[str, Any]' = b'',
             options: 'Iterable[Mapping[str, Any]]' = (),
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
            siaddr: Next server IP address.
            giaddr: Relay agent IP address.
            chaddr: Client hardware address: a MAC address for an Ethernet or
                IEEE 802 type, or its octets.
            chaddr_padding: Octets of ``chaddr`` after the address; zeros filling
                the field if :obj:`None`.
            sname: Server host name, which NULs fill out, or the options it
                holds, as :class:`~pcapkit.protocols.application.dhcp.data.OverloadedField`
                holds them.
            file: Boot file name, which NULs fill out, or the options it holds,
                likewise.
            options: Options, each a mapping as
                :class:`~pcapkit.protocols.application.dhcp.data.Option` holds it,
                written after the magic cookie.
            padding: Octets after the End option, or with none, the option the
                field ends inside.
            payload: Octets after the message.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If a field does not fit its width; if an option is
                malformed; if ``sname`` or ``file`` holds options where the
                Option Overload option does not say so, or text where it does; or
                if the options carry no DHCP Message Type option.

        """
        header = self._make_dhcp_header(op=op, htype=htype, hlen=hlen, hops=hops, xid=xid, secs=secs, flags=flags,
                                        ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr, giaddr=giaddr,
                                        chaddr=chaddr, chaddr_padding=chaddr_padding)
        area = MAGIC_COOKIE + self._make_dhcp_options(options, padding)
        entries, _, _ = self._split_options(area[len(MAGIC_COOKIE):])
        expected = {start for start, _ in self._overloaded_fields(entries)}

        made = {}  # type: dict[str, bytes]
        for name, start, value, size, text in (('sname', 44, sname, SNAME_LENGTH, 'server host name'),
                                                ('file', 108, file, FILE_LENGTH, 'boot file name')):
            if isinstance(value, collections.abc.Mapping) != (start in expected):
                raise ProtocolError(f'{self.alias}: invalid {name}: it holds options exactly where '
                                    'the Option Overload option says so')
            if isinstance(value, collections.abc.Mapping):
                made[name] = self._make_dhcp_options(value.get('options', ()), value.get('padding', b''), size=size)
            else:
                made[name] = self._make_dhcp_field(value, size=size, name=text)

        if self._classify(bytes(44) + made['sname'] + made['file'] + area) is not DHCPv4:
            raise ProtocolError(f'{self.alias}: no DHCP Message Type option; build BOOTP for a message without one')
        return Schema_DHCP(
            **header,
            sname=made['sname'],
            file=made['file'],
            options=area,
            payload=payload,
        )

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_DHCPv4') -> 'dict[str, Any]':  # type: ignore[override]
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
            'options': data.options,
            'padding': data.padding,
            'payload': cls._make_payload(data),
        }

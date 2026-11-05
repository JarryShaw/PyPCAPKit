# -*- coding: utf-8 -*-
"""L2TPv2 - Layer Two Tunnelling Protocol version 2
======================================================

.. module:: pcapkit.protocols.link.l2tpv2.protocol

:mod:`pcapkit.protocols.link.l2tpv2.protocol` contains
:class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` only, which implements the extractor
for the Layer Two Tunnelling Protocol version 2 (L2TPv2) [*]_ as specified by
:rfc:`2661` -- a 16-bit tunnel ID and a 16-bit session ID, with the version
nibble reading ``2``. Its structure is described as below:

.. table::

   ======= ===== ===================== ==========================================
    Octets Bits  Name                  Description
   ======= ===== ===================== ==========================================
    0          0 ``l2tp.flags``        Flags and Version Info
   ------- ----- --------------------- ------------------------------------------
    0          0 ``l2tp.flags.type``   Type (control / data)
   ------- ----- --------------------- ------------------------------------------
    0          1 ``l2tp.flags.len``    Length
   ------- ----- --------------------- ------------------------------------------
    0          2                       Reserved (must be zero)
   ------- ----- --------------------- ------------------------------------------
    0          4 ``l2tp.flags.seq``    Sequence
   ------- ----- --------------------- ------------------------------------------
    0          5                       Reserved (must be zero)
   ------- ----- --------------------- ------------------------------------------
    0          6 ``l2tp.flags.offset`` Offset
   ------- ----- --------------------- ------------------------------------------
    0          7 ``l2tp.flags.prio``   Priority
   ------- ----- --------------------- ------------------------------------------
    1          8                       Reserved (must be zero)
   ------- ----- --------------------- ------------------------------------------
    1         12 ``l2tp.version``      Version (``2``)
   ------- ----- --------------------- ------------------------------------------
    2         16 ``l2tp.length``       Length (optional by ``len``)
   ------- ----- --------------------- ------------------------------------------
    4         32 ``l2tp.tunnelid``     Tunnel ID
   ------- ----- --------------------- ------------------------------------------
    6         48 ``l2tp.sessionid``    Session ID
   ------- ----- --------------------- ------------------------------------------
    8         64 ``l2tp.ns``           Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    10        80 ``l2tp.nr``           Next Sequence Number (optional by ``seq``)
   ------- ----- --------------------- ------------------------------------------
    12        96 ``l2tp.offset``       Offset Size (optional by ``offset``)
   ======= ===== ===================== ==========================================

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol

"""
from typing import TYPE_CHECKING

from pcapkit.const.l2tp.type import Type as Enum_Type
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.link.l2tp.data import L2TP as Data_L2TP
from pcapkit.protocols.link.l2tp.data import Flags as Data_Flags
from pcapkit.protocols.link.l2tp.protocol import L2TP
from pcapkit.protocols.link.l2tp.schema import L2TP as Schema_L2TP
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.apptype.udp import UDP as AppType_UDP
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['L2TPv2']

#: The UDP port registry :meth:`L2TPv2.__index__` reads its port from, resolved
#: there rather than imported, as ``import pcapkit`` leaves it unloaded
#: (:issue:`1538`), so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_UDP: 'ModuleDescriptor[AppType_UDP]' = ModuleDescriptor('pcapkit.const.reg.apptype.udp', 'UDP')


# NOTE: ``schema`` and ``data`` are explicit because the version-agnostic base declares none,
# and an omitted one is looked up by class name and would silently bind ``Schema_Raw``.
class L2TPv2(L2TP[Data_L2TP, Schema_L2TP],
             schema=Schema_L2TP, data=Data_L2TP):
    """This class implements Layer Two Tunnelling Protocol version 2.

    The protocol is dispatched from :attr:`UDP.__proto__
    <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>` at port 1701.

    Only the :rfc:`2661` framing is read: :meth:`read` refuses a datagram whose
    version nibble is not ``2``, so a v3 datagram arriving on port 1701
    (:rfc:`3931` §4.7.2 shares the port) degrades to
    :class:`~pcapkit.protocols.misc.raw.protocol.Raw` instead of being reported as v2.

    .. versionadded:: 1.5.0

       Takes over the version-2 parsing that
       :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` carried, and refuses a version
       nibble other than ``2`` (:issue:`548`).

    .. versionchanged:: 1.6.0

       ``type`` of :meth:`make` takes a member or an :class:`int` code,
       resolved with the enumeration's ``get``; a name, or a code the
       one-bit field cannot carry, raises
       :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than
       resolving against an enumeration inferred from the caller's frame
       (:issue:`2594`).

    .. versionremoved:: 1.6.0

       The ``type_default``, ``type_namespace`` and ``type_reversed``
       arguments of :meth:`make`; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    Note:
        IANA protocol number 115 (``L2TP``) is deliberately left unbound. It
        references :rfc:`3931`, i.e. **L2TPv3**, whose session and control
        message headers are a different shape -- so the binding waits on an
        ``L2TPv3`` class rather than on this one. Binding *this* class there does
        not work (:issue:`548`): over IP the v3 session header carries no
        version nibble at all, so this class cannot recognise that the datagram
        is not its own. See :mod:`pcapkit.protocols.link.l2tp.protocol` for the
        versions not implemented.

        The class subclasses :class:`~pcapkit.protocols.link.link.Link` and so
        reports ``layer == 'Link'`` even though it is carried inside UDP: a
        tunnelling protocol is placed by what it carries. See
        :doc:`/contributing/conventions/protocol-layer-placement`.
    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Layer 2 Tunnelling Protocol version 2"]':
        """Name of current protocol."""
        return 'Layer 2 Tunnelling Protocol version 2'

    @property
    def alias(self) -> 'Literal["L2TPv2"]':
        """Acronym of current protocol."""
        return 'L2TPv2'

    @property
    def version(self) -> 'Literal[2]':
        """Version of current protocol.

        Always ``2``: :rfc:`2661` fixes the version nibble, and a datagram
        carrying any other value is a different protocol reached through a
        different class. See :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP`.

        This is enforced rather than merely asserted -- :meth:`read` refuses a
        datagram whose nibble is not ``2``, so this hard-coded answer cannot
        disagree with
        :attr:`info.version <pcapkit.protocols.link.l2tp.data.L2TP.version>`
        on the same octets.

        """
        return 2

    @property
    def length(self) -> 'int':
        """Header length of current protocol."""
        return self._info.hdr_len

    @property
    def type(self) -> 'Literal["control", "data"]':
        """L2TP type."""
        return self._info.flags.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_L2TP':  # pylint: disable=unused-argument
        """Read Layer Two Tunnelling Protocol.

        Structure of L2TP header [:rfc:`2661`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |           Tunnel ID           |           Session ID          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |             Ns (opt)          |             Nr (opt)          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Offset Size (opt)        |    Offset pad... (opt)
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the version nibble is not ``2``.

        """
        schema = self.__header__
        _flag = schema.flags

        # NOTE: Any ``Ver`` but 2 is another protocol (RFC 2661 Section 3.1), whose later fields
        # mean something else, so it is refused rather than misread (#548).
        if _flag['version'] != 2:
            raise ProtocolError(f'{self.alias}: invalid version: {_flag["version"]}')

        flags = Data_Flags(
            type=Enum_Type(_flag['type']),
            len=bool(_flag['len']),
            seq=bool(_flag['seq']),
            offset=bool(_flag['offset']),
            prio=bool(_flag['prio']),
            reserved=(_flag['reserved_1'] << 12) | (_flag['reserved_2'] << 10) | (_flag['reserved_3'] << 4),
        )

        _size = schema.offset if flags.offset else 0
        hdr_len = 6 + 2 * (flags.len + 2 * flags.seq + flags.offset) + _size

        l2tp = Data_L2TP(
            flags=flags,
            version=_flag['version'],
            length=schema.length if flags.len else None,
            tunnelid=schema.tunnel_id,
            sessionid=schema.session_id,
            ns=schema.ns if flags.seq else None,
            nr=schema.nr if flags.seq else None,
            offset=_size if flags.offset else None,
        )

        l2tp.__update__([
            ('hdr_len', hdr_len),
            ('padding', schema.padding if flags.offset else None),
        ])
        if _size:
            self._read_fileng(_size)

        # NOTE: Octets captured past the Length field belong to this layer, as its own
        # length field leaves them out of the payload; the rebuild keeps them (#1455).
        if schema.trailer:
            l2tp.__update__([
                ('trailer', schema.trailer),
            ])

        length = schema.length if flags.len else (length or len(self))
        # L2TP carries no next-protocol field -- the payload is a PPP frame,
        # which pcapkit does not dissect -- so dispatch on the -1 sentinel, as
        # ARP does, rather than on a code read off the wire. Passing the
        # remaining length here would dispatch on it as if it were an EtherType,
        # resolving to Raw only because a length rarely collides with a
        # registered one.
        return self._decode_next_layer(l2tp, -1, length - hdr_len)

    def make(self,
             version: 'Literal[2]' = 2,
             type: 'Enum_Type | int' = Enum_Type.Data,
             priority: 'bool' = False,
             reserved: 'int' = 0,
             total_length: 'Optional[int]' = None,
             length_flag: 'Optional[bool]' = None,
             tunnel_id: 'int' = 0,
             session_id: 'int' = 0,
             ns: 'Optional[int]' = None,
             nr: 'Optional[int]' = None,
             offset: 'Optional[int]' = None,
             padding: 'Optional[bytes]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_L2TP':  # pylint: disable=unused-argument
        """Make (construct) packet data.

        Args:
            version: L2TP version.
            type: L2TP type.
            priority: Priority flag.
            reserved: Reserved bits of the flags word, in their on-wire
                positions (bits 2, 3, 5 and 8-11, i.e. within ``0x34F0``).
            total_length: Length of the datagram, header included, written as
                given; the real header-plus-payload length when :data:`None`
                and the Length field is present.
            length_flag: Whether the Length field and its ``L`` flag are
                present. When :data:`None`, they are present if
                ``total_length`` is given, or for a control message, which
                :rfc:`2661` §3.1 requires to set ``L``.
            tunnel_id: Tunnel ID.
            session_id: Session ID.
            ns: Sequence number.
            nr: Acknowledgement number.
            offset: Offset size.
            padding: Offset pad, zero-filled or truncated to ``offset`` octets;
                all zeros when :data:`None`.
            payload: Payload data.
            trailer: Octets after the datagram, outside the Length field;
                written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``type`` is a name, or a member or code its
                one-bit field cannot carry; if ``total_length`` is given with
                ``length_flag`` set to :data:`False`; if only one of ``ns``
                and ``nr`` is given; or if ``reserved`` sets a bit outside
                ``0x34F0``.

        """
        type_ = self._make_index(type, Enum_Type, bits=1, name='type')
        # NOTE: :rfc:`2661` §3.1 makes ``S`` mark *both* Ns and Nr, so refuse a lone
        # value rather than drop it, or invent the other on the wire.
        if (ns is None) != (nr is None):
            raise ProtocolError(f'{self.alias}: ns and nr must be given together')
        seq = ns is not None

        if reserved & ~0x34F0:
            raise ProtocolError(f'{self.alias}: reserved bits outside 0x34F0: {reserved:#06x}')

        if length_flag is None:
            length_flag = total_length is not None or type_ == Enum_Type.Control
        elif not length_flag and total_length is not None:
            raise ProtocolError(f'{self.alias}: total_length given without the Length field')

        # NOTE: An explicit ``total_length`` is not checked against the octets, so a rebuild
        # of a snaplen-truncated capture keeps the declared length, as UDP does (#1155).
        if length_flag and total_length is None:
            total_length = 6 + 2 * (1 + 2 * seq + (offset is not None)) + (offset or 0) + len(payload)

        return Schema_L2TP(
            flags={
                'type': type_,
                'len': length_flag,
                'seq': seq,
                'offset': offset is not None,
                'prio': priority,
                'reserved_1': (reserved >> 12) & 0b11,
                'reserved_2': (reserved >> 10) & 0b1,
                'reserved_3': (reserved >> 4) & 0b1111,
                'version': version,
            },
            length=total_length,
            tunnel_id=tunnel_id,
            session_id=session_id,
            ns=ns,
            nr=nr,
            offset=offset,
            padding=b'' if padding is None else padding,
            payload=payload,
            trailer=trailer,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["L2TP"], Literal["L2TPv2"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the canonical family name first, then
            this version's own label. Element zero is what callers treat as
            canonical, so both ``protocol='L2TP'`` and ``protocol='L2TPv2'``
            select this class.

        """
        return ('L2TP', 'L2TPv2')

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    @classmethod
    def __index__(cls) -> 'int':  # type: ignore[override]
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_ service names and
            port numbers: UDP port 1701, the port of
            :attr:`UDP.l2tp <pcapkit.const.reg.apptype.udp.UDP.l2tp>` as an
            :class:`int`, which
            :attr:`UDP.__proto__ <pcapkit.protocols.transport.udp.protocol.UDP.__proto__>`
            dispatches here (:ref:`registry-protocol-index`).
            :class:`~pcapkit.const.reg.transtype.TransType` 115 names L2TPv3
            over IP instead.

        .. _IANA: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml

        .. versionchanged:: 1.6.0

           Returns UDP port 1701, where it raised
           :exc:`~pcapkit.utilities.exceptions.UnsupportedCall` (:issue:`2627`).

        """
        return int(_UDP.klass.l2tp)  # type: ignore[call-overload]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_L2TP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'type': data.flags.type,
            'priority': data.flags.prio,
            'reserved': data.flags.reserved,
            'version': data.version,
            # NOTE: As ``total_length``: ``length`` is ProtocolBase's parse length and would
            # never reach :meth:`make`, dropping the Length field and ``L`` flag (#1172).
            'total_length': data.length,
            # NOTE: So a control message captured without ``L`` rebuilds as captured, not
            # gaining the Length field :meth:`make` gives by default.
            'length_flag': data.flags.len,
            'tunnel_id': data.tunnelid,
            'session_id': data.sessionid,
            'ns': data.ns,
            'nr': data.nr,
            'offset': data.offset,
            'padding': data.get('padding'),
            'payload': cls._make_payload(data),
            # NOTE: And the octets captured past the Length field (#1455).
            'trailer': data.get('trailer', b''),
        }

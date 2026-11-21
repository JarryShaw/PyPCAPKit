# -*- coding: utf-8 -*-
"""PPPoE - PPP over Ethernet
===============================

.. module:: pcapkit.protocols.link.pppoe.protocol

:mod:`pcapkit.protocols.link.pppoe.protocol` contains
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` only,
which implements the extractor for PPP over Ethernet
(PPPoE) [*]_ of :rfc:`2516`, whose structure is described as below:

.. table::

   ====== ===== ===================== =========================================
   Octets Bits  Name                  Description
   ====== ===== ===================== =========================================
   0          0 ``pppoe.version``     Version (``1``)
   ------ ----- --------------------- -----------------------------------------
   0          4 ``pppoe.type``        Type (``1``)
   ------ ----- --------------------- -----------------------------------------
   1          8 ``pppoe.code``        Code
   ------ ----- --------------------- -----------------------------------------
   2         16 ``pppoe.session_id``  Session ID
   ------ ----- --------------------- -----------------------------------------
   4         32 ``pppoe.length``      Length of the payload
   ------ ----- --------------------- -----------------------------------------
   6         48 ``pppoe.tags``        Tags (discovery stage)
   ====== ===== ===================== =========================================

.. [*] https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet

"""
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from pcapkit.const.pppoe.code import Code as Enum_Code
from pcapkit.const.pppoe.tag import Tag as Enum_Tag
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.pppoe.data import PPPoE as Data_PPPoE
from pcapkit.protocols.link.pppoe.data import Tag as Data_Tag
from pcapkit.protocols.link.pppoe.schema import PPPoE as Schema_PPPoE
from pcapkit.protocols.link.pppoe.schema import Tag as Schema_Tag
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['PPPoE']


class PPPoE(Link[Data_PPPoE, Schema_PPPoE],
            schema=Schema_PPPoE, data=Data_PPPoE):
    """This class implements PPP over Ethernet.

    The packet is dispatched from :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>` at EtherType ``0x8863``,
    the discovery stage, and ``0x8864``, the session stage, and from
    :attr:`Frame.__proto__ <pcapkit.protocols.misc.pcap.frame.protocol.Frame.__proto__>`
    and :attr:`PCAPNG.__proto__ <pcapkit.protocols.misc.pcapng.protocol.PCAPNG.__proto__>`
    at ``LINKTYPE_PPP_ETHER``. Which stage a packet is in is read from its
    Code, :attr:`~pcapkit.const.pppoe.code.Code.PPP_Session_Stage` being the
    session stage's (:rfc:`2516#section-6`), since ``LINKTYPE_PPP_ETHER``
    carries no EtherType to tell.

    A discovery packet carries its tags and no next layer. A session packet
    carries a PPP frame, dispatched as :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>` dispatches EtherType
    ``0x880B``. The octets past the Length field are kept as
    :attr:`~pcapkit.protocols.link.pppoe.schema.PPPoE.trailer`.

    .. versionadded:: 1.7.0

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["PPP over Ethernet"]':
        """Name of current protocol."""
        return 'PPP over Ethernet'

    @property
    def length(self) -> 'int':
        """Header length of current protocol, the tags included."""
        if self._info.tags is None:
            return 6
        return 6 + self._info.length

    @property
    def code(self) -> 'Enum_Code':
        """Code of current packet."""
        return self._info.code

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_PPPoE':  # pylint: disable=unused-argument
        """Read PPP over Ethernet.

        Structure of PPPoE header [:rfc:`2516`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |  VER  | TYPE  |      CODE     |          SESSION_ID           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |            LENGTH             |           payload             ~
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the version or the type is not ``1``, or the
                Length of a discovery packet ends inside a tag.

        """
        schema = self.__header__

        # NOTE: RFC 2516 Section 4 fixes both to 1; another is a format this does not know.
        if schema.info['ver'] != 1 or schema.info['type'] != 1:
            raise ProtocolError(f'{self.alias}: invalid version or type: '
                                f'{schema.info["ver"]}, {schema.info["type"]}')

        session = schema.code == Enum_Code.PPP_Session_Stage
        # NOTE: A Length ending inside a tag leaves a tag the list read past its octets,
        # which would rebuild longer; a capture cut is the short read's to keep instead.
        if (not session and getattr(schema, '__short_read__', None) is None
                and sum(4 + tag.length for tag in schema.tags) != schema.length):
            raise ProtocolError(f'{self.alias}: length {schema.length} ends inside a tag')
        pppoe = Data_PPPoE(
            version=schema.info['ver'],
            type=schema.info['type'],
            code=schema.code,
            session_id=schema.session_id,
            length=schema.length,
            tags=None if session else tuple(Data_Tag(
                type=tag.type,
                length=tag.length,
                value=tag.value,
            ) for tag in schema.tags),
        )

        # NOTE: Octets captured past the Length field, Ethernet's padding among them,
        # belong to this layer, as L2TPv2 keeps its own (#1455).
        if schema.trailer:
            pppoe.__update__([
                ('trailer', schema.trailer),
            ])

        if session:
            return self._decode_next_layer(pppoe, Enum_EtherType.Point_to_Point_Protocol, schema.length)
        return self._decode_next_layer(pppoe, -1, 0)

    def make(self,
             code: 'Enum_Code | int' = Enum_Code.PPP_Session_Stage,
             session_id: 'int' = 0,
             payload_length: 'Optional[int]' = None,
             tags: 'Optional[Iterable[Data_Tag | Mapping[str, Any] | tuple[Enum_Tag | int, bytes]]]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_PPPoE':  # pylint: disable=unused-argument
        """Make (construct) packet data.

        Args:
            code: Code; the session stage's, or a discovery packet's.
            session_id: Session ID.
            payload_length: Length field; the length of the payload or of the
                tags when :data:`None`, which it has to be when given, but in a
                rebuild of a cut packet.
            tags: Tags of a discovery packet, each a ``(type, value)`` pair or
                a mapping of its ``type``, ``value`` and optionally ``length``,
                which has to be that of the value.
            payload: Payload data, a PPP frame in the session stage.
            trailer: Octets after the packet, outside the Length field;
                written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``code`` is a name, or a code its field cannot
                carry; if ``tags`` is given in the session stage, or
                ``payload`` in the discovery stage; if ``tags`` is no iterable
                of tags, or a tag has no ``type`` or ``value``, a type that does
                not fit, a value that is not :class:`bytes` or a length other
                than its value's; or if ``payload_length`` is not the length of
                what follows the header.

        """
        code_ = self._make_index(code, Enum_Code, bits=8, name='code')
        session_id = self._make_uint(session_id, bits=16, name='session ID')

        if tags is not None and (isinstance(tags, (str, bytes, bytearray, Mapping))
                                 or not isinstance(tags, Iterable)):
            raise ProtocolError(f'{self.alias}: invalid tags: must be an iterable of tags, not {tags!r}')

        made = []  # type: list[Schema_Tag]
        packed = payload if isinstance(payload, (bytes, bytearray)) else bytes(payload)
        if code_ == Enum_Code.PPP_Session_Stage:
            if tags:
                raise ProtocolError(f'{self.alias}: tags given in the session stage')
            size = len(packed)
        else:
            if packed:
                raise ProtocolError(f'{self.alias}: payload given in the discovery stage')
            made = [self._make_tag(tag) for tag in (tags or ())]
            size = sum(4 + len(tag.value) for tag in made)

        if payload_length is None:
            payload_length = size
        payload_length = self._make_uint(payload_length, bits=16, name='length')
        # NOTE: Another Length would read back with octets moved between the payload or tags
        # and the trailer, unless a rebuild of a cut packet carries it, cut back by ``pack``.
        if payload_length != size and self.__short_read__ is None:
            raise ProtocolError(f'{self.alias}: length {payload_length} is not the {size} octet(s) '
                                'after the header')

        return Schema_PPPoE(
            info={
                'ver': 1,
                'type': 1,
            },
            code=code_,
            session_id=session_id,
            length=payload_length,
            tags=None if code_ == Enum_Code.PPP_Session_Stage else made,
            payload=payload,
            trailer=trailer,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[6]':
        """Return an estimated length for the object."""
        return 6

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types. EtherTypes ``0x8863`` and ``0x8864`` are dispatched
            here as well.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.PPP_ETHER  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_PPPoE') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'code': data.code,
            'session_id': data.session_id,
            # NOTE: As ``payload_length``: ``length`` is ProtocolBase's parse length (#1172).
            'payload_length': data.length,
            'tags': data.tags,
            'payload': cls._make_payload(data),
            'trailer': data.get('trailer', b''),
        }

    def _make_tag(self, tag: 'Data_Tag | Mapping[str, Any] | tuple[Enum_Tag | int, bytes]') -> 'Schema_Tag':
        """Make a discovery tag.

        Args:
            tag: A ``(type, value)`` pair, or a mapping of the tag's ``type``,
                ``value`` and optionally ``length``, by default that of the
                value.

        Returns:
            The tag.

        Raises:
            ProtocolError: If ``tag`` is neither, or has no ``type`` or
                ``value``; if the type does not fit, or the value is not
                :class:`bytes`; or if the length is not the value's.

        """
        if isinstance(tag, tuple) and len(tag) == 2:
            type_, value, length = tag[0], tag[1], None
        elif isinstance(tag, Mapping) and 'type' in tag and 'value' in tag:
            type_, value, length = tag['type'], tag['value'], tag.get('length')
        else:
            raise ProtocolError(f'{self.alias}: invalid tag: must be a (type, value) pair or a '
                                f'mapping of its type and value, not {tag!r}')
        if not isinstance(value, (bytes, bytearray)):
            raise ProtocolError(f'{self.alias}: invalid tag value: {value!r}')
        length = self._make_uint(len(value) if length is None else length, bits=16, name='tag length')
        # NOTE: Another length would read back with the value cut or run into the next tag.
        if length != len(value):
            raise ProtocolError(f'{self.alias}: tag length {length} is not its value\'s {len(value)}')
        return Schema_Tag(
            type=self._make_index(type_, Enum_Tag, bits=16, name='tag type'),
            length=length,
            value=bytes(value),
        )

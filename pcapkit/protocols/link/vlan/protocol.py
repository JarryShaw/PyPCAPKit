# -*- coding: utf-8 -*-
"""VLAN - 802.1Q/802.1ad VLAN Tag Types
==========================================

.. module:: pcapkit.protocols.link.vlan.protocol

:mod:`pcapkit.protocols.link.vlan.protocol` contains
:class:`~pcapkit.protocols.link.vlan.protocol.VLAN` only, an abstract base class holding
the tag layout shared by every VLAN tag [*]_. The concrete tags live in
packages of their own: :class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag` for the
802.1Q customer tag (``0x8100``) and :class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag`
for the 802.1ad service tag (``0x88A8``). The tag structure is described as
below, keyed as for a customer tag; a service tag's keys start ``s_tag`` instead:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  0           0   ``c_tag.tci``             Tag Control Information
  0           0   ``c_tag.tci.pcp``         Priority Code Point
  0           3   ``c_tag.tci.dei``         Drop Eligible Indicator
  0           4   ``c_tag.tci.vid``         VLAN Identifier
  2          16   ``c_tag.type``            Protocol (Internet Layer)
======= ========= ====================== =============================

Both tags have the same tag control information layout -- 3-bit PCP, 1-bit
DEI, 12-bit VID -- and differ only in the tag protocol identifier (TPID) that
selected them. The TPID is the EtherType field of the encapsulating header, not
part of the tag, so both classes share all parsing and construction code.

They are still distinct classes because 802.1ad *stacks* them: a Q-in-Q frame
carries a service tag whose next EtherType, ``0x8100``, selects a customer tag.
:attr:`~pcapkit.protocols.protocol.Protocol.info_name` -- ``s_tag`` against
``c_tag`` -- keeps the two apart in the parsed
:class:`~pcapkit.corekit.infoclass.Info`; one class bound at both EtherTypes
would nest one ``c_tag`` inside another.

Each tag has a package of its own, since a package holds one protocol class,
named after it (:issue:`2529`). This base is abstract and nothing dispatches to
it, so its :meth:`~pcapkit.protocols.protocol.Protocol.__index__` raises.

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.vlan.priority_level import PriorityLevel as Enum_PriorityLevel
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.link.vlan.data import TCI as Data_TCI
from pcapkit.protocols.link.vlan.data import VLAN as Data_VLAN
from pcapkit.protocols.link.vlan.schema import TCI as Schema_TCI
from pcapkit.protocols.link.vlan.schema import VLAN as Schema_VLAN
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.link.vlan.schema import TCIType
    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['VLAN']


class VLAN(Link[Data_VLAN, Schema_VLAN],  # pylint: disable=abstract-method
           schema=Schema_VLAN, data=Data_VLAN):
    """Abstract base class for 802.1Q/802.1ad VLAN tag types.

    The class implements the whole of the tag -- both parsing and construction --
    since the customer and service tags are byte-for-byte identical. What it
    deliberately leaves to its subclasses is only how the tag *names* itself:
    :attr:`~pcapkit.protocols.protocol.Protocol.name`,
    :attr:`~pcapkit.protocols.protocol.Protocol.alias` and
    :attr:`~pcapkit.protocols.protocol.Protocol.info_name`.

    It is abstract for the same reason :class:`~pcapkit.protocols.internet.ip.protocol.IP`
    is: :attr:`~pcapkit.protocols.protocol.Protocol.name` is declared
    abstract by :class:`~pcapkit.protocols.protocol.ProtocolBase` and is not
    defined here, so the class cannot be instantiated. Bind
    :class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag` or
    :class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag`, never this class.

    .. versionchanged:: 1.5.0

       Became an abstract base. The 802.1Q customer tag it implemented, with its
       ``name``, ``alias`` and ``info_name``, moved to
       :class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag`.

    .. versionchanged:: 1.6.0

       ``pcp`` and ``type`` of :meth:`make` each take a member or an
       :class:`int` code, resolved with the enumeration's ``get``, and so does
       the ``pcp`` of its ``tci``; a name, a :obj:`bool`, or a code the field
       cannot carry raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`,
       rather than resolving against an enumeration inferred from the caller's
       frame or writing a different value (:issue:`2594`).

    .. versionremoved:: 1.6.0

       The ``pcp_default``, ``pcp_namespace``, ``pcp_reversed``,
       ``type_default``, ``type_namespace`` and ``type_reversed`` arguments of
       :meth:`make`; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def length(self) -> 'Literal[4]':
        """Header length of current protocol."""
        return 4

    @property
    def protocol(self) -> 'Enum_EtherType':
        """Name of next layer protocol."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["VLAN"], Literal["C_Tag"], Literal["S_Tag"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the family name, then every tag in it, as
            :meth:`L2TP.id <pcapkit.protocols.link.l2tp.protocol.L2TP.id>` does for
            its own family. Note that unlike L2TP's versions, the two tags are
            *distinct protocols* rather than flavours of one, so each is its own
            canonical name; they carry ``VLAN`` only as a secondary alias.

        """
        return ('VLAN', 'C_Tag', 'S_Tag')

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_VLAN':  # pylint: disable=unused-argument
        """Read 802.1Q/802.1ad VLAN tag type.

        Structure of 802.1Q/802.1ad VLAN tag type [`IEEE 802.1Q <https://standards.ieee.org/ieee/802.1Q/6844/>`__]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              TCI              |                               |
           |-------------------------------|                               |
           |  P  |D|                       |             Type              |
           |  C  |E|          VID          |                               |
           |  P  |I|                       |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        tci = schema.tci
        vlan = Data_VLAN(
            tci=Data_TCI(
                pcp=Enum_PriorityLevel.get(tci['pcp']),
                dei=bool(tci['dei']),
                vid=int(tci['vid']),
            ),
            type=schema.type,
        )
        return self._decode_next_layer(vlan, schema.type, length - self.length)

    def make(self,
             tci: 'Optional[Schema_TCI | TCIType]' = None,
             pcp: 'Enum_PriorityLevel | int' = Enum_PriorityLevel.BE,
             dei: 'bool' = False,
             vid: 'int' = 0,
             type: 'Enum_EtherType | int' = Enum_EtherType.Internet_Protocol_version_4,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_VLAN':
        """Make (construct) packet data.

        Args:
            tci: TCI field; its ``pcp``, ``dei`` and ``vid`` take the place of
                the arguments of those names when given.
            pcp: Priority Code Point (PCP) field.
            dei: Drop Eligible Indicator (DEI) field.
            vid: VLAN Identifier (VID) field.
            type: EtherType field.
            payload: Payload field.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``pcp``, the ``pcp`` of ``tci``, or ``type`` is
                a name, a :obj:`bool`, or a member or code its field cannot
                carry.

        """
        if tci is not None:
            pcp = tci['pcp']
            dei = tci['dei']  # type: ignore[assignment]
            vid = tci['vid']
        pcp_value = self._make_index(pcp, Enum_PriorityLevel, bits=3, name='PCP')
        type_value = self._make_index(type, Enum_EtherType, bits=16, name='EtherType')

        return Schema_VLAN(
            tci={
                'pcp': pcp_value,
                'dei': dei,
                'vid': vid,
            },
            type=type_value,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

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
    def _make_data(cls, data: 'Data_VLAN') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'tci': {
                'pcp': data.tci.pcp,
                'dei': data.tci.dei,
                'vid': data.tci.vid,
            },
            'type': data.type,
            'payload': cls._make_payload(data),
        }

# -*- coding: utf-8 -*-
"""L2TP - Layer Two Tunnelling Protocol
==========================================

.. module:: pcapkit.protocols.link.l2tp.protocol

:mod:`pcapkit.protocols.link.l2tp.protocol` contains
:class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` only, an abstract base class for the
Layer Two Tunnelling Protocol family [*]_. The concrete versions live in modules
of their own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
   * - L2TPv2
     - :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`
     - :rfc:`2661`

Only L2TPv2 is implemented; the missing members are set out below.

The base carries **no header parsing**, as
:class:`~pcapkit.protocols.internet.ip.protocol.IP` carries none for its family: the
versions share only a version nibble at bits 12-15 of the first 16-bit word, so a
base that parsed further would impose one version's layout on all of them.

Unimplemented Members
---------------------

**L2TPv3** [:rfc:`3931`] has a different session header and a different control
message header from v2, and is reachable two ways -- over UDP port 1701 like v2
(§4.1.2), and directly over IP as **protocol number 115** (§4.1.1: *"L2TPv3 over
IP (both versions) utilizes the IANA-assigned IP protocol ID 115"*). So
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
leaves 115 unbound until an ``L2TPv3`` class exists; v2's
:meth:`~pcapkit.protocols.protocol.Protocol.__index__` is its UDP port.

Binding :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` at 115 does not
work (:issue:`548`). Over IP the v3
session header is, in :rfc:`3931` §4.1.1.1's own words, *"free of any restrictions
imposed by coexistence with L2TPv2 and L2F"* -- a data message opens with the raw
32-bit Session ID and carries **no version nibble at all**, so there is nothing a
v2 parser could test to recognise that the datagram is not its own. Without the
version check in :meth:`L2TPv2.read <pcapkit.protocols.link.l2tpv2.protocol.L2TPv2.read>`,
that binding reports ``version=4``, ``tunnelid=0x5678`` and ``sessionid=0xff03``
for a v3-over-IP datagram: a complete header assembled out of a Session ID and
the first two octets of the PPP frame behind it. The check refuses that datagram
only because its Session ID does not put ``2`` in the nibble; one that does
parses as v2.

**L2F** [:rfc:`2341`] is reached when the version nibble reads ``1``. It is *not*
an earlier version of L2TP: :rfc:`2661` §3.1 requires ``Ver`` to be 2 and reserves
the value 1 "to permit detection of L2F packets should they arrive intermixed
with L2TP packets". L2F is a separate protocol with its own header. It is
therefore to be implemented as ``L2F``, the canonical name, carrying ``L2TPv1``
only as an alias in its :meth:`~pcapkit.protocols.protocol.Protocol.id`. See
:meth:`L2TPv2.id <pcapkit.protocols.link.l2tpv2.protocol.L2TPv2.id>` for how a
version-flavoured alias is spelled: canonical name first, alias second, since
callers take element zero as canonical.

Selecting a Version
-------------------

Constructing the base gives the member its ``version`` field names, from octets
or from fields; without it, octets give the one their version nibble names, and
fields are refused, since no field picks a member (:issue:`2574`).
:meth:`L2TP._member_of_version <pcapkit.protocols.link.l2tp.protocol.L2TP._member_of_version>`
maps ``2`` to :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` and refuses any
other version, for that field, for the nibble and for the data
:meth:`L2TP.from_data <pcapkit.protocols.link.l2tp.protocol.L2TP.from_data>` is handed.
:meth:`L2TPv2.read <pcapkit.protocols.link.l2tpv2.protocol.L2TPv2.read>` **checks** the
nibble as well and refuses anything other than ``2``. That keeps v3 traffic on
port 1701, which :rfc:`3931` §4.7.2 shares, from being reported as v2 with a
tunnel and session ID read out of v3's Control Connection ID.

UDP port 1701 binds L2TPv2 itself, the only member.
:meth:`~pcapkit.protocols.link.l2tp.protocol.L2TP._member_of_version` is where a further
member goes, and binding the port to this base through a hook making the same
switch, as :meth:`IGMP._dispatch <pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch>`
does for IP protocol 2, needs no new registry: unlike
:class:`~pcapkit.protocols.application.http.protocol.HTTP`, whose
:meth:`~pcapkit.protocols.application.http.protocol.HTTP._guess_version` has to *infer*
the version, L2TP states it in those four bits. The switch belongs on the
**UDP** path only: over IP protocol 115 there is no nibble to switch on, per the
§4.1.1.1 note above.

.. [*] https://en.wikipedia.org/wiki/Layer_2_Tunneling_Protocol

"""
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from typing import IO, Any, NoReturn, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.protocols.link.l2tpv2.protocol import L2TPv2

__all__ = ['L2TP']

#: The member :meth:`L2TP._member_of_version` picks for version ``2``, resolved
#: there rather than imported, so its first import holds
#: :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_L2TPV2: 'ModuleDescriptor[L2TPv2]' = \
    ModuleDescriptor('pcapkit.protocols.link.l2tpv2.protocol', 'L2TPv2')


class L2TP(Link[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements all protocols in L2TP family.

    - Layer Two Tunnelling Protocol version 2
      (:class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`) [:rfc:`2661`]

    It is abstract for the same mechanical reason
    :class:`~pcapkit.protocols.internet.ip.protocol.IP` is:
    :attr:`~pcapkit.protocols.protocol.Protocol.name` and
    :meth:`~pcapkit.protocols.protocol.Protocol.read` are both declared
    abstract by :class:`~pcapkit.protocols.protocol.ProtocolBase` and neither is
    defined here, so no instance of it exists. Bind a version, never this class.

    It dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). The ``version`` field names the member; without it, octets
    give the one their version nibble names, and fields are refused.
    :meth:`from_data` reads the ``version`` of its data. See :meth:`__new__`.

    .. versionchanged:: 1.5.0

       Became an abstract base for the family; its version-2 parsing moved to
       :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`.

    .. versionchanged:: 1.6.0

       Constructing it and :meth:`from_data` give
       :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2`, where they raised
       :exc:`TypeError`. The ``version`` field names the member; without it,
       octets give the one their version nibble names, and fields are refused
       (:issue:`2574`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    #: NOTE: Declared on the base, and so shared by every version, deliberately.
    #: This is the key the parsed datagram appears under, and a consumer wants
    #: ``udp.l2tp`` whichever version was on the wire -- the version is reported
    #: by :attr:`~pcapkit.protocols.protocol.Protocol.alias` instead. Left to
    #: the class-name default it would read ``l2tpv2``, ``l2tpv3`` and so on, and
    #: every consumer would have to know the version to find the data.
    @property
    def info_name(self) -> 'Literal["l2tp"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'l2tp'

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["L2TP"], Literal["L2TPv2"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol -- the family name, then every version in
            it, as :meth:`VLAN.id <pcapkit.protocols.link.vlan.protocol.VLAN.id>`
            does for its own family. ``L2F`` and ``L2TPv3`` join this tuple when
            they are implemented.

        """
        return ('L2TP', 'L2TPv2')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member the
            ``version`` of ``data`` names.

        Raises:
            ProtocolError: If no member reads that ``version``, on this class.

        """
        if cls is not L2TP:
            return super().from_data(data, **kwargs)
        member = cls._member_of_version(data.get('version'))
        return cast('Self', member.from_data(data, **kwargs))

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        Note:
            An abstract base is reached by nothing, so it has no index of its
            own.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'L2TP':
        """Create the member a construction of this class describes.

        The ``version`` field names the member, on either path. Without it,
        parsing octets gives the member the version nibble, bits 12 to 15 of
        their first word, names, and building from fields is refused, since no
        field picks a member. That member's ``__init__`` then runs with the same
        arguments. A subclass of this class is created as itself.

        Args:
            file: Source packet stream, read here without being consumed.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            ProtocolError: If no member reads ``version``; or, without it, if
                building from fields, or if the octets are shorter than the first
                word or no member reads their version.

        """
        if cls is not L2TP:
            return super().__new__(cls, file, length, **kwargs)
        version = kwargs.get('version')
        if version is None:
            if file is None:
                raise ProtocolError('L2TP: no version to build with; pass version=2')
            if isinstance(file, bytes):
                head = file[:2]
            else:
                offset = file.tell()
                head = file.read(2)
                file.seek(offset)
            if len(head) < 2:
                raise ProtocolError('L2TP: no version in a packet shorter than 2 octets')
            version = head[1] & 0x0F
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[L2TP]':
        """The member that reads a ``version`` of the version nibble.

        Args:
            version: Version of L2TP.

        Returns:
            :class:`~pcapkit.protocols.link.l2tpv2.protocol.L2TPv2` for ``2``.

        Raises:
            ProtocolError: For any other ``version``, or one that is no
                :obj:`int`, as a :obj:`bool` or a :obj:`float` is even where it
                equals ``2``: ``1`` is L2F and ``3`` is L2TPv3, neither
                implemented.

        """
        if isinstance(version, int) and not isinstance(version, bool) and version == 2:
            return cast('Type[L2TP]', _L2TPV2.klass)
        raise ProtocolError(f'L2TP: invalid version: {version!r}')

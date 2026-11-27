# -*- coding: utf-8 -*-
"""OSPF - Open Shortest Path First
=====================================

.. module:: pcapkit.protocols.application.ospf.protocol

:mod:`pcapkit.protocols.application.ospf.protocol` holds
:class:`~pcapkit.protocols.application.ospf.protocol.OSPF`, the abstract base of the
Open Shortest Path First (OSPF) family [*]_. Each version is a member of its own:

.. list-table::
   :header-rows: 1

   * - Version
     - Class
     - Specification
     - Header
   * - 1
     - :class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`
     - :rfc:`1131`
     - 24 octets, AuType and Authentication
   * - 2
     - :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`
     - :rfc:`2328`
     - 24 octets, AuType and Authentication
   * - 3
     - :class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`
     - :rfc:`5340`
     - 16 octets, Instance ID and a reserved octet

All three share the first 14 octets alone, Version to Checksum, so the base
parses no header. IP protocol 89 is OSPF's in every version, so
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`
binds this base, which picks the member by the Version octet. Each RFC requires its
own version there (:rfc:`1131` Section 8.2, :rfc:`2328#section-8.2`,
:rfc:`5340#section-4.2.2`), so a direct parse of any other version raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, and behind IP the packet is left
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

.. [*] https://en.wikipedia.org/wiki/Open_Shortest_Path_First

.. versionadded:: 1.5.0

   Moved here from ``pcapkit.protocols.link.ospf``, with its data model and
   header schema. :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` derives
   from :class:`~pcapkit.protocols.application.application.Application`, so
   its layer is ``'Application'`` (:issue:`719`).

.. versionremoved:: 1.5.0

   ``pcapkit.protocols.link.ospf``, ``pcapkit.protocols.data.link.ospf`` and
   ``pcapkit.protocols.schema.link.ospf``, the ``OSPF`` name that
   :mod:`pcapkit.protocols.link`, ``pcapkit.protocols.data.link`` and
   ``pcapkit.protocols.schema.link`` each exported, and the
   ``OSPF_CrytographicAuthentication`` name that
   ``pcapkit.protocols.data.link`` and ``pcapkit.protocols.schema.link``
   exported, with no alias (:issue:`719`, :issue:`1090`).

.. versionchanged:: 1.5.0

   A rebuild keeps the parsed Packet Length and the octets past it, where
   ``OSPF.make`` recomputed the length from the payload and dropped those octets;
   it takes them as ``packet_length`` and ``trailer`` (:issue:`1249`,
   :issue:`1455`).

.. versionchanged:: 1.6.0

   The OSPFv2 checksum is computed when ``OSPF.make`` is given none, and verified
   on read under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY` (:issue:`2475`).

   ``OSPF.make`` raises :exc:`~pcapkit.utilities.exceptions.ProtocolError` for a
   checksum, or the reserved octets of cryptographic authentication data, that is
   not two octets, rather than padding or cutting it (:issue:`2676`).

.. versionchanged:: 1.8.1

   :class:`~pcapkit.protocols.application.ospf.protocol.OSPF` became the abstract base
   of the family, giving :class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`,
   :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2` or
   :class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`; it read every
   version with OSPFv2's 24-octet header, OSPFv3's 16-octet one included. A version
   none of them reads, 0 or 4 to 255, is refused, and left
   :class:`~pcapkit.protocols.misc.raw.protocol.Raw` behind IP (:issue:`3105`).

.. versionremoved:: 1.8.1

   ``pcapkit.protocols.application.ospf.schema`` and
   ``pcapkit.protocols.application.ospf.data``, with their ``OSPF`` and
   ``CryptographicAuthentication`` classes and
   ``pcapkit.protocols.application.ospf.schema.ospf_auth_data_selector``;
   ``pcapkit.protocols.application.ospf.Schema_OSPF``,
   ``pcapkit.protocols.application.ospf.Schema_CryptographicAuthentication``,
   ``pcapkit.protocols.application.ospf.Data_OSPF`` and
   ``pcapkit.protocols.application.ospf.Data_CryptographicAuthentication``; and
   ``OSPF.read``, ``OSPF.make`` and ``OSPF.length``, with ``OSPF._make_data``,
   ``OSPF._read_encrypt_auth``, ``OSPF._make_encrypt_auth``, ``OSPF._read_id_numbers``
   and ``OSPF._make_id_numbers``. None has an alias: the OSPFv2 header moved to
   :mod:`pcapkit.protocols.application.ospfv2`, as ``OSPFv2``, and each member defines
   its own ``read``, ``make`` and ``length`` (:issue:`3105`).

"""
from typing import TYPE_CHECKING, Generic, cast, overload

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.corekit.sentinels import NO_VALUE, NoValueType
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.protocol import _PT, _ST, _nothing_to_parse
from pcapkit.utilities import config
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import IO, Any, Iterable, Mapping, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.const.ospf.packet import Packet as Enum_Packet
    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.protocols.misc.raw.protocol import Raw
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['OSPF']

#: tuple[tuple[int, ModuleDescriptor[OSPF]], ...]: Each version and the member that
#: reads it, resolved in :meth:`OSPF._member_of_version` rather than imported, so its
#: first import holds :data:`~pcapkit.utilities.importlib.import_lock` (:issue:`2771`).
_MEMBERS = (
    (1, ModuleDescriptor('pcapkit.protocols.application.ospfv1.protocol', 'OSPFv1')),
    (2, ModuleDescriptor('pcapkit.protocols.application.ospfv2.protocol', 'OSPFv2')),
    (3, ModuleDescriptor('pcapkit.protocols.application.ospfv3.protocol', 'OSPFv3')),
)  # type: tuple[tuple[int, ModuleDescriptor[OSPF]], ...]


class OSPF(Application[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """This class implements all protocols in the OSPF family.

    - Open Shortest Path First version 1
      (:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`) [:rfc:`1131`]
    - Open Shortest Path First version 2
      (:class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`) [:rfc:`2328`]
    - Open Shortest Path First version 3
      (:class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`) [:rfc:`5340`]

    A routing protocol computes the forwarding table rather than forwarding
    packets, so it is a *user* of the stack rather than part of its forwarding
    path. :rfc:`1812#section-7` places it accordingly, titling that chapter
    "APPLICATION LAYER - ROUTING PROTOCOLS" with OSPF at §7.2.2, while the
    Internet Layer protocols :rfc:`1812#section-4.1` names are IP, ICMP and IGMP.
    Hence :class:`~pcapkit.protocols.application.application.Application` as the
    base, and ``layer == 'Application'``. See
    :doc:`/contributing/conventions/protocol-layer-placement`.

    It is abstract, as :class:`~pcapkit.protocols.link.l2tp.protocol.L2TP` is:
    :attr:`~pcapkit.protocols.protocol.Protocol.length`,
    :meth:`~pcapkit.protocols.protocol.Protocol.read` and
    :meth:`~pcapkit.protocols.protocol.Protocol.make` are declared abstract by
    :class:`~pcapkit.protocols.protocol.ProtocolBase`, and none is defined here. It
    dispatches on both paths, never giving an instance of this class
    (:issue:`2574`). The ``version`` field names the member; without it, octets
    give the one their Version octet names, and fields are refused.
    :meth:`from_data` reads the ``version`` of its data. See :meth:`__new__`.

    Note:
        The subpackage does not track the dispatch tier. OSPF is dispatched
        from :attr:`Internet.__proto__
        <pcapkit.protocols.internet.internet.Internet.__proto__>` at
        :attr:`~pcapkit.const.reg.transtype.TransType.OSPFIGP` (IANA protocol
        number 89), since IP is what carries it.

    .. versionchanged:: 1.6.0

       Each enumeration field of its ``make`` takes a member or an :class:`int`
       code, resolved with the enumeration's ``get``; a name, a :obj:`bool` for a
       field wider than one bit, or a code the field cannot carry raises
       :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than resolving
       against an enumeration inferred from the caller's frame or writing a
       different value (:issue:`2594`).

    .. versionremoved:: 1.6.0

       The ``type_default``, ``type_namespace``, ``type_reversed``,
       ``auth_type_default``, ``auth_type_namespace`` and ``auth_type_reversed``
       arguments of its ``make``; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    .. versionchanged:: 1.8.1

       Became the abstract base of the family; its parsing moved to
       :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`. Constructing it
       and :meth:`from_data` give a member, and fields without ``version`` are refused
       (:issue:`3105`).

    """

    #: Version number of corresponding protocol, as read off the header. Held on
    #: the instance rather than read back out of :attr:`self._info
    #: <pcapkit.protocols.protocol.Protocol._info>` because :attr:`name` and
    #: :attr:`alias` are needed *during* :meth:`read` -- :meth:`self._decode_next_layer
    #: <pcapkit.protocols.protocol.Protocol._decode_next_layer>` builds the
    #: protocol chain out of :attr:`alias` -- and ``_info`` is not assigned until
    #: :meth:`read` has returned. See ``ARP._acnm`` on
    #: :class:`~pcapkit.protocols.link.arp.protocol.ARP`, which has the same constraint.
    #: Each member's :meth:`read` sets it.
    _version: 'int'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'str':
        """Name of current protocol."""
        return f'Open Shortest Path First version {self._version}'

    @property
    def alias(self) -> 'str':
        """Acronym of current protocol."""
        return f'OSPFv{self._version}'

    #: NOTE: On the base, as L2TP's is, so a consumer finds ``ospf`` whichever
    #: version was on the wire.
    @property
    def info_name(self) -> 'Literal["ospf"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'ospf'

    @property
    def type(self) -> 'Enum_Packet':
        """OSPF packet type."""
        return self._info.type  # type: ignore[attr-defined]

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["OSPFv1"], Literal["OSPFv2"], Literal["OSPFv3"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, each member's name, as
            :meth:`IP.id <pcapkit.protocols.internet.ip.protocol.IP.id>` lists
            its own; each member narrows it to its own name.

        """
        return ('OSPFv1', 'OSPFv2', 'OSPFv3')

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', /, **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member the
            ``version`` of ``data`` names.

        Raises:
            ProtocolError: If, on this class, ``data`` carries no ``version`` or
                one no member reads.

        """
        if cls is not OSPF:
            return super().from_data(data, **kwargs)
        member = cls._member_of_version(data.get('version'))
        return cast('Self', member.from_data(data, **kwargs))

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_, which every
            member inherits.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.OSPFIGP  # type: ignore[return-value]

    def __length_hint__(self) -> 'int':
        """Return an estimated length for the object.

        The longest member's header, OSPFv1's and OSPFv2's 24 octets, as
        :meth:`L2TPv2.__length_hint__
        <pcapkit.protocols.link.l2tpv2.protocol.L2TPv2.__length_hint__>` takes its
        longest form.

        """
        return 24

    if not TYPE_CHECKING:
        # NOTE: For the docs' class signature (#1860): mypy rejects each overload of an abstract
        # class's ``__init__``, so it reads the one below and refuses this base as ``abstract`` (#3081).
        @overload  # pragma: no cover
        def __init__(self, file: 'IO[bytes] | bytes', length: 'Optional[int]' = ..., /, *,
                     version: 'Optional[int]' = ...,
                     layer: 'Optional[str]' = ...,
                     protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     ) -> 'None': ...
        @overload  # pragma: no cover
        def __init__(self, *, version: 'Optional[int]' = ...,
                     context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = ...,  # pylint: disable=line-too-long
                     **fields: 'Any') -> 'None': ...

    def __init__(self, file: 'IO[bytes] | bytes | NoValueType' = NO_VALUE,  # pylint: disable=super-init-not-called
                 length: 'Optional[int]' = None, /, *,
                 version: 'Optional[int]' = None,
                 layer: 'Optional[str]' = None,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None,  # pylint: disable=line-too-long
                 **fields: 'Any') -> 'None':
        """Parse a protocol instance from its octets, or construct one from its fields.

        Args:
            file: Source packet stream; omitted to construct.
            length: Length of packet data.
            version: Version of OSPF: the member :meth:`__new__` picks, which must
                be this class's own.
            layer: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            protocol: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            context: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.
            **fields: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If ``version`` is not a version of OSPF, or is not this
                class's own version: that of the member it is or derives from.

        .. versionadded:: 1.8.1

        """
        if isinstance(file, NoValueType):
            # NOTE: ``version`` is a field of every member, which ``make`` writes.
            if version is not None:
                fields['version'] = version
            self._construct(context, self._call_fields(length, layer, protocol, fields))
            return
        if version is not None and not isinstance(self, self._member_of_version(version)):
            raise ProtocolError(f'{type(self).__name__}: no version of its own to match '
                                f'version={version!r}')
        # NOTE: ``_parse``, inline, as the base's ``__init__`` takes no ``version``, and
        # calling ``_parse`` adds a frame per layer (#1610, #2840).
        keywords = self._start_parse(file, layer, protocol, context, {}, fields)
        self.__post_init__(file, length, **keywords)
        self._info.__update__(packet=self.packet.payload)

    def __new__(cls, file: 'Optional[IO[bytes] | bytes] | NoValueType' = NO_VALUE,
                length: 'Optional[int]' = None, /, **kwargs: 'Any') -> 'OSPF':
        """Create the member a parse or a construction of this class describes.

        The ``version`` keyword names the member. Without it, the octets give the
        member their Version octet, the first, names, and fields are refused. That
        member's ``__init__`` then runs with the same arguments. A subclass of this
        class is created as itself.

        Args:
            file: Source packet stream, read here without being consumed;
                omitted to construct.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            TypeError: If ``file`` is :obj:`None`, on this class.
            ProtocolError: On this class, if ``version`` is not a version of OSPF;
                if, without it, the octets are empty; or if fields come without it.

        .. versionadded:: 1.8.1

        """
        if cls is not OSPF:
            return super().__new__(cls, file, length, **kwargs)
        if isinstance(file, NoValueType):
            member = cls._construction_member(kwargs)
            return member.__new__(member)
        if file is None:
            raise _nothing_to_parse(OSPF)
        version = kwargs.get('version')
        if version is None:
            if isinstance(file, bytes):
                head = file[:1]
            else:
                offset = file.tell()
                head = file.read(1)
                file.seek(offset)
            if not head:
                raise ProtocolError('OSPF: no version in a packet shorter than 1 octet')
            version = head[0]
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[OSPF]':
        """The member that reads a ``version`` of the Version octet.

        Args:
            version: Version of OSPF.

        Returns:
            :class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1` for ``1``,
            :class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2` for ``2`` and
            :class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3` for ``3``.

        Raises:
            ProtocolError: For any other ``version``, or one that is no :obj:`int`, as
                a :obj:`bool` or a :obj:`float` is even where it equals one.

        .. versionadded:: 1.8.1

        """
        if isinstance(version, int) and not isinstance(version, bool):
            for number, member in _MEMBERS:
                if version == number:
                    return member.klass
        raise ProtocolError(f'OSPF: invalid version: {version!r}')

    @classmethod
    def _dispatch(cls, data: 'bytes', length: 'int') -> 'Type[ProtocolBase] | Type[Raw]':  # pylint: disable=unused-argument
        """Pick the class that parses the OSPF packet at the start of ``data``.

        As :meth:`IGMP._dispatch <pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch>`
        does for IP protocol 2, before any class is built.

        Args:
            data: Payload of the IP layer, starting at the OSPF packet.
            length: The OSPF packet's length, in octets.

        Returns:
            The member its Version octet names, as :meth:`_member_of_version` gives it;
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` for any other version,
            which then keeps its octets undissected.

        .. versionadded:: 1.8.1

        """
        for number, member in _MEMBERS:
            if data[:1] == bytes([number]):
                return member.klass
        from pcapkit.protocols.misc.raw.protocol import Raw  # isort: skip # pylint: disable=import-outside-toplevel
        return Raw

    @classmethod
    def _construction_member(cls, fields: 'dict[str, Any]') -> 'Type[Self]':
        """The member :meth:`from_fields`, :meth:`from_data` and a call given no file construct.

        On this class, the member the ``version`` field names, which stays in
        ``fields``; on another, the class itself.

        Args:
            fields: Construction keywords.

        Returns:
            The member, or the class itself.

        Raises:
            ProtocolError: If, on this class, ``version`` is missing or is not a
                version of OSPF.

        .. versionadded:: 1.8.1

        """
        if cls is not OSPF:
            return cls
        version = fields.get('version')
        if version is None:
            raise ProtocolError('OSPF: no version to build with; pass version=1, 2 or 3')
        return cast('Type[Self]', cls._member_of_version(version))

    def _make_version(self, version: 'Any') -> 'int':
        """Check that ``version`` is one this class reads, for :meth:`make` to write.

        Args:
            version: The ``version`` given to :meth:`make`.

        Returns:
            ``version``, as a plain :class:`int`.

        Raises:
            ProtocolError: If ``version`` is not a version of OSPF, or names another
                member.

        .. versionadded:: 1.8.1

        """
        if not isinstance(self, self._member_of_version(version)):
            raise ProtocolError(f'{type(self).__name__}: version={version!r} names another member')
        return int(version)

    @staticmethod
    def _rebuilt_version(data: 'Any', own: 'int') -> 'int':
        """The version a rebuild of ``data`` writes: its own, or ``own`` if the capture ended first.

        A capture that ends before the Version octet leaves it zero, which names no
        member's own version; the rebuild is cut back before the octet,
        so the version it writes is never read (:issue:`2880`).

        Args:
            data: The data model being rebuilt.
            own: The version of the member rebuilding it.

        Returns:
            The version for :meth:`make`.

        .. versionadded:: 1.8.1

        """
        record = data.get('__short_read__')
        if record is not None and tuple(record) == ('version', 0):
            return own
        return data.version

    def _verify_checksum(self, ospf: '_PT', exempt: 'bool' = False) -> 'None':
        """Record on ``ospf`` the outcome of verifying a 24-octet header's checksum.

        Only under :data:`~pcapkit.utilities.config.CHECKSUM_VERIFY`, as
        ``checksum_status``. OSPFv1 and OSPFv2 define it alike, over the packet
        but the 8-octet Authentication field at octet 16, with no pseudo-header
        (:rfc:`1131` Section A.2, :rfc:`2328#appendix-A.3.1`). OSPFv3's covers an
        IPv6 pseudo-header instead (:rfc:`5340#appendix-A.3.1`) and is not verified.

        Args:
            ospf: Parsed packet data, with ``len`` and ``chksum``.
            exempt: Whether the packet leaves its checksum unused, as OSPFv2's
                cryptographic authentication does (:rfc:`2328#appendix-D.4.3`).

        .. versionadded:: 1.8.1

        """
        if not config.CHECKSUM_VERIFY:
            return
        from pcapkit.corekit.checksum.internet import ChecksumStatus, verify_checksum  # isort: skip # pylint: disable=import-outside-toplevel
        if exempt:
            status = ChecksumStatus.NOT_COMPUTED
        else:
            end = max(ospf.len, 24)  # type: ignore[attr-defined]
            status = verify_checksum(self.alias, self._data[:16] + self._data[24:end],
                                     ospf.chksum, length=end - 8)  # type: ignore[attr-defined]
        ospf.__update__([
            ('checksum_status', status),
        ])

    @staticmethod
    def _compute_checksum(schema: '_ST', packet_length: 'int') -> 'None':
        """Fill in a made 24-octet header's checksum, as :meth:`_verify_checksum` checks it.

        Args:
            schema: The header :meth:`make` built, its checksum zero.
            packet_length: Its Packet Length.

        .. versionadded:: 1.8.1

        """
        from pcapkit.corekit.checksum.internet import compute_checksum  # isort: skip # pylint: disable=import-outside-toplevel
        # NOTE: Over the packet but the Authentication field, as read() checks it (#2475).
        octets = schema.pack()
        schema.checksum = compute_checksum(octets[:16] + octets[24:max(packet_length, 24)])

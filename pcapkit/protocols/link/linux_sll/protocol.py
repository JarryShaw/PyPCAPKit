# -*- coding: utf-8 -*-
"""LINUX_SLL - Linux "Cooked" Capture Encapsulation Family
=============================================================

.. module:: pcapkit.protocols.link.linux_sll.protocol

:mod:`pcapkit.protocols.link.linux_sll.protocol` contains
:class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL` only, the base class of
:class:`~pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1` and
:class:`~pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2`. Constructing the base
gives the one its ``version`` keyword names, from octets or from fields, and is
refused without it, since the link type rather than the header names the
version. Its :meth:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.from_data` gives
the one whose data model it is handed (:issue:`2574`).

"""
import collections
from typing import TYPE_CHECKING, Generic, cast

from pcapkit.const.linux.arphrd import ARPHRD as Enum_ARPHRD
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.decorators import beholder
from pcapkit.corekit.fields.numbers import EnumField
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, ClassVar, DefaultDict, NoReturn, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.link.linux_sll1.data import LinuxSLL1 as Data_LinuxSLL1
    from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1
    from pcapkit.protocols.link.linux_sll2.data import LinuxSLL2 as Data_LinuxSLL2
    from pcapkit.protocols.link.linux_sll2.protocol import LinuxSLL2
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['LinuxSLL']

#: Resolves ``protocol_type`` exactly as
#: :class:`~pcapkit.protocols.link.ethernet.schema.Ethernet` resolves its ``type``.
_ETHERTYPE_FIELD = EnumField(length=2, namespace=Enum_EtherType)

#: The member :class:`LinuxSLL` hands a version 1 header to; it, the version 2
#: member and their data models are resolved where used rather than imported, so a
#: member's first import holds :data:`~pcapkit.utilities.importlib.import_lock`
#: (:issue:`2771`).
_LINUX_SLL1: 'ModuleDescriptor[LinuxSLL1]' = \
    ModuleDescriptor('pcapkit.protocols.link.linux_sll1.protocol', 'LinuxSLL1')
_LINUX_SLL2: 'ModuleDescriptor[LinuxSLL2]' = \
    ModuleDescriptor('pcapkit.protocols.link.linux_sll2.protocol', 'LinuxSLL2')
_DATA_LINUX_SLL1: 'ModuleDescriptor[Data_LinuxSLL1]' = \
    ModuleDescriptor('pcapkit.protocols.link.linux_sll1.data', 'LinuxSLL1')
_DATA_LINUX_SLL2: 'ModuleDescriptor[Data_LinuxSLL2]' = \
    ModuleDescriptor('pcapkit.protocols.link.linux_sll2.data', 'LinuxSLL2')


def _resolve_next_layer_proto(registry: 'DefaultDict[int, Any]', arphrd_type: 'int',
                              protocol_type: 'int') -> 'Enum_EtherType | int':
    """Resolve the next-layer dispatch key of either version.

    Args:
        registry: The ``arphrd_type`` registry, i.e. :attr:`LinuxSLL.__proto__
            <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>`.
        arphrd_type: ARP hardware type of the interface the packet was seen on.
        protocol_type: Protocol (internet layer), as parsed off the wire.

    Returns:
        ``protocol_type`` itself if ``arphrd_type`` is a key of ``registry``;
        otherwise the value :class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet`
        stores for the same ``type``.

    """
    if int(arphrd_type) in registry:
        return protocol_type
    return _ETHERTYPE_FIELD.post_process(protocol_type, {})


def _validate_link_addr(alias: 'str', link_addr: 'bytes | bytearray',
                        link_addr_length: 'Optional[int]', *,
                        max_length: 'int') -> 'tuple[bytes, int]':
    """Validate and pad the link-layer address for ``make()`` of either version.

    Args:
        alias: Acronym of the calling protocol, for the error message.
        link_addr: Link-layer address, at most 8 octets.
        link_addr_length: Length in use, by default ``len(link_addr)``; may
            exceed 8, e.g. 20 for InfiniBand, of which the header keeps 8.
        max_length: Maximum of the wire field holding the length.

    Returns:
        ``link_addr`` padded with ``NUL`` octets to 8, and the length.

    Raises:
        ProtocolError: If ``link_addr`` exceeds 8 octets, or the length is
            outside ``0`` to ``max_length``.

    """
    _addr = bytes(link_addr)
    if len(_addr) > 8:
        raise ProtocolError(f'{alias}: invalid link-layer address: {link_addr!r}, '
                            f'must fit in 8 octets')
    if link_addr_length is None:
        link_addr_length = len(_addr)
    elif not 0 <= link_addr_length <= max_length:
        raise ProtocolError(f'{alias}: invalid link-layer address length: {link_addr_length!r}, '
                            f'must be between 0 and {max_length}')
    return _addr.ljust(8, b'\x00'), link_addr_length


class LinuxSLL(Link[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Base class of the Linux "cooked" capture encapsulation family.

    The versions differ in field order and width, so this base holds only the
    next-layer dispatch they share. See :ref:`linux-sll-labels` for the labels
    that select a version.

    This class supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__
    <pcapkit.protocols.link.linux_sll.protocol.LinuxSLL.__proto__>` attribute, keyed by
    ``arphrd_type``:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.FRAD`
         - :class:`pcapkit.protocols.link.frad.protocol.FRAD`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IPGRE`
         - :class:`pcapkit.protocols.link.gre.protocol.GRE`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IEEE80211_RADIOTAP`
         - :class:`pcapkit.protocols.link.radiotap.protocol.Radiotap`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IP6GRE`
         - :class:`pcapkit.protocols.link.gre.protocol.GRE`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.NETLINK`
         - :class:`pcapkit.protocols.link.netlink.protocol.Netlink`

    Every other ``arphrd_type`` reads ``protocol_type`` as an EtherType and
    dispatches it through :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>`, as an Ethernet frame does.

    It dispatches where the version is known, never giving an instance of this
    class (:issue:`2574`). ``version`` names the member, from octets or from
    fields, and nothing else does: the header carries no version of its own,
    and no field picks a member, so either is refused without it.
    :meth:`from_data` gives the member whose data model it is handed, and
    refuses a :obj:`dict`. See :meth:`__new__`.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, keyed by the
    #: ``arphrd_type`` values whose ``protocol_type`` is not an EtherType, per
    #: tcpdump.org's LINUX_SLL and LINUX_SLL2 pages.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw.protocol', 'Raw'),
        {
            Enum_ARPHRD.FRAD:               ModuleDescriptor('pcapkit.protocols.link.frad.protocol',     'FRAD'),
            Enum_ARPHRD.IPGRE:              ModuleDescriptor('pcapkit.protocols.link.gre.protocol',      'GRE'),
            Enum_ARPHRD.IEEE80211_RADIOTAP: ModuleDescriptor('pcapkit.protocols.link.radiotap.protocol', 'Radiotap'),
            Enum_ARPHRD.IP6GRE:             ModuleDescriptor('pcapkit.protocols.link.gre.protocol',      'GRE'),
            Enum_ARPHRD.NETLINK:            ModuleDescriptor('pcapkit.protocols.link.netlink.protocol',  'Netlink'),
        },
    )  # type: DefaultDict[int | Enum_ARPHRD, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by, declared as
    #: :attr:`Link.__proto_key__ <pcapkit.protocols.link.link.Link.__proto_key__>` is.
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_ARPHRD, False)

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["LinuxSLL1"], Literal["LinuxSLL2"]]':
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol: the direct members, each by its own name.

        """
        return ('LinuxSLL1', 'LinuxSLL2')

    @classmethod
    def register(cls, code: 'Enum_ARPHRD', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class for an ``arphrd_type``.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: ARP hardware type as in :class:`~pcapkit.const.linux.arphrd.ARPHRD`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass

        Important:
            This overrides :meth:`Link.register
            <pcapkit.protocols.link.link.Link.register>` because
            :attr:`self.__proto__ <LinuxSLL.__proto__>` is keyed by
            ``arphrd_type`` rather than by EtherType. A registered
            ``arphrd_type`` dispatches through it, and its ``protocol_type``
            is not read as an EtherType.

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this ``arphrd_type``
                is already registered and the incumbent differs from the
                replacement; see :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the guard,
                and for the shipped descriptor a restore puts back (:issue:`1504`).

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'ARP hardware type {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: As :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance; on this class, an instance of the member whose data
            model ``data`` is.

        Raises:
            ProtocolError: If ``data`` is neither member's data model, on this
                class. A :obj:`dict` is refused: it carries no version, and no
                key picks a member.

        """
        if cls is not LinuxSLL:
            return super().from_data(data, **kwargs)

        if isinstance(data, _DATA_LINUX_SLL1.klass):
            return cast('Self', _LINUX_SLL1.klass.from_data(data, **kwargs))
        if isinstance(data, _DATA_LINUX_SLL2.klass):
            return cast('Self', _LINUX_SLL2.klass.from_data(data, **kwargs))
        raise ProtocolError('LinuxSLL: invalid data: must be a LinuxSLL1 or LinuxSLL2 data model')

    ##########################################################################
    # Data models.
    ##########################################################################

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: The family base has no registry entry; nothing
                dispatches to it, only to its members.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    def __init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                 length: 'Optional[int]' = None, *,
                 version: 'Optional[Literal[1, 2]]' = None, **kwargs: 'Any') -> 'None':
        """Initialisation.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            version: Version of the header, ``1`` or ``2``: the member
                :meth:`__new__` picks. Building from fields, it must be this
                class's own. Parsing, it is handed on unread.
            **kwargs: As :meth:`Protocol.__init__
                <pcapkit.protocols.protocol.Protocol.__init__>`.

        Raises:
            ProtocolError: If, building from fields, ``version`` names neither
                member, or is not this class's own version: that of the member
                it is or derives from, which a subclass outside the members
                does not have.

        """
        if file is not None:
            if version is not None:
                kwargs['version'] = version
        elif version is not None and not isinstance(self, self._member_of_version(version)):
            if not any(isinstance(self, self._member_of_version(own)) for own in (1, 2)):
                raise ProtocolError(f'{type(self).__name__}: no version of its own to match '
                                    f'version={version!r}')
            raise ProtocolError(f'{type(self).__name__}: version={version!r} names another member')
        super().__init__(file, length, **kwargs)  # type: ignore[arg-type]

    def __new__(cls, file: 'Optional[IO[bytes] | bytes]' = None,
                length: 'Optional[int]' = None, **kwargs: 'Any') -> 'LinuxSLL':
        """Create the member a construction of this class describes.

        The ``version`` keyword names the member, on either path, and nothing
        else does: the header carries no version of its own, and no field picks
        a member. That member's ``__init__`` then runs with the same arguments. A
        subclass of this class is created as itself.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            An uninitialised instance of the member.

        Raises:
            ProtocolError: If ``version`` is missing, or names neither member.
                Without it, octets are refused as fields are: the link type names
                the version, ``LINUX_SLL`` (113) or ``LINUX_SLL2`` (276).

        """
        if cls is not LinuxSLL:
            return super().__new__(cls, file, length, **kwargs)
        version = kwargs.get('version')
        if version is None:
            if file is not None:
                raise ProtocolError('LinuxSLL: no version field; pass version=1 or version=2, '
                                    'or parse with LinuxSLL1 or LinuxSLL2')
            raise ProtocolError('LinuxSLL: no version to build with; pass version=1 or version=2')
        member = cls._member_of_version(version)
        return member.__new__(member, file, length, **kwargs)

    ##########################################################################
    # Utilities.
    ##########################################################################

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack
                <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of next layer: the class :attr:`self.__proto__
            <LinuxSLL.__proto__>` registers for ``arphrd_type`` when it has a key
            for it, and otherwise the class :attr:`Link.__proto__
            <pcapkit.protocols.link.link.Link.__proto__>` registers for ``proto``
            as an EtherType. Where parsing stops at this layer, either path
            keeps the payload :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, and a
            :class:`~pcapkit.protocols.misc.raw.protocol.Raw` records ``proto`` either way.

        Note:
            :attr:`self.__proto__ <LinuxSLL.__proto__>` holds the
            ``arphrd_type`` keys, so the EtherType path names
            :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`
            itself rather than reaching it through ``super()``, as
            :meth:`FRAD._import_next_layer
            <pcapkit.protocols.link.frad.protocol.FRAD._import_next_layer>` does for a
            SNAP EtherType.

        """
        file_ = self._get_payload()
        if length is None:
            length = len(file_)
        arphrd_type = int(self.__header__.arphrd_type)  # type: ignore[attr-defined]

        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'
        empty = self._empty_next_layer(file_, length)
        if empty is not None:
            protocol = empty
        elif self._sigterm:
            from pcapkit.protocols.misc.raw.protocol import \
                Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif arphrd_type in self.__proto__:
            protocol = self._lookup_next_layer(self.__proto__, arphrd_type)
        else:
            protocol = self._lookup_next_layer(Link.__proto__, proto)

        return self._parse_next_layer(protocol, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)

    @staticmethod
    def _member_of_version(version: 'Any') -> 'Type[LinuxSLL]':
        """The member a ``version`` of ``1`` or ``2`` names.

        Args:
            version: Version of the header.

        Returns:
            :class:`~pcapkit.protocols.link.linux_sll1.protocol.LinuxSLL1` or
            :class:`~pcapkit.protocols.link.linux_sll2.protocol.LinuxSLL2`.

        Raises:
            ProtocolError: If ``version`` is neither, or is no :obj:`int`: a
                :obj:`bool` or a :obj:`float` is refused even where it equals one.

        """
        if isinstance(version, int) and not isinstance(version, bool):
            if version == 1:
                return cast('Type[LinuxSLL]', _LINUX_SLL1.klass)
            if version == 2:
                return cast('Type[LinuxSLL]', _LINUX_SLL2.klass)
        raise ProtocolError(f'LinuxSLL: invalid version: {version!r}')

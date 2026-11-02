# -*- coding: utf-8 -*-
"""LINUX_SLL - Linux "Cooked" Capture Encapsulation Family
==============================================================

.. module:: pcapkit.protocols.link.linux_sll

:mod:`pcapkit.protocols.link.linux_sll` contains
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` only, the base class of
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1` and
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`.

"""
import collections
from typing import TYPE_CHECKING, Generic

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
    from typing import Any, ClassVar, DefaultDict, NoReturn, Optional, Type

    from typing_extensions import Literal

    from pcapkit.corekit.enum import EnumRegistry
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['LinuxSLL']

#: Resolves ``protocol_type`` exactly as
#: :class:`~pcapkit.protocols.schema.link.ethernet.Ethernet` resolves its ``type``.
_ETHERTYPE_FIELD = EnumField(length=2, namespace=Enum_EtherType)


def _resolve_next_layer_proto(registry: 'DefaultDict[int, Any]', arphrd_type: 'int',
                              protocol_type: 'int') -> 'Enum_EtherType | int':
    """Resolve the next-layer dispatch key of either version.

    Args:
        registry: The ``arphrd_type`` registry, i.e. :attr:`LinuxSLL.__proto__
            <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`.
        arphrd_type: ARP hardware type of the interface the packet was seen on.
        protocol_type: Protocol (internet layer), as parsed off the wire.

    Returns:
        ``protocol_type`` itself if ``arphrd_type`` is a key of ``registry``;
        otherwise the value :class:`~pcapkit.protocols.link.ethernet.Ethernet`
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
    <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>` attribute, keyed by
    ``arphrd_type``:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.FRAD`
         - :class:`pcapkit.protocols.link.frad.FRAD`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IPGRE`
         - :class:`pcapkit.protocols.link.gre.GRE`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IEEE80211_RADIOTAP`
         - :class:`pcapkit.protocols.link.radiotap.Radiotap`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.IP6GRE`
         - :class:`pcapkit.protocols.link.gre.GRE`
       * - :attr:`~pcapkit.const.linux.arphrd.ARPHRD.NETLINK`
         - :class:`pcapkit.protocols.link.netlink.Netlink`

    Every other ``arphrd_type`` reads ``protocol_type`` as an EtherType and
    dispatches it through :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>`, as an Ethernet frame does.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Protocol index mapping for decoding next layer, keyed by the
    #: ``arphrd_type`` values whose ``protocol_type`` is not an EtherType, per
    #: tcpdump.org's LINUX_SLL and LINUX_SLL2 pages.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_ARPHRD.FRAD:               ModuleDescriptor('pcapkit.protocols.link.frad',     'FRAD'),
            Enum_ARPHRD.IPGRE:              ModuleDescriptor('pcapkit.protocols.link.gre',      'GRE'),
            Enum_ARPHRD.IEEE80211_RADIOTAP: ModuleDescriptor('pcapkit.protocols.link.radiotap', 'Radiotap'),
            Enum_ARPHRD.IP6GRE:             ModuleDescriptor('pcapkit.protocols.link.gre',      'GRE'),
            Enum_ARPHRD.NETLINK:            ModuleDescriptor('pcapkit.protocols.link.netlink',  'Netlink'),
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
            keeps the payload :class:`~pcapkit.protocols.misc.raw.Raw`, and a
            :class:`~pcapkit.protocols.misc.raw.Raw` records ``proto`` either way.

        Note:
            :attr:`self.__proto__ <LinuxSLL.__proto__>` holds the
            ``arphrd_type`` keys, so the EtherType path names
            :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`
            itself rather than reaching it through ``super()``, as
            :meth:`FRAD._import_next_layer
            <pcapkit.protocols.link.frad.FRAD._import_next_layer>` does for a
            SNAP EtherType.

        """
        file_ = self._get_payload()
        if length is None:
            length = len(file_)
        arphrd_type = int(self.__header__.arphrd_type)  # type: ignore[attr-defined]

        if TYPE_CHECKING:
            protocol: 'Type[ProtocolBase]'
        if not min(length, len(file_)):
            from pcapkit.protocols.misc.null import \
                NoPayload as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif self._sigterm:
            from pcapkit.protocols.misc.raw import \
                Raw as protocol  # isort: skip # pylint: disable=import-outside-toplevel
        elif arphrd_type in self.__proto__:
            protocol = self._lookup_next_layer(self.__proto__, arphrd_type)
        else:
            protocol = self._lookup_next_layer(Link.__proto__, proto)

        return self._parse_next_layer(protocol, file_, length, alias=proto, packet=packet,
                                      layer=self._exlayer, protocol=self._exproto,
                                      __context__=self._exctx)

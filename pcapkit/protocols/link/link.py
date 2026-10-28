# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Base Protocol
===================

.. module:: pcapkit.protocols.link.link

:mod:`pcapkit.protocols.link.link` contains
:class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g.
:class:`~pcapkit.protocols.link.arp.ARP`/:class:`~pcapkit.protocols.link.arp.InARP`,
:class:`~pcapkit.protocols.link.ethernet.Ethernet`,
:class:`~pcapkit.protocols.link.l2tp.L2TP`,
:class:`~pcapkit.protocols.link.loopback.Loopback` and
:class:`~pcapkit.protocols.link.vlan.VLAN`.

"""
import collections
from typing import TYPE_CHECKING, Generic

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.protocols.schema.schema import keep_short_read, replay_short_read
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import IO, Any, ClassVar, DefaultDict, Optional, Type

    from typing_extensions import Literal, Self

    from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Link']


class Link(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for link layer protocol family.

    This class supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Address_Resolution_Protocol`
         - :class:`pcapkit.protocols.link.arp.ARP`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Reverse_Address_Resolution_Protocol`
         - :class:`pcapkit.protocols.application.rarp.RARP`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Customer_VLAN_Tag_Type`
         - :class:`pcapkit.protocols.link.c_tag.C_Tag`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier`
         - :class:`pcapkit.protocols.link.s_tag.S_Tag`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Internet_Protocol_version_4`
         - :class:`pcapkit.protocols.internet.ipv4.IPv4`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Internet_Protocol_version_6`
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`
       * - 0x8137
         - :class:`pcapkit.protocols.internet.ipx.IPX`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: Layer of protocol.
    __layer__ = 'Link'  # type: Literal['Link']

    #: Protocol index mapping for decoding next layer, see
    #: :meth:`self._decode_next_layer
    #: <pcapkit.protocols.protocol.Protocol._decode_next_layer>` &
    #: :meth:`self._import_next_layer
    #: <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_EtherType.Address_Resolution_Protocol:         ModuleDescriptor('pcapkit.protocols.link.arp',      'ARP'),
            Enum_EtherType.Reverse_Address_Resolution_Protocol:
                ModuleDescriptor('pcapkit.protocols.application.rarp', 'RARP'),
            # The 802.1Q customer tag and the 802.1ad service tag. Q-in-Q stacks
            # them -- the service tag's own next-EtherType is what selects the
            # customer tag -- so the two coexist in one frame rather than
            # competing. They are separate classes only to keep their
            # ``info_name`` apart in the parsed output; the tag layout itself is
            # identical, and both share the code in
            # :class:`~pcapkit.protocols.link.vlan.VLAN`.
            Enum_EtherType.Customer_VLAN_Tag_Type:
                ModuleDescriptor('pcapkit.protocols.link.c_tag', 'C_Tag'),
            Enum_EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier:
                ModuleDescriptor('pcapkit.protocols.link.s_tag', 'S_Tag'),

            Enum_EtherType.Internet_Protocol_version_4:         ModuleDescriptor('pcapkit.protocols.internet.ipv4', 'IPv4'),
            Enum_EtherType.Internet_Protocol_version_6:         ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),

            # see https://en.wikipedia.org/wiki/EtherType#Values
            0x8137:                                             ModuleDescriptor('pcapkit.protocols.internet.ipx',  'IPX'),
        },
    )  # type: DefaultDict[int | Enum_EtherType, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    #: What :attr:`__proto__` is keyed by: the enum a key must be a member of,
    #: and whether a bare :class:`int` is a valid key there too. Declared by the
    #: class *owning* the registry, and read from it by
    #: :func:`~pcapkit.foundation.registry.protocols.register_protocol_code` so a
    #: ``code=`` key is checked exactly as
    #: :func:`~pcapkit.foundation.registry.protocols.register_ethertype` checks
    #: its own -- :class:`~pcapkit.protocols.link.ethernet.Ethernet`, which shares
    #: this registry, is therefore checked as :class:`Link` is, while
    #: :class:`~pcapkit.protocols.link.loopback.Loopback`, which keeps one of its
    #: own, declares its own pairing or none at all (:issue:`2268`).
    __proto_key__: 'ClassVar[tuple[Type[EnumRegistry], bool]]' = (Enum_EtherType, False)

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self) -> 'Literal["Link"]':
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def register(cls, code: 'Enum_EtherType', protocol: 'ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The fully qualified class name of the new protocol class
            should be ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                class, or not a :class:`~pcapkit.protocols.protocol.ProtocolBase` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this EtherType is
                already registered, naming the displaced entry and its
                replacement so a caller can tell *what* was lost. Fires only
                when the incumbent differs from the replacement -- see
                :meth:`Protocol.register
                <pcapkit.protocols.protocol.Protocol.register>` for the
                guard this shares with ``register_protocol``, and for the
                shipped descriptor that a restore puts back (:issue:`1504`).

        .. versionchanged:: 1.3.0

           Takes the protocol as one ``protocol`` argument, a
           :class:`~pcapkit.corekit.module.ModuleDescriptor` or a
           :class:`~pcapkit.protocols.protocol.Protocol` subclass, in place of
           the ``module`` and ``class_`` names.

        """
        incumbent = cls.__proto__.get(code)
        entry = cls._next_layer_entry(code, protocol)
        if entry is None:
            return
        if incumbent is not None and incumbent is not entry:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {entry!r}', RegistryWarning)
        cls.__proto__[code] = entry

    @classmethod
    def from_data(cls, data: '_PT | dict[str, Any]', **kwargs: 'Any') -> 'Self':
        """Create protocol instance from data.

        Args:
            data: Protocol data.
            **kwargs: Construction keywords, as for :meth:`Protocol.from_data
                <pcapkit.protocols.protocol.Protocol.from_data>`.

        Returns:
            Protocol instance, cut back to what was captured when the header
            it was parsed from was cut short (:issue:`1458`).

        """
        return replay_short_read(super().from_data(data, **kwargs), data)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __post_init__(self, file: 'Optional[IO[bytes] | bytes]' = None,
                      length: 'Optional[int]' = None, **kwargs: 'Any') -> 'None':
        """Post initialisation hook.

        Args:
            file: Source packet stream.
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Notes:
            A header the data ends inside keeps that in its
            :attr:`~pcapkit.protocols.protocol.Protocol.info`, so that
            :meth:`from_data` rebuilds only what was captured (:issue:`1458`).

        """
        super().__post_init__(file, length, **kwargs)  # type: ignore[arg-type]
        keep_short_read(self)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: int) -> 'Enum_EtherType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            EtherType enumeration of the next layer protocol.

        """
        _byte = self._read_unpack(size)
        _prot = Enum_EtherType.get(_byte)
        return _prot

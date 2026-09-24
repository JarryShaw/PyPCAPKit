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
:class:`~pcapkit.protocols.link.ospf.OSPF`,
:class:`~pcapkit.protocols.link.rarp.RARP`/:class:`~pcapkit.protocols.link.rarp.DRARP`
and etc.

"""
import collections
from typing import TYPE_CHECKING, Generic

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.protocol import _PT, _ST, ProtocolBase
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import DefaultDict, Type

    from typing_extensions import Literal

__all__ = ['Link']


class Link(ProtocolBase[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
    """Abstract base class for link layer protocol family.

    This class currently supports parsing of the following protocols, which are
    registered in the :attr:`self.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Address_Resolution_Protocol`
         - :class:`pcapkit.protocols.link.arp.ARP`
       * - :attr:`~pcapkit.const.reg.ethertype.EtherType.Reverse_Address_Resolution_Protocol`
         - :class:`pcapkit.protocols.link.rarp.RARP`
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

    #: DefaultDict[int, ModuleDescriptor[ProtocolBase] | ~typing.Type[ProtocolBase]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_EtherType.Address_Resolution_Protocol:         ModuleDescriptor('pcapkit.protocols.link.arp',      'ARP'),
            Enum_EtherType.Reverse_Address_Resolution_Protocol: ModuleDescriptor('pcapkit.protocols.link.rarp',     'RARP'),
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

            # c.f., https://en.wikipedia.org/wiki/EtherType#Values
            0x8137:                                             ModuleDescriptor('pcapkit.protocols.internet.ipx',  'IPX'),
        },
    )  # type: DefaultDict[int | Enum_EtherType, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

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
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        Raises:
            pcapkit.utilities.exceptions.RegistryError: If ``protocol`` is not a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass.

        Warns:
            pcapkit.utilities.warnings.RegistryWarning: If this EtherType is
                already registered, naming the displaced entry and its
                replacement so a caller can tell *what* was lost. Fires only
                when the incumbent differs from the replacement -- see
                :meth:`ProtocolBase.register
                <pcapkit.protocols.protocol.ProtocolBase.register>` for the
                guard this shares with ``register_protocol``.

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, ProtocolBase):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        incumbent = cls.__proto__.get(code)
        if incumbent is not None and incumbent is not protocol:
            warn(f'protocol {code} already registered, overwriting '
                 f'{incumbent!r} with {protocol!r}', RegistryWarning)
        cls.__proto__[code] = protocol

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: int) -> 'Enum_EtherType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            Internet layer protocol enumeration.

        """
        _byte = self._read_unpack(size)
        _prot = Enum_EtherType.get(_byte)
        return _prot

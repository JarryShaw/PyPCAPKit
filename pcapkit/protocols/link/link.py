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
from pcapkit.protocols.protocol import _PT, _ST
from pcapkit.protocols.protocol import ProtocolBase as Protocol
from pcapkit.utilities.exceptions import RegistryError
from pcapkit.utilities.warnings import RegistryWarning, warn

if TYPE_CHECKING:
    from typing import DefaultDict, Type

    from typing_extensions import Literal

__all__ = ['Link']


class Link(Protocol[_PT, _ST], Generic[_PT, _ST]):  # pylint: disable=abstract-method
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
         - :class:`pcapkit.protocols.link.vlan.VLAN`
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

    #: DefaultDict[int, ModuleDescriptor[Protocol] | Type[Protocol]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            Enum_EtherType.Address_Resolution_Protocol:         ModuleDescriptor('pcapkit.protocols.link.arp',      'ARP'),
            Enum_EtherType.Reverse_Address_Resolution_Protocol: ModuleDescriptor('pcapkit.protocols.link.rarp',     'RARP'),
            Enum_EtherType.Customer_VLAN_Tag_Type:              ModuleDescriptor('pcapkit.protocols.link.vlan',     'VLAN'),
            Enum_EtherType.Internet_Protocol_version_4:         ModuleDescriptor('pcapkit.protocols.internet.ipv4', 'IPv4'),
            Enum_EtherType.Internet_Protocol_version_6:         ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),

            # c.f., https://en.wikipedia.org/wiki/EtherType#Values
            0x8137:                                             ModuleDescriptor('pcapkit.protocols.internet.ipx',  'IPX'),
        },
    )  # type: DefaultDict[int | Enum_EtherType, ModuleDescriptor[Protocol] | Type[Protocol]]

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
    def register(cls, code: 'Enum_EtherType', protocol: 'ModuleDescriptor[Protocol] | Type[Protocol]') -> 'None':  # type: ignore[override]
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{protocol.module}.{protocol.name}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
            protocol: module descriptor or a
                :class:`~pcapkit.protocols.protocol.Protocol` subclass

        """
        if isinstance(protocol, ModuleDescriptor):
            protocol = protocol.klass
        if not issubclass(protocol, Protocol):
            raise RegistryError(f'protocol must be a Protocol subclass, not {protocol!r}')
        if code in cls.__proto__:
            warn(f'protocol {code} already registered, overwriting', RegistryWarning)
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

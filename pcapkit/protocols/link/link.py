# -*- coding: utf-8 -*-
"""Base Protocol
===================

:mod:`pcapkit.protocols.link.link` contains :class:`~pcapkit.protocols.link.link.Link`,
which is a base class for link layer protocols, e.g. :class:`~pcapkit.protocols.link.link.arp.ARP`/InARP,
:class:`~pcapkit.protocols.link.link.ethernet.Ethernet`, :class:`~pcapkit.protocols.link.link.l2tp.L2TP`,
:class:`~pcapkit.protocols.link.link.ospf.OSPF`, :class:`~pcapkit.protocols.link.link.rarp.RARP`/DRARP and etc.

"""
import collections
from typing import TYPE_CHECKING, Generic

from pcapkit.const.reg.ethertype import EtherType as RegType_EtherType
from pcapkit.protocols.protocol import PT, Protocol

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['Link']


class Link(Protocol[PT], Generic[PT]):  # pylint: disable=abstract-method
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

    #: DefaultDict[int, tuple[str, str]]: Protocol index mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    __proto__ = collections.defaultdict(
        lambda: ('pcapkit.protocols.misc.raw', 'Raw'),
        {
            RegType_EtherType.Address_Resolution_Protocol:         ('pcapkit.protocols.link.arp',      'ARP'),
            RegType_EtherType.Reverse_Address_Resolution_Protocol: ('pcapkit.protocols.link.rarp',     'RARP'),
            RegType_EtherType.Customer_VLAN_Tag_Type:              ('pcapkit.protocols.link.vlan',     'VLAN'),
            RegType_EtherType.Internet_Protocol_version_4:         ('pcapkit.protocols.internet.ipv4', 'IPv4'),
            RegType_EtherType.Internet_Protocol_version_6:         ('pcapkit.protocols.internet.ipv6', 'IPv6'),

            # c.f., https://en.wikipedia.org/wiki/EtherType#Values
            0x8137: ('pcapkit.protocols.internet.ipx',  'IPX'),
        },
    )

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
    def register(cls, code: 'RegType_EtherType', module: str, class_: str) -> 'None':
        r"""Register a new protocol class.

        Notes:
            The full qualified class name of the new protocol class
            should be as ``{module}.{class_}``.

        Arguments:
            code: protocol code as in :class:`~pcapkit.const.reg.ethertype.EtherType`
            module: module name
            class\_: class name

        """
        cls.__proto__[code] = (module, class_)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_protos(self, size: int) -> 'RegType_EtherType':
        """Read next layer protocol type.

        Arguments:
            size: buffer size

        Returns:
            Internet layer protocol enumeration.

        """
        _byte = self._read_unpack(size)
        _prot = RegType_EtherType.get(_byte)
        return _prot

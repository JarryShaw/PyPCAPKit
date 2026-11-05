# -*- coding: utf-8 -*-
# pylint: disable=unused-import,fixme
"""Link Layer Protocols
==========================

.. module:: pcapkit.protocols.link

:mod:`pcapkit.protocols.link` collects the link layer protocols.

Each protocol class, and the base class :class:`~pcapkit.protocols.link.link.Link`,
is imported the first time it is reached rather than with this package, through
:func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
# TODO: Implement DSL, EAPOL, FDDI, ISDN, NDP, PPP.

from typing import TYPE_CHECKING

# Link-Layer Header Type Values
from pcapkit.const.reg.linktype import LinkType as LINKTYPE
from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # Base Class for Link Layer
    from pcapkit.protocols.link.link import Link

    # Link Layer Protocols
    from pcapkit.protocols.link.arp import ARP
    from pcapkit.protocols.link.inarp import InARP
    from pcapkit.protocols.link.ethernet import Ethernet
    from pcapkit.protocols.link.frad import FRAD
    from pcapkit.protocols.link.gre import GRE
    from pcapkit.protocols.link.ieee802_11 import IEEE802_11
    from pcapkit.protocols.link.loopback import Loopback
    from pcapkit.protocols.link.netlink import Netlink
    from pcapkit.protocols.link.radiotap import Radiotap

    # Linux "Cooked" Capture Encapsulation Family
    from pcapkit.protocols.link.linux_sll import LinuxSLL
    from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
    from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

    # VLAN Tag Family
    from pcapkit.protocols.link.vlan import VLAN
    from pcapkit.protocols.link.c_tag import C_Tag
    from pcapkit.protocols.link.s_tag import S_Tag

    # L2TP Family
    from pcapkit.protocols.link.l2tp import L2TP
    from pcapkit.protocols.link.l2tpv2 import L2TPv2

__all__ = [
    # Protocol Numbers
    'LINKTYPE',

    # Link Layer Protocols
    'ARP', 'C_Tag', 'Ethernet', 'FRAD', 'GRE', 'IEEE802_11', 'InARP', 'L2TP', 'L2TPv2',
    'LinuxSLL', 'LinuxSLL1', 'LinuxSLL2', 'Loopback', 'Netlink', 'Radiotap', 'S_Tag', 'VLAN',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Link': ('link', 'Link'),
    'ARP': ('arp', 'ARP'),
    'C_Tag': ('c_tag', 'C_Tag'),
    'Ethernet': ('ethernet', 'Ethernet'),
    'FRAD': ('frad', 'FRAD'),
    'GRE': ('gre', 'GRE'),
    'IEEE802_11': ('ieee802_11', 'IEEE802_11'),
    'InARP': ('inarp', 'InARP'),
    'L2TP': ('l2tp', 'L2TP'),
    'L2TPv2': ('l2tpv2', 'L2TPv2'),
    'LinuxSLL': ('linux_sll', 'LinuxSLL'),
    'LinuxSLL1': ('linux_sll1', 'LinuxSLL1'),
    'LinuxSLL2': ('linux_sll2', 'LinuxSLL2'),
    'Loopback': ('loopback', 'Loopback'),
    'Netlink': ('netlink', 'Netlink'),
    'Radiotap': ('radiotap', 'Radiotap'),
    'S_Tag': ('s_tag', 'S_Tag'),
    'VLAN': ('vlan', 'VLAN'),
})

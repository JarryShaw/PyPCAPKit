# -*- coding: utf-8 -*-
"""Linux ARP Hardware Types
==============================

.. module:: pcapkit.const.linux.arphrd

This module contains the constant enumeration for the Linux ``ARPHRD_*``
hardware types of ``<linux/if_arp.h>``, the ``arphrd_type`` of the Linux
"cooked" capture encapsulations. Only the values that pcapkit names are listed.
The rest of the numbering is IANA's, see
:class:`~pcapkit.const.arp.hardware.Hardware`, which differs for most
non-Ethernet types.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumLookup

__all__ = ['ARPHRD']


class ARPHRD(EnumLookup, IntEnum):
    """[ARPHRD] Linux ARP hardware types [``<linux/if_arp.h>``]"""

    #: Frame Relay Access Device
    FRAD = 770

    #: GRE over IP
    IPGRE = 778

    #: IEEE 802.11 with radiotap header
    IEEE80211_RADIOTAP = 803

    #: GRE over IPv6
    IP6GRE = 823

    #: Kernel Netlink socket
    NETLINK = 824

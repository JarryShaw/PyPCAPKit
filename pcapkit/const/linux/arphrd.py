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

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ARPHRD']


class ARPHRD(EnumRegistry, IntEnum):
    """[ARPHRD] Linux ARP hardware types [``<linux/if_arp.h>``]"""

    #: NET/ROM pseudo.
    NETROM = 0

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

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it is an ``arphrd_type`` (a 16-bit value).

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        so that :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses
        the values :meth:`_missing_` refuses.

        Raises:
            EnumValueError: If ``value`` is not an integer in ``0..0xFFFF``.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ARPHRD':
        """Resolve an unnamed ``arphrd_type`` to an unregistered member.

        Args:
            value: Value to get enum item.

        Raises:
            ValueError: If ``value`` is not a 16-bit integer.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

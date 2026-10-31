# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Linux ARP hardware types
==============================

.. module:: pcapkit.const.linux.arphrd

This module contains the constant enumeration for **Linux ARP hardware types**,
which is automatically generated from :class:`pcapkit.vendor.linux.arphrd.ARPHRD`.

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
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ARPHRD':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')

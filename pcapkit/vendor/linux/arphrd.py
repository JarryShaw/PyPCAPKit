# -*- coding: utf-8 -*-
"""Linux ARP Hardware Types
==============================

.. module:: pcapkit.vendor.linux.arphrd

This module contains the vendor crawler for **Linux ARP Hardware Types**,
which is automatically generating :class:`pcapkit.const.linux.arphrd.ARPHRD`.

"""

import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.vendor.default import Vendor

if TYPE_CHECKING:
    from collections import Counter

__all__ = ['ARPHRD']

###############################################################################
# NOTE: this crawler does not crawl. Its source is the Linux kernel header
# ``<linux/if_arp.h>``, which assigns ``ARPHRD_*`` values in C source under the
# kernel's own versioning, not an IANA or IETF table :mod:`pcapkit.vendor` could
# scrape. Per the const-vendor-pairing convention, a hand-maintained registry
# still gets a crawler, reading :data:`~pcapkit.vendor.linux.arphrd.DATA`
# instead of fetching a URL -- the same shape as
# :mod:`pcapkit.vendor.ipx.packet` and :mod:`pcapkit.vendor.ipx.socket`.
#
# pcapkit names only the ``ARPHRD_*`` values its Linux "cooked" capture
# dissector (:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`) actually
# matches on, not every value the header defines. The rest of the ARP
# hardware-type numbering is IANA's own
# (:class:`~pcapkit.const.arp.hardware.Hardware`), which differs for most
# non-Ethernet types.
###############################################################################

#: ARPHRD hardware-type registry, transcribed from ``<linux/if_arp.h>`` for the
#: values pcapkit's Linux "cooked" capture dissector names.
#:
#: Maps an ``arphrd_type`` to the enumeration name it takes and the comment
#: rendered above it. Names go through :meth:`~Vendor.rename`, so the generated
#: member is the :meth:`~Vendor.safe_name` of the first element.
DATA = {
    0: ('NETROM', 'NET/ROM pseudo.'),
    770: ('FRAD', 'Frame Relay Access Device'),
    778: ('IPGRE', 'GRE over IP'),
    803: ('IEEE80211_RADIOTAP', 'IEEE 802.11 with radiotap header'),
    823: ('IP6GRE', 'GRE over IPv6'),
    824: ('NETLINK', 'Kernel Netlink socket'),
}  # type: dict[int, tuple[str, str]]


class ARPHRD(Vendor):
    """Linux ARP hardware types [``<linux/if_arp.h>``]"""

    #: Value limit checker.
    FLAG = 'isinstance(value, int) and 0x0000 <= value <= 0xFFFF'

    #: Destination of a bare ``ARPHRD`` member; see
    #: :attr:`~pcapkit.vendor.default.Vendor.PROTO_DEST`.
    PROTO_DEST = (ModuleDescriptor('pcapkit.protocols.link.linux_sll', 'LinuxSLL'),)

    def request(self) -> 'dict[int, tuple[str, str]]':  # type: ignore[override] # pylint: disable=arguments-differ
        """Fetch registry data.

        Returns:
            Registry data (:data:`~pcapkit.vendor.linux.arphrd.DATA`).

        """
        return DATA

    def count(self, data: 'dict[int, tuple[str, str]]') -> 'Counter[str]':  # type: ignore[override]
        """Count field records.

        Args:
            data: Registry data.

        Returns:
            Field recordings.

        """
        return collections.Counter(self.safe_name(name) for name, _ in data.values())

    def process(self, data: 'dict[int, tuple[str, str]]') -> 'tuple[list[str], list[str]]':  # type: ignore[override]
        """Process registry data.

        Args:
            data: Registry data.

        Returns:
            Enumeration fields and missing fields.

        """
        enum = []  # type: list[str]
        miss = [
            "return cls._unregistered_member(value, 'Unassigned')",
        ]

        for code, (name, desc) in data.items():
            pval = str(code)
            renm = self.rename(name, pval)

            enum.append(f'#: {self.wrap_comment(desc)}\n    {renm} = {pval}')
        return enum, miss


if __name__ == '__main__':
    sys.exit(ARPHRD())  # type: ignore[arg-type]

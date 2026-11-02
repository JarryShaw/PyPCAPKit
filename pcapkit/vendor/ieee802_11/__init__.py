# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` Vendor Crawlers
============================================================================

.. module:: pcapkit.vendor.ieee802_11

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.ieee802_11.IEEE802_11` implementations.
Available vendor crawlers include:

.. list-table::

   * - :class:`IEEE802_11_Type <pcapkit.vendor.ieee802_11.type.Type>`
     - Frame Types
   * - :class:`IEEE802_11_ManagementSubtype <pcapkit.vendor.ieee802_11.management_subtype.ManagementSubtype>`
     - Management Frame Subtypes
   * - :class:`IEEE802_11_ControlSubtype <pcapkit.vendor.ieee802_11.control_subtype.ControlSubtype>`
     - Control Frame Subtypes
   * - :class:`IEEE802_11_DataSubtype <pcapkit.vendor.ieee802_11.data_subtype.DataSubtype>`
     - Data Frame Subtypes
   * - :class:`IEEE802_11_ExtensionSubtype <pcapkit.vendor.ieee802_11.extension_subtype.ExtensionSubtype>`
     - Extension Frame Subtypes

None of these crawlers crawls. IEEE Std 802.11-2020 assigns the frame type
and subtype values in Table 9-1, *Valid type and subtype combinations*, of the
standard's text, and neither IEEE nor IANA publishes them as a
machine-readable registry. So each crawler reads a ``DATA`` literal instead of
fetching a URL, the shape :mod:`pcapkit.vendor.linux.arphrd` takes
(:ref:`const-vendor-pairing`).

Each ``DATA`` is transcribed row for row from the table on Wikipedia's
*802.11 frame types* page [*]_, revision 1369762968, which reproduces Table 9-1
with the Trigger frame of IEEE Std 802.11ax-2021 and cites both. Its spelling
is kept as written, less the footnote marker after ``Trigger``. The values
agree with the Linux kernel's ``include/linux/ieee80211.h`` for every subtype
both name.

.. [*] https://en.wikipedia.org/w/index.php?title=802.11_frame_types&oldid=1369762968

"""

from pcapkit.vendor.ieee802_11.control_subtype import ControlSubtype as IEEE802_11_ControlSubtype
from pcapkit.vendor.ieee802_11.data_subtype import DataSubtype as IEEE802_11_DataSubtype
from pcapkit.vendor.ieee802_11.extension_subtype import \
    ExtensionSubtype as IEEE802_11_ExtensionSubtype
from pcapkit.vendor.ieee802_11.management_subtype import \
    ManagementSubtype as IEEE802_11_ManagementSubtype
from pcapkit.vendor.ieee802_11.type import Type as IEEE802_11_Type

__all__ = [
    'IEEE802_11_Type', 'IEEE802_11_ManagementSubtype', 'IEEE802_11_ControlSubtype',
    'IEEE802_11_DataSubtype', 'IEEE802_11_ExtensionSubtype',
]

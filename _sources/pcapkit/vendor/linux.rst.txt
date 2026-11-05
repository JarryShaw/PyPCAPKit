===================================================================
Linux-Specific Vendor Crawlers
===================================================================

.. module:: pcapkit.vendor.linux

For Linux-specific encapsulations, such as
:class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`.

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.vendor.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types [*]_

.. versionadded:: 1.6.0

ARP Hardware Types
==================

.. module:: pcapkit.vendor.linux.arphrd

Generates :class:`pcapkit.const.linux.arphrd.ARPHRD`.

.. note::

   This crawler does not crawl. Its source is the Linux kernel header
   ``<linux/if_arp.h>``, which assigns ``ARPHRD_*`` values in C source rather
   than in a table to scrape, so the data is maintained by hand in the ``DATA``
   mapping of :mod:`pcapkit.vendor.linux.arphrd`, and the class defines no
   ``LINK``.

.. autoclass:: pcapkit.vendor.linux.arphrd.ARPHRD
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h

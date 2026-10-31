===================================================================
Linux-Specific Vendor Crawlers
===================================================================

.. module:: pcapkit.vendor.linux

This module contains all vendor crawlers of the Linux-specific
encapsulations, e.g. :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`.
Available vendor crawlers include:

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.vendor.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types [*]_

ARP Hardware Types
==================

.. module:: pcapkit.vendor.linux.arphrd

This module contains the vendor crawler for **Linux ARP Hardware Types**,
which is automatically generating :class:`pcapkit.const.linux.arphrd.ARPHRD`.

.. note::

   This crawler does not crawl. Its source is the Linux kernel header
   ``<linux/if_arp.h>``, which assigns ``ARPHRD_*`` values in C source
   under the kernel's own versioning, not an IANA or IETF table that
   :mod:`pcapkit.vendor` could scrape. The data is maintained by hand in
   the ``DATA`` mapping of :mod:`pcapkit.vendor.linux.arphrd`, and the
   class defines no ``LINK``.

.. autoclass:: pcapkit.vendor.linux.arphrd.ARPHRD
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h

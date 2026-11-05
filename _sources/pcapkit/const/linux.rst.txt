====================================
Linux-Specific Constant Enumerations
====================================

.. module:: pcapkit.const.linux

For Linux-specific encapsulations, such as
:class:`~pcapkit.protocols.link.linux_sll.protocol.LinuxSLL`.

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.const.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types [*]_

.. versionadded:: 1.6.0

ARP Hardware Types
==================

.. module:: pcapkit.const.linux.arphrd

Generated from :class:`pcapkit.vendor.linux.arphrd.ARPHRD`.

.. autoclass:: pcapkit.const.linux.arphrd.ARPHRD
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __proto_dest__

.. rubric:: Footnotes

.. [*] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h

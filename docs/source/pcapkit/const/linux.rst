====================================
Linux-Specific Constant Enumerations
====================================

.. module:: pcapkit.const.linux

This module contains all constant enumerations of the Linux-specific
encapsulations, e.g. :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`.
Available enumerations include:

.. list-table::

   * - :class:`ARPHRD <pcapkit.const.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types [*]_

ARP Hardware Types
==================

.. module:: pcapkit.const.linux.arphrd

This module contains the constant enumeration for **Linux ARP Hardware Types**,
which is automatically generated from :class:`pcapkit.vendor.linux.arphrd.ARPHRD`.

.. autoclass:: pcapkit.const.linux.arphrd.ARPHRD
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __proto_dest__

.. rubric:: Footnotes

.. [*] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h

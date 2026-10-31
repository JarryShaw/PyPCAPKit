# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":mod:`pcapkit.const.linux` Vendor Crawlers
===============================================

.. module:: pcapkit.vendor.linux

This module contains all vendor crawlers of the Linux-specific encapsulations,
e.g. :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`. Available crawlers
include:

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.vendor.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types

"""

from pcapkit.vendor.linux.arphrd import ARPHRD as Linux_ARPHRD

__all__ = ['Linux_ARPHRD']

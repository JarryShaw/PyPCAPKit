# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":mod:`pcapkit.const.linux` Constant Enumerations
=====================================================

This module contains the constant enumerations of the Linux-specific
encapsulations, e.g. :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`.
Available enumerations include:

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.const.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types

"""

from pcapkit.const.linux.arphrd import ARPHRD as Linux_ARPHRD

__all__ = ['Linux_ARPHRD']

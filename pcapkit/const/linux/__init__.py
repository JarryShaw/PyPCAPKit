# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":mod:`pcapkit.const.linux` Constant Enumerations
======================================================

This module contains the constant enumerations of the Linux-specific
encapsulations, e.g. :class:`~pcapkit.protocols.link.linux_sll.LinuxSLL`.
Available enumerations include:

.. list-table::

   * - :class:`Linux_ARPHRD <pcapkit.const.linux.arphrd.ARPHRD>`
     - Linux ARP Hardware Types

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.lazy import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.linux.arphrd import ARPHRD as Linux_ARPHRD

__all__ = ['Linux_ARPHRD']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Linux_ARPHRD': ('arphrd', 'ARPHRD'),
})

# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.transport.tcp.TCP` Constant Enumerations
=========================================================================

.. module:: pcapkit.const.tcp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.transport.tcp.TCP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.const.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_MPTCPOption <pcapkit.const.tcp.mp_tcp_option.MPTCPOption>`
     - Multipath TCP options [*]_
   * - :class:`TCP_Option <pcapkit.const.tcp.option.Option>`
     - TCP Option Kind Numbers [*]_
   * - :class:`TCP_Flags <pcapkit.const.tcp.flags.Flags>`
     - TCP Header Flags [*]_

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#mptcp-option-subtypes
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-header-flags

"""

from pcapkit.const.tcp.checksum import Checksum as TCP_Checksum
from pcapkit.const.tcp.flags import Flags as TCP_Flags
from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as TCP_MPTCPOption
from pcapkit.const.tcp.option import Option as TCP_Option

__all__ = ['TCP_Checksum', 'TCP_Option', 'TCP_MPTCPOption', 'TCP_Flags']

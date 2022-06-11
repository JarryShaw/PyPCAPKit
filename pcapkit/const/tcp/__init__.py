# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.transport.tcp.TCP` Constant Enumerations
=========================================================================

This module contains all constant enumerations of
:class:`~pcapkit.protocols.transport.tcp.TCP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.const.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_Option <pcapkit.vendor.tcp.option.Option>`
     - TCP Option Kind Numbers [*]_

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1

"""

from pcapkit.const.tcp.checksum import Checksum as TCP_Checksum
from pcapkit.const.tcp.option import Option as TCP_Option

__all__ = ['TCP_Checksum', 'TCP_Option']

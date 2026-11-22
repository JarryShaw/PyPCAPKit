# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.ppp.protocol.PPP` Constant Enumerations
=============================================================================

.. module:: pcapkit.const.ppp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.ppp.protocol.PPP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`PPP_Protocol <pcapkit.const.ppp.protocol.Protocol>`
     - PPP DLL Protocol Numbers [*]_

.. [*] https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.ppp.protocol import Protocol as PPP_Protocol

__all__ = ['PPP_Protocol']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'PPP_Protocol': ('protocol', 'Protocol'),
})

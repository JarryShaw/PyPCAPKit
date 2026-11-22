# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` Constant Enumerations
=================================================================================

.. module:: pcapkit.const.pppoe

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE` implementations. Available
enumerations include:

.. list-table::

   * - :class:`PPPoE_Code <pcapkit.const.pppoe.code.Code>`
     - PPPoE Active Discovery Code Fields [*]_
   * - :class:`PPPoE_Tag <pcapkit.const.pppoe.tag.Tag>`
     - PPPoE TAG Values [*]_

.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-2
.. [*] https://www.iana.org/assignments/pppoe-parameters/pppoe-parameters.xhtml#pppoe-parameters-1

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.pppoe.code import Code as PPPoE_Code
    from pcapkit.const.pppoe.tag import Tag as PPPoE_Tag

__all__ = ['PPPoE_Code', 'PPPoE_Tag']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'PPPoE_Code': ('code', 'Code'),
    'PPPoE_Tag': ('tag', 'Tag'),
})

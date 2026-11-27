# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.llc.protocol.LLC` Constant Enumerations
=============================================================================

.. module:: pcapkit.const.llc

This module contains all constant enumerations of
:class:`~pcapkit.protocols.link.llc.protocol.LLC` implementations. Available
enumerations include:

.. list-table::

   * - :class:`LLC_LSAP <pcapkit.const.llc.lsap.LSAP>`
     - LLC Address (LSAP) Values [*]_
   * - :class:`LLC_SupervisoryFunction <pcapkit.const.llc.supervisory_function.SupervisoryFunction>`
     - LLC Supervisory Functions
   * - :class:`LLC_ModifierFunction <pcapkit.const.llc.modifier_function.ModifierFunction>`
     - LLC Modifier Functions

.. [*] https://web.archive.org/web/20180413024649/http://standards.ieee.org:80/develop/regauth/llc/public.html

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.llc.lsap import LSAP as LLC_LSAP
    from pcapkit.const.llc.modifier_function import ModifierFunction as LLC_ModifierFunction
    from pcapkit.const.llc.supervisory_function import \
        SupervisoryFunction as LLC_SupervisoryFunction

__all__ = ['LLC_LSAP', 'LLC_SupervisoryFunction', 'LLC_ModifierFunction']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'LLC_LSAP': ('lsap', 'LSAP'),
    'LLC_SupervisoryFunction': ('supervisory_function', 'SupervisoryFunction'),
    'LLC_ModifierFunction': ('modifier_function', 'ModifierFunction'),
})

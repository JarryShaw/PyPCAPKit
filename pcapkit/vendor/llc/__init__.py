# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.link.llc.protocol.LLC` Vendor Crawlers
=======================================================================

.. module:: pcapkit.vendor.llc

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.link.llc.protocol.LLC` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`LLC_LSAP <pcapkit.vendor.llc.lsap.LSAP>`
     - LLC Address (LSAP) Values [*]_
   * - :class:`LLC_SupervisoryFunction <pcapkit.vendor.llc.supervisory_function.SupervisoryFunction>`
     - LLC Supervisory Functions
   * - :class:`LLC_ModifierFunction <pcapkit.vendor.llc.modifier_function.ModifierFunction>`
     - LLC Modifier Functions

None of these crawlers crawls, so each reads a ``DATA`` literal instead of
fetching a URL, the shape :mod:`pcapkit.vendor.linux.arphrd` takes
(:ref:`const-vendor-pairing`). :data:`~pcapkit.vendor.llc.lsap.DATA` is
transcribed from the Internet Archive's copy of the IEEE Registration
Authority's *LLC Public Listing*, its two tables of individual and group
address values. The control field
functions are fixed by the text of IEEE Std 802.2, which no registry
publishes; their values agree with Wireshark's ``packet-xdlc.h``.

.. [*] https://web.archive.org/web/20180413024649/http://standards.ieee.org:80/develop/regauth/llc/public.html

"""

from pcapkit.vendor.llc.lsap import LSAP as LLC_LSAP
from pcapkit.vendor.llc.modifier_function import ModifierFunction as LLC_ModifierFunction
from pcapkit.vendor.llc.supervisory_function import SupervisoryFunction as LLC_SupervisoryFunction

__all__ = ['LLC_LSAP', 'LLC_SupervisoryFunction', 'LLC_ModifierFunction']

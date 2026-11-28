=====================================================================
:class:`~pcapkit.protocols.link.llc.protocol.LLC` Vendor Crawlers
=====================================================================

.. module:: pcapkit.vendor.llc

.. list-table::

   * - :class:`LLC_LSAP <pcapkit.vendor.llc.lsap.LSAP>`
     - LLC Address (LSAP) Values [*]_
   * - :class:`LLC_SupervisoryFunction <pcapkit.vendor.llc.supervisory_function.SupervisoryFunction>`
     - LLC Supervisory Functions
   * - :class:`LLC_ModifierFunction <pcapkit.vendor.llc.modifier_function.ModifierFunction>`
     - LLC Modifier Functions

.. note::

   These crawlers do not crawl, so each reads a ``DATA`` literal and defines
   no ``LINK`` (:ref:`const-vendor-pairing`). The LSAP values are transcribed
   from the Internet Archive's copy of the IEEE Registration Authority's *LLC
   Public Listing*. The control field functions are fixed by the text of
   IEEE Std 802.2, which no registry publishes; their values agree with
   Wireshark's ``packet-xdlc.h``.

.. versionadded:: 1.9.0

LLC Address (LSAP) Values
=========================

.. module:: pcapkit.vendor.llc.lsap

Generates :class:`pcapkit.const.llc.lsap.LSAP`.

.. autoclass:: pcapkit.vendor.llc.lsap.LSAP
   :members: FLAG, PROTO_DEST
   :show-inheritance:

LLC Supervisory Functions
=========================

.. module:: pcapkit.vendor.llc.supervisory_function

Generates :class:`pcapkit.const.llc.supervisory_function.SupervisoryFunction`.

.. autoclass:: pcapkit.vendor.llc.supervisory_function.SupervisoryFunction
   :members: FLAG
   :show-inheritance:

LLC Modifier Functions
======================

.. module:: pcapkit.vendor.llc.modifier_function

Generates :class:`pcapkit.const.llc.modifier_function.ModifierFunction`.

.. autoclass:: pcapkit.vendor.llc.modifier_function.ModifierFunction
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://web.archive.org/web/20180413024649/http://standards.ieee.org:80/develop/regauth/llc/public.html

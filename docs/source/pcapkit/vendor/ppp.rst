===========================================================================
:class:`~pcapkit.protocols.link.ppp.protocol.PPP` Vendor Crawlers
===========================================================================

.. module:: pcapkit.vendor.ppp

.. list-table::

   * - :class:`PPP_Protocol <pcapkit.vendor.ppp.protocol.Protocol>`
     - PPP DLL Protocol Numbers [*]_

PPP DLL Protocol Numbers
========================

.. module:: pcapkit.vendor.ppp.protocol

Generates :class:`pcapkit.const.ppp.protocol.Protocol`.

.. autoclass:: pcapkit.vendor.ppp.protocol.Protocol
   :members: FLAG, LINK, PROTO_DEST
   :show-inheritance:

.. autofunction:: pcapkit.vendor.ppp.protocol.hexlify

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2

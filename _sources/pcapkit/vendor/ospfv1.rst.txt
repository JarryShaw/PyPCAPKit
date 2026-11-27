==============================================================================
:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1` Vendor Crawlers
==============================================================================

.. module:: pcapkit.vendor.ospfv1

.. list-table::

   * - :class:`OSPFv1_Authentication <pcapkit.vendor.ospfv1.authentication.Authentication>`
     - OSPFv1 Authentication Types [*]_
   * - :class:`OSPFv1_Packet <pcapkit.vendor.ospfv1.packet.Packet>`
     - OSPFv1 Packet Types [*]_

.. versionadded:: 1.8.1

OSPFv1 Authentication Types
===========================

.. module:: pcapkit.vendor.ospfv1.authentication

Generates :class:`pcapkit.const.ospfv1.authentication.Authentication`.

.. note::

   This crawler does not crawl. Its source is :rfc:`1131`, published as PostScript
   alone, so the data is maintained by hand in the ``DATA`` mapping of
   :mod:`pcapkit.vendor.ospfv1.authentication`, and the class defines no ``LINK``.

.. autoclass:: pcapkit.vendor.ospfv1.authentication.Authentication
   :members: FLAG
   :show-inheritance:

OSPFv1 Packet Types
===================

.. module:: pcapkit.vendor.ospfv1.packet

Generates :class:`pcapkit.const.ospfv1.packet.Packet`.

.. note::

   This crawler does not crawl, for the same reason
   :class:`~pcapkit.vendor.ospfv1.authentication.Authentication` does: the data is
   maintained by hand in the ``DATA`` mapping of :mod:`pcapkit.vendor.ospfv1.packet`,
   and the class defines no ``LINK``.

.. autoclass:: pcapkit.vendor.ospfv1.packet.Packet
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://datatracker.ietf.org/doc/html/rfc1131
.. [*] https://datatracker.ietf.org/doc/html/rfc1131

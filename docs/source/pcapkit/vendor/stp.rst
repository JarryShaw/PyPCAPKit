==============================================================================
:class:`~pcapkit.protocols.application.stp.protocol.STP` Vendor Crawlers
==============================================================================

.. module:: pcapkit.vendor.stp

.. list-table::

   * - :class:`STP_ProtocolVersion <pcapkit.vendor.stp.protocol_version.ProtocolVersion>`
     - STP Protocol Version Identifiers
   * - :class:`STP_BPDUType <pcapkit.vendor.stp.bpdu_type.BPDUType>`
     - STP BPDU Types
   * - :class:`STP_PortRole <pcapkit.vendor.stp.port_role.PortRole>`
     - STP Port Roles

.. note::

   These crawlers do not crawl, so each reads a ``DATA`` literal and defines
   no ``LINK`` (:ref:`const-vendor-pairing`). The values are fixed by the text
   of :ieee:`802.1D-2004` clause 9 and :ieee:`802.1Q-2022` clause 14, which no
   registry publishes; they agree with Wireshark's ``packet-bpdu.c``, tcpdump's
   ``print-stp.c`` and mstpd's ``mstp.h``.

.. versionadded:: 1.9.0

STP Protocol Version Identifiers
================================

.. module:: pcapkit.vendor.stp.protocol_version

Generates :class:`pcapkit.const.stp.protocol_version.ProtocolVersion`.

.. autoclass:: pcapkit.vendor.stp.protocol_version.ProtocolVersion
   :members: FLAG
   :show-inheritance:

STP BPDU Types
==============

.. module:: pcapkit.vendor.stp.bpdu_type

Generates :class:`pcapkit.const.stp.bpdu_type.BPDUType`.

.. autoclass:: pcapkit.vendor.stp.bpdu_type.BPDUType
   :members: FLAG
   :show-inheritance:

STP Port Roles
==============

.. module:: pcapkit.vendor.stp.port_role

Generates :class:`pcapkit.const.stp.port_role.PortRole`.

.. autoclass:: pcapkit.vendor.stp.port_role.PortRole
   :members: FLAG
   :show-inheritance:

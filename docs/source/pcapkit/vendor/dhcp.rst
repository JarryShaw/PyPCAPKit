==========================================================================
:class:`~pcapkit.protocols.application.dhcp.protocol.DHCP` Vendor Crawlers
==========================================================================

.. module:: pcapkit.vendor.dhcp

.. list-table::

   * - :class:`DHCP_Opcode <pcapkit.vendor.dhcp.opcode.Opcode>`
     - BOOTP Message Op Codes
   * - :class:`DHCP_Option <pcapkit.vendor.dhcp.option.Option>`
     - BOOTP Vendor Extensions and DHCP Options
   * - :class:`DHCP_MessageType <pcapkit.vendor.dhcp.message_type.MessageType>`
     - DHCP Message Type 53 Values
   * - :class:`DHCP_RelayAgentSubOption <pcapkit.vendor.dhcp.relay_agent_suboption.RelayAgentSubOption>`
     - DHCP Relay Agent Sub-Option Codes

.. note::

   :class:`~pcapkit.vendor.dhcp.opcode.Opcode` does not crawl: it reads a ``DATA``
   literal and defines no ``LINK`` (:ref:`const-vendor-pairing`), since IANA
   publishes no registry for the two codes of :rfc:`951#section-3`.

.. versionadded:: 1.10.0

BOOTP Message Op Codes
======================

.. module:: pcapkit.vendor.dhcp.opcode

Generates :class:`pcapkit.const.dhcp.opcode.Opcode`.

.. autoclass:: pcapkit.vendor.dhcp.opcode.Opcode
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.dhcp.opcode.DATA
   :no-value:

BOOTP Vendor Extensions and DHCP Options
========================================

.. module:: pcapkit.vendor.dhcp.option

Generates :class:`pcapkit.const.dhcp.option.Option`.

.. autoclass:: pcapkit.vendor.dhcp.option.Option
   :members: FLAG, LINK
   :show-inheritance:

DHCP Message Type 53 Values
===========================

.. module:: pcapkit.vendor.dhcp.message_type

Generates :class:`pcapkit.const.dhcp.message_type.MessageType`.

.. autoclass:: pcapkit.vendor.dhcp.message_type.MessageType
   :members: FLAG, LINK
   :show-inheritance:

DHCP Relay Agent Sub-Option Codes
=================================

.. module:: pcapkit.vendor.dhcp.relay_agent_suboption

Generates :class:`pcapkit.const.dhcp.relay_agent_suboption.RelayAgentSubOption`.

.. autoclass:: pcapkit.vendor.dhcp.relay_agent_suboption.RelayAgentSubOption
   :members: FLAG, LINK
   :show-inheritance:

.. autodata:: pcapkit.vendor.dhcp.relay_agent_suboption.RESERVED
   :no-value:

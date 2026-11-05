========================================================================
:class:`~pcapkit.protocols.transport.dccp.protocol.DCCP` Vendor Crawlers
========================================================================

.. module:: pcapkit.vendor.dccp

.. list-table::

   * - :class:`DCCP_PacketType <pcapkit.vendor.dccp.packet_type.PacketType>`
     - DCCP Packet Types [*]_
   * - :class:`DCCP_ResetCode <pcapkit.vendor.dccp.reset_code.ResetCode>`
     - DCCP Reset Codes [*]_
   * - :class:`DCCP_Option <pcapkit.vendor.dccp.option.Option>`
     - DCCP Option Types [*]_
   * - :class:`DCCP_Feature <pcapkit.vendor.dccp.feature.Feature>`
     - DCCP Feature Numbers [*]_
   * - :class:`DCCP_AckVectorState <pcapkit.vendor.dccp.ack_vector_state.AckVectorState>`
     - DCCP Ack Vector States [*]_
   * - :class:`DCCP_DropCode <pcapkit.vendor.dccp.drop_code.DropCode>`
     - DCCP Drop Codes [*]_

.. versionadded:: 1.6.0

DCCP Packet Types
=================

.. module:: pcapkit.vendor.dccp.packet_type

Generates :class:`pcapkit.const.dccp.packet_type.PacketType`.

.. autoclass:: pcapkit.vendor.dccp.packet_type.PacketType
   :members: FLAG, LINK
   :show-inheritance:

DCCP Reset Codes
================

.. module:: pcapkit.vendor.dccp.reset_code

Generates :class:`pcapkit.const.dccp.reset_code.ResetCode`.

.. autoclass:: pcapkit.vendor.dccp.reset_code.ResetCode
   :members: FLAG, LINK
   :show-inheritance:

DCCP Option Types
=================

.. module:: pcapkit.vendor.dccp.option

Generates :class:`pcapkit.const.dccp.option.Option`.

.. autoclass:: pcapkit.vendor.dccp.option.Option
   :members: FLAG, LINK
   :show-inheritance:

DCCP Feature Numbers
====================

.. module:: pcapkit.vendor.dccp.feature

Generates :class:`pcapkit.const.dccp.feature.Feature`.

.. autoclass:: pcapkit.vendor.dccp.feature.Feature
   :members: FLAG, LINK
   :show-inheritance:

DCCP Ack Vector States
======================

.. module:: pcapkit.vendor.dccp.ack_vector_state

Generates :class:`pcapkit.const.dccp.ack_vector_state.AckVectorState`.

.. autoclass:: pcapkit.vendor.dccp.ack_vector_state.AckVectorState
   :members: FLAG, LINK
   :show-inheritance:

DCCP Drop Codes
===============

.. module:: pcapkit.vendor.dccp.drop_code

Generates :class:`pcapkit.const.dccp.drop_code.DropCode`.

.. autoclass:: pcapkit.vendor.dccp.drop_code.DropCode
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-1
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-3
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-5
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-7
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-10
.. [*] https://www.iana.org/assignments/dccp-parameters/dccp-parameters.xhtml#dccp-parameters-11

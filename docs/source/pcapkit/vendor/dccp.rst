===============================================================
:class:`~pcapkit.protocols.transport.dccp.DCCP` Vendor Crawlers
===============================================================

.. module:: pcapkit.vendor.dccp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.transport.dccp.DCCP` implementations. Available
vendor crawlers include:

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

DCCP Packet Types
=================

.. module:: pcapkit.vendor.dccp.packet_type

This module contains the vendor crawler for **DCCP Packet Types**,
which is automatically generating :class:`pcapkit.const.dccp.packet_type.PacketType`.

.. autoclass:: pcapkit.vendor.dccp.packet_type.PacketType
   :members: FLAG, LINK
   :show-inheritance:

DCCP Reset Codes
================

.. module:: pcapkit.vendor.dccp.reset_code

This module contains the vendor crawler for **DCCP Reset Codes**,
which is automatically generating :class:`pcapkit.const.dccp.reset_code.ResetCode`.

.. autoclass:: pcapkit.vendor.dccp.reset_code.ResetCode
   :members: FLAG, LINK
   :show-inheritance:

DCCP Option Types
=================

.. module:: pcapkit.vendor.dccp.option

This module contains the vendor crawler for **DCCP Option Types**,
which is automatically generating :class:`pcapkit.const.dccp.option.Option`.

.. autoclass:: pcapkit.vendor.dccp.option.Option
   :members: FLAG, LINK
   :show-inheritance:

DCCP Feature Numbers
====================

.. module:: pcapkit.vendor.dccp.feature

This module contains the vendor crawler for **DCCP Feature Numbers**,
which is automatically generating :class:`pcapkit.const.dccp.feature.Feature`.

.. autoclass:: pcapkit.vendor.dccp.feature.Feature
   :members: FLAG, LINK
   :show-inheritance:

DCCP Ack Vector States
======================

.. module:: pcapkit.vendor.dccp.ack_vector_state

This module contains the vendor crawler for **DCCP Ack Vector States**,
which is automatically generating :class:`pcapkit.const.dccp.ack_vector_state.AckVectorState`.

.. autoclass:: pcapkit.vendor.dccp.ack_vector_state.AckVectorState
   :members: FLAG, LINK
   :show-inheritance:

DCCP Drop Codes
===============

.. module:: pcapkit.vendor.dccp.drop_code

This module contains the vendor crawler for **DCCP Drop Codes**,
which is automatically generating :class:`pcapkit.const.dccp.drop_code.DropCode`.

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

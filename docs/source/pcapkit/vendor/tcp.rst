===================================================================
:class:`~pcapkit.protocols.transport.tcp.TCP` Vendor Crawlers
===================================================================

.. module:: pcapkit.vendor.tcp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.transport.tcp.TCP` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.vendor.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_MPTCPOption <pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption>`
     - Multipath TCP options [*]_
   * - :class:`TCP_Option <pcapkit.vendor.tcp.option.Option>`
     - TCP Option Kind Numbers

TCP Checksum
============

.. module:: pcapkit.vendor.tcp.checksum

This module contains the vendor crawler for **TCP Checksum**,
which is automatically generating :class:`pcapkit.const.tcp.checksum.Checksum`.

.. autoclass:: pcapkit.vendor.tcp.checksum.Checksum
   :members: FLAG, LINK
   :show-inheritance:

Multipath TCP options
=====================

.. module:: pcapkit.vendor.tcp.mp_tcp_option

This module contains the vendor crawler for **Multipath TCP options**,
which is automatically generating :class:`pcapkit.const.tcp.mp_tcp_option.MPTCPOption`.

.. autoclass:: pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption
   :members: FLAG, LINK
   :show-inheritance:

TCP Option Kind Numbers
=======================

.. module:: pcapkit.vendor.tcp.option

This module contains the vendor crawler for **TCP Option Kind Numbers**,
which is automatically generating :class:`pcapkit.const.tcp.option.Option`.

.. autoclass:: pcapkit.vendor.tcp.option.Option
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1

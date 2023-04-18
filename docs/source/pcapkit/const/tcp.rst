===================================================================
:class:`~pcapkit.protocols.transport.tcp.TCP` Constant Enumerations
===================================================================

.. module:: pcapkit.const.tcp

This module contains all constant enumerations of
:class:`~pcapkit.protocols.transport.tcp.TCP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.const.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_MPTCPOption <pcapkit.const.tcp.mp_tcp_option.MPTCPOption>`
     - Multipath TCP options [*]_
   * - :class:`TCP_Option <pcapkit.const.tcp.option.Option>`
     - TCP Option Kind Numbers

TCP Checksum
============

.. module:: pcapkit.const.tcp.checksum

This module contains the constant enumeration for **TCP Checksum**,
which is automatically generated from :class:`pcapkit.vendor.tcp.checksum.Checksum`.

.. autoclass:: pcapkit.const.tcp.checksum.Checksum
   :members:
   :undoc-members:
   :show-inheritance:

Multipath TCP options
=====================

.. module:: pcapkit.const.tcp.mp_tcp_option

This module contains the constant enumeration for **Multipath TCP options**,
which is automatically generated from :class:`pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption`.

.. autoclass:: pcapkit.const.tcp.mp_tcp_option.MPTCPOption
   :members:
   :undoc-members:
   :show-inheritance:

TCP Option Kind Numbers
=======================

.. module:: pcapkit.const.tcp.option

This module contains the constant enumeration for **TCP Option Kind Numbers**,
which is automatically generated from :class:`pcapkit.vendor.tcp.option.Option`.

.. autoclass:: pcapkit.const.tcp.option.Option
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1

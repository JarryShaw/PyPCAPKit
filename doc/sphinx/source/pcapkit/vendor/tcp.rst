:class:`~pcapkit.protocols.transport.tcp.TCP` Vendor Crawlers
=============================================================

.. module:: pcapkit.vendor.tcp

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.transport.tcp.TCP` implementations. Available
enumerations include:

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.vendor.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_MPTCPOption <pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption>`
     - Multipath TCP options [*]_
   * - :class:`TCP_Option <pcapkit.vendor.tcp.option.Option>`
     - TCP Option Kind Numbers

.. automodule:: pcapkit.vendor.tcp.checksum
   :no-members:

.. autoclass:: pcapkit.vendor.tcp.checksum.Checksum
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.vendor.tcp.mp_tcp_option
   :no-members:

.. autoclass:: pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. automodule:: pcapkit.vendor.tcp.option
   :no-members:

.. autoclass:: pcapkit.vendor.tcp.option.Option
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1

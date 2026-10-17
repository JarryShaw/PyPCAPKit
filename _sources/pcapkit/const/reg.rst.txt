============================================
Protocol Type Registry Constant Enumerations
============================================

.. module:: pcapkit.const.reg

This module contains all constant enumerations of protocol type registry
implementations. Available enumerations include:

.. list-table::

   * - :class:`LINKTYPE <pcapkit.const.reg.linktype.LinkType>`
     - Link-Layer Header Type Values [*]_
   * - :class:`ETHERTYPE <pcapkit.const.reg.ethertype.EtherType>`
     - Ethertype IEEE 802 Numbers [*]_
   * - :class:`TRANSTYPE <pcapkit.const.reg.transtype.TransType>`
     - Transport Layer Protocol Numbers [*]_
   * - :class:`APPTYPE <pcapkit.const.reg.apptype.apptype.AppType>`
     - Application Layer Protocol Numbers (Service Name and Transport Protocol Port Number Registry) [*]_

Link-Layer Header Type Values
=============================

.. module:: pcapkit.const.reg.linktype

This module contains the constant enumeration for **Link-Layer Header Type Values**,
which is automatically generated from :class:`pcapkit.vendor.reg.linktype.LinkType`.

.. autoclass:: pcapkit.const.reg.linktype.LinkType
   :members:
   :undoc-members:
   :show-inheritance:

Ethertype IEEE 802 Numbers
==========================

.. module:: pcapkit.const.reg.ethertype

This module contains the constant enumeration for **Ethertype IEEE 802 Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.ethertype.EtherType`.

.. autoclass:: pcapkit.const.reg.ethertype.EtherType
   :members:
   :undoc-members:
   :show-inheritance:

Transport Layer Protocol Numbers
================================

.. module:: pcapkit.const.reg.transtype

This module contains the constant enumeration for **Transport Layer Protocol Numbers**,
which is automatically generated from :class:`pcapkit.vendor.reg.transtype.TransType`.

.. autoclass:: pcapkit.const.reg.transtype.TransType
   :members:
   :undoc-members:
   :show-inheritance:

Application Layer Protocol Numbers
==================================

.. module:: pcapkit.const.reg.apptype

This package contains the constant enumerations for **Application Layer Protocol
Numbers**, which are automatically generated from :mod:`pcapkit.vendor.reg.apptype`.
IANA keys every assignment on a ``(service, port, transport)`` triple, so the
registry is one enumeration per transport protocol sharing a memberless base.

.. versionchanged:: 1.5.0

   Split by transport protocol (:issue:`732`): :mod:`pcapkit.const.reg.apptype`
   is a package, and every assignment is a member of one of the per-transport
   registries rather than of :class:`~pcapkit.const.reg.apptype.apptype.AppType`.
   ``get()`` raises :exc:`ValueError` for a port outside ``0``-``65535``
   (:issue:`758`), and returns an unregistered member rather than minting one
   for a port the registry does not assign (:issue:`860`).

.. module:: pcapkit.const.reg.apptype.apptype

.. versionchanged:: 1.5.0

   :class:`~pcapkit.const.reg.apptype.apptype.TransportProtocol` is an
   ``aenum.IntEnum`` rather than an ``aenum.IntFlag`` (:issue:`808`), numbered
   sequentially: ``sctp`` is ``3`` and ``dccp`` is ``4``, where they were ``4``
   and ``8``, and no :class:`int` is decoded as a ``|`` composite
   (:issue:`860`). Its ``get()`` refuses a name no member declares, with
   :exc:`~pcapkit.utilities.exceptions.EnumKeyError`, rather than minting a
   member for it (:issue:`808`, :issue:`923`).

.. autoclass:: pcapkit.const.reg.apptype.apptype.TransportProtocol
   :members:
   :undoc-members:
   :show-inheritance:

.. versionchanged:: 1.1.1

   An :class:`~pcapkit.const.reg.apptype.apptype.AppType` member converts with
   :class:`int` to its port number, and compares, orders and hashes as that
   port.

.. autoclass:: pcapkit.const.reg.apptype.apptype.AppType
   :members:
   :undoc-members:
   :show-inheritance:

.. module:: pcapkit.const.reg.apptype.tcp

.. autoclass:: pcapkit.const.reg.apptype.tcp.TCP
   :members:
   :undoc-members:
   :show-inheritance:

.. module:: pcapkit.const.reg.apptype.udp

.. autoclass:: pcapkit.const.reg.apptype.udp.UDP
   :members:
   :undoc-members:
   :show-inheritance:

.. module:: pcapkit.const.reg.apptype.sctp

.. autoclass:: pcapkit.const.reg.apptype.sctp.SCTP
   :members:
   :undoc-members:
   :show-inheritance:

.. module:: pcapkit.const.reg.apptype.dccp

.. autoclass:: pcapkit.const.reg.apptype.dccp.DCCP
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] http://www.tcpdump.org/linktypes.html
.. [*] https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1
.. [*] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
.. [*] https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?

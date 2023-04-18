==============================================================
:class:`~pcapkit.protocols.internet.ipv6.IPv6` Vendor Crawlers
==============================================================

.. module:: pcapkit.vendor.ipv6

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipv6.IPv6` implementations. Available
vendor crawlers include:

.. list-table::

   * - :class:`IPv6_Extension_Header <pcapkit.vendor.ipv6.extension_header.ExtensionHeader>`
     - IPv6 Extension Header Types [*]_
   * - :class:`IPv6_Option <pcapkit.vendor.ipv6.option.Option>`
     - Destination Options and Hop-by-Hop Options [*]_
   * - :class:`IPv6_OptionAction <pcapkit.vendor.ipv6.option_action.OptionAction>`
     - Option Actions [*]_
   * - :class:`IPv6_QSFunction <pcapkit.vendor.ipv6.qs_function.QSFunction>`
     - IPv6 QS Functions
   * - :class:`IPv6_RouterAlert <pcapkit.vendor.ipv6.router_alert.RouterAlert>`
     - IPv6 Router Alert Option Values [*]_
   * - :class:`IPv6_Routing <pcapkit.vendor.ipv6.routing.Routing>`
     - Routing Types [*]_
   * - :class:`IPv6_SeedID <pcapkit.vendor.ipv6.seed_id.SeedID>`
     - Seed-ID Types
   * - :class:`IPv6_SMFDPDMode <pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode>`
     - Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
   * - :class:`IPv6_TaggerID <pcapkit.vendor.ipv6.tagger_id.TaggerID>`
     - Tagger-ID Types [*]_

IPv6 Extension Header Types
===========================

.. module:: pcapkit.vendor.ipv6.extension_header

This module contains the vendor crawler for **IPv6 Extension Header Types**,
which is automatically generating :class:`pcapkit.const.ipv6.extension_header.ExtensionHeader`.

.. autoclass:: pcapkit.vendor.ipv6.extension_header.ExtensionHeader
   :members: FLAG, LINK
   :show-inheritance:

Option Actions
==============

.. module:: pcapkit.vendor.ipv6.option_action

This module contains the vendor crawler for **Option Actions**,
which is automatically generating :class:`pcapkit.const.ipv6.option_action.OptionAction`.

.. autoclass:: pcapkit.vendor.ipv6.option_action.OptionAction
   :members: FLAG, LINK
   :show-inheritance:

Destination Options and Hop-by-Hop Options
==========================================

.. module:: pcapkit.vendor.ipv6.option

This module contains the vendor crawler for **Destination Options and Hop-by-Hop Options**,
which is automatically generating :class:`pcapkit.const.ipv6.option.Option`.

.. autoclass:: pcapkit.vendor.ipv6.option.Option
   :members: FLAG, LINK
   :show-inheritance:

QS Functions
============

.. module:: pcapkit.vendor.ipv6.qs_function

This module contains the vendor crawler for **QS Functions**,
which is automatically generating :class:`pcapkit.const.ipv6.qs_function.QSFunction`.

.. autoclass:: pcapkit.vendor.ipv6.qs_function.QSFunction
   :members: FLAG, LINK
   :show-inheritance:

IPv6 Router Alert Option Values
===============================

.. module:: pcapkit.vendor.ipv6.router_alert

This module contains the vendor crawler for **IPv6 Router Alert Option Values**,
which is automatically generating :class:`pcapkit.const.ipv6.router_alert.RouterAlert`.

.. autoclass:: pcapkit.vendor.ipv6.router_alert.RouterAlert
   :members: FLAG, LINK
   :show-inheritance:

IPv6 Routing Types
==================

.. module:: pcapkit.vendor.ipv6.routing

This module contains the vendor crawler for **IPv6 Routing Types**,
which is automatically generating :class:`pcapkit.const.ipv6.routing.Routing`.

.. autoclass:: pcapkit.vendor.ipv6.routing.Routing
   :members: FLAG, LINK
   :show-inheritance:

Seed-ID Types
=============

.. module:: pcapkit.vendor.ipv6.seed_id

This module contains the vendor crawler for **Seed-ID Types**,
which is automatically generating :class:`pcapkit.const.ipv6.seed_id.SeedID`.

.. autoclass:: pcapkit.vendor.ipv6.seed_id.SeedID
   :members: FLAG, LINK
   :show-inheritance:

Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
================================================================================

.. module:: pcapkit.vendor.ipv6.smf_dpd_mode

This module contains the vendor crawler for **Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options**,
which is automatically generating :class:`pcapkit.const.ipv6.smf_dpd_mode.SMFDPDMode`.

.. autoclass:: pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode
   :members: FLAG, LINK
   :show-inheritance:

TaggerID Types
==============

.. module:: pcapkit.vendor.ipv6.tagger_id

This module contains the vendor crawler for **TaggerID Types**,
which is automatically generating :class:`pcapkit.const.ipv6.tagger_id.TaggerID`.

.. autoclass:: pcapkit.vendor.ipv6.tagger_id.TaggerID
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
.. [*] https://www.rfc-editor.org/rfc/rfc8200#section-4.2
.. [*] https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml#ipv6-routeralert-values-1
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#taggerId-types

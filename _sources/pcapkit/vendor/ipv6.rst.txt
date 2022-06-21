:class:`~pcapkit.protocols.internet.ipv6.IPv6` Vendor Crawlers
==============================================================

.. module:: pcapkit.vendor.ipv6

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipv6.IPv6` implementations. Available
crawlers include:

.. list-table::

   * - :class:`IPv6_Extension_Header <pcapkit.vendor.ipv6.extension_header.ExtensionHeader>`
     - IPv6 Extension Header Types [*]_
   * - :class:`IPv6_Option <pcapkit.vendor.ipv6.option.Option>`
     - Destination Options and Hop-by-Hop Options [*]_
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

.. automodule:: pcapkit.vendor.ipv6.extension_header
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.extension_header.ExtensionHeader
   :noindex:
   :members: LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv6.option
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.option.Option
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv6.qs_function
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.qs_function.QSFunction
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv6.qs_function.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv6.router_alert
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.router_alert.RouterAlert
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv6.routing
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.routing.Routing
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv6.seed_id
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.seed_id.SeedID
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv6.seed_id.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv6.smf_dpd_mode
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv6.smf_dpd_mode.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv6.tagger_id
   :no-members:

.. autoclass:: pcapkit.vendor.ipv6.tagger_id.TaggerID
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
.. [*] https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml#ipv6-routeralert-values-1
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#taggerId-types
